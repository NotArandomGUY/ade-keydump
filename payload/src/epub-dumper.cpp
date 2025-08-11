#include <pch.h>
#include <zip.h>
#include <zlib.h>

#include "crypto/aes.h"
#include "utils/common.h"
#include "epub-dumper.h"

using namespace std;
using namespace boost::property_tree;

namespace fs = std::filesystem;

constexpr auto META_INF_CONTAINER = "META-INF/container.xml";
constexpr auto META_INF_ENCRYPTION = "META-INF/encryption.xml";
constexpr auto META_INF_RIGHTS = "META-INF/rights.xml"; // TODO: maybe implement full license api at some point?
constexpr const char* DUMP_IGNORE_FILES[] = { META_INF_ENCRYPTION, META_INF_RIGHTS };

/* Static Functions */

static const char* zip_error_str(zip_t* za, int status) {
  static thread_local zip_error_t s_error;
  static thread_local char s_error_str[512];

  zip_error_t* error = za == nullptr ? nullptr : zip_get_error(za);
  if (error == nullptr || (error->sys_err == 0 && error->zip_err == ZIP_ER_OK)) {
    error = &s_error;
    zip_error_init_with_code(error, status);
  }

  const char* error_str = zip_error_strerror(error);
  memset(s_error_str, 0, sizeof(s_error_str));
  memcpy(s_error_str, zip_error_strerror(error), min(strlen(error_str), sizeof(s_error_str) - 1));

  zip_error_fini(error);

  return s_error_str;
}

static int archive_read(zip_t* za, zip_stat_t* stat, string& buffer, size_t offset) {
  zip_file_t* zf = zip_fopen_index(za, stat->index, ZIP_FL_UNCHANGED);
  if (zf == nullptr) return ZIP_ER_OPEN;

  size_t size = stat->size;
  buffer.resize(offset + size);

  uint8_t* data = (uint8_t*)buffer.data() + offset;
  memset(data, 0, size);
  if (zip_fread(zf, data, size) < 0) {
    zip_fclose(zf);
    return ZIP_ER_READ;
  }

  zip_fclose(zf);
  return ZIP_ER_OK;
}

static int archive_read_encrypted(zip_t* za, zip_stat_t* stat, const string& key, string& buffer, size_t offset) {
  string compressed_buffer;

  int status = archive_read(za, stat, compressed_buffer, 0);
  if (status != ZIP_ER_OK) return status;

  uint8_t* compressed_data = (uint8_t*)compressed_buffer.data();
  size_t compressed_size = stat->size;

  Bytef* decompressed_data = (Bytef*)buffer.data() + offset;
  size_t decompressed_size = buffer.size() - offset;

  if (key.empty()) {
    LOG("epub unable to decrypt without key");
    memcpy(decompressed_data, compressed_data, min(decompressed_size, compressed_size));
    return ZIP_ER_OK;
  }

  if (compressed_size <= 16) {
    LOG("epub compressed data too small");
    return ZIP_ER_EOF;
  }
  compressed_size -= 16;
  aes128_cbc_pkcs7_dec(compressed_data + 16, compressed_size, (const uint8_t*)key.c_str(), compressed_data);

  z_stream stream{};

  status = inflateInit2(&stream, -MAX_WBITS);
  if (status != Z_OK) {
    LOG("epub inflate init error: %d", status);
    return ZIP_ER_COMPRESSED_DATA;
  }

  stream.next_in = compressed_data + 16;
  stream.next_out = decompressed_data;

  const uInt max = (uInt)-1;
  uLong len = compressed_size;
  uLong left = decompressed_size;

  do {
    if (stream.avail_out == 0) {
      stream.avail_out = left > (uLong)max ? max : (uInt)left;
      left -= stream.avail_out;
    }
    if (stream.avail_in == 0) {
      stream.avail_in = len > (uLong)max ? max : (uInt)len;
      len -= stream.avail_in;
    }
    status = inflate(&stream, Z_NO_FLUSH);
  } while (status == Z_OK);

  inflateEnd(&stream);

  if (status < Z_OK) {
    LOG("epub inflate error: %d", status);
    return ZIP_ER_COMPRESSED_DATA;
  }

  if (stream.total_out != decompressed_size) {
    LOG("epub decompressed size mismatch (%lld/%lld)", (uint64_t)stream.total_out, (uint64_t)decompressed_size);
    return ZIP_ER_EOF;
  }

  return ZIP_ER_OK;
}

/* Instance Methods */

EPubDumper::EPubDumper() :
  input_archive_(nullptr),
  output_archive_(nullptr),
  encryption_key_(),
  encrypted_index_map_(),
  async_thread_(nullptr),
  is_abort_dump_(false)
{
}

EPubDumper::~EPubDumper() {
  close();
}

int EPubDumper::open(const string& path, const string& encryption_key) {
  close();

  int status = ZIP_ER_OK;

  try {
    LOG("epub open input archive '%s'", path.c_str());

    input_archive_ = zip_open(path.c_str(), ZIP_RDONLY, &status);
    if (input_archive_ == nullptr || status != ZIP_ER_OK) {
      LOG("epub open input archive error: %s", zip_error_str(input_archive_, status));
      close();
      return -2;
    }

    ptree encryption_pt;
    status = readXMLPath(META_INF_ENCRYPTION, encryption_pt);
    if (status == ZIP_ER_OK) {
      encrypted_index_map_.clear();
      encryption_key_ = encryption_key;

      zip_stat_t stat{};
      string test_buffer;

      for (auto& [tag, child] : encryption_pt.get_child("encryption")) {
        if (tag != "EncryptedData") continue;

        string uri = child.get_optional<string>("CipherData.CipherReference.<xmlattr>.URI").value_or("");
        if (uri.empty()) continue;

        string algorithm = child.get<string>("EncryptionMethod.<xmlattr>.Algorithm");
        if (!algorithm.ends_with("#aes128-cbc")) {
          LOG("ignoring '%s' due to unsupported algorithm: %s", uri.c_str(), algorithm.c_str());
          continue;
        }

        status = zip_stat(input_archive_, uri.c_str(), ZIP_FL_UNCHANGED, &stat);
        if (status != ZIP_ER_OK) {
          LOG("ignoring '%s' due to error: %s", uri.c_str(), zip_error_str(input_archive_, status));
          continue;
        }

        size_t size = child.get_optional<size_t>("EncryptionProperties.ResourceSize").value_or(0);
        if (size <= 0) {
          LOG("ignoring '%s' due to invalid size", uri.c_str());
          continue;
        }

        encrypted_index_map_[stat.index] = size;

        if (readIndex(stat.index, test_buffer) != ZIP_ER_OK) {
          LOG("epub encryption test failed, maybe invalid key");
          close();
          return -3;
        }
      }
    }
    else {
      LOG("epub skip encryption due to error: %s", zip_error_str(input_archive_, status));
    }

    ptree container_pt;
    status = readXMLPath(META_INF_CONTAINER, container_pt);
    if (status != ZIP_ER_OK) {
      LOG("epub read container metadata error: %s", zip_error_str(input_archive_, status));
      close();
      return -4;
    }

    if (container_pt.get_optional<string>("container.rootfiles.rootfile.<xmlattr>.full-path").value_or("").empty()) {
      LOG("epub invalid container");
      close();
      return -5;
    }

    fs::path output_path(path);
    output_path.replace_extension(".dump" + output_path.extension().string());

    LOG("epub open output archive '%s'", output_path.string().c_str());

    output_archive_ = zip_open(output_path.string().c_str(), ZIP_TRUNCATE | ZIP_CREATE, &status);
    if (output_archive_ == nullptr || status != ZIP_ER_OK) {
      LOG("epub open output archive error: %s", zip_error_str(output_archive_, status));
      close();
      return -6;
    }

    return 0;
  }
  catch (exception& ex) {
    LOG("epub read metadata error: %s", ex.what());
    close();
    return -1;
  }
}

int EPubDumper::dump(bool is_close) {
  if (input_archive_ == nullptr || output_archive_ == nullptr) {
    LOG("epub invalid state to dump");
    if (is_close) close();
    return -1;
  }

  int status = 0;
  uint64_t encrypted_count = 0;
  string buffer;
  zip_source_t* zs = nullptr;

  int64_t entries = zip_get_num_entries(input_archive_, ZIP_FL_ENC_UTF_8);
  if (entries <= 0) {
    LOG("epub has no files to dump");
    goto done;
  }

  for (uint64_t index = 0; index < entries && !is_abort_dump_; index++) {
    const char* path = zip_get_name(input_archive_, index, ZIP_FL_ENC_UTF_8 | ZIP_FL_UNCHANGED);
    if (path == nullptr) {
      LOG("epub get name(%lld) error: %s", index, zip_error_str(input_archive_, index));
      continue;
    }

    bool is_ignore = false;
    for (uint16_t i = 0; i < (sizeof(DUMP_IGNORE_FILES) / sizeof(const char*)); i++) {
      if (path != DUMP_IGNORE_FILES[i]) continue;

      is_ignore = true;
      break;
    }
    if (is_ignore) continue;

    LOG("epub dump progress ALL(%lld/%lld) ENC(%lld/%lld) '%s'", index, entries, encrypted_count, (uint64_t)encrypted_index_map_.size(), path);

    if (encrypted_index_map_.contains(index)) {
      status = readIndex(index, buffer, 0);
      if (status != ZIP_ER_OK) {
        LOG("epub failed to read encrypted data '%s'", zip_error_str(input_archive_, status));
        continue;
      }

      void* source_buffer = malloc(buffer.size());
      if (source_buffer == nullptr) {
        LOG("epub failed to allocate source buffer");
        continue;
      }
      memcpy(source_buffer, buffer.c_str(), buffer.size());

      zs = zip_source_buffer(output_archive_, source_buffer, buffer.size(), 1);
      encrypted_count++;
    }
    else {
      zs = zip_source_zip_file(output_archive_, input_archive_, index, ZIP_FL_COMPRESSED, 0, -1, nullptr);
    }

    if (zs == nullptr) {
      LOG("epub invalid archive source for '%s'", path);
      continue;
    }

    string parent_path = fs::path(path).parent_path().string();
    if (!parent_path.empty()) zip_dir_add(output_archive_, parent_path.c_str(), ZIP_FL_ENC_UTF_8);

    zip_file_add(output_archive_, path, zs, ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8);
  }

  LOG("epub dump complete");

  if (encrypted_count != encrypted_index_map_.size()) {
    LOG("[WARNING] epub encrypted file count mismatch (%lld/%lld), dumped file might not work property", encrypted_count, (uint64_t)encrypted_index_map_.size());
  }

done:
  if (is_close) close();
  return 0;
}

int EPubDumper::dumpAsync(bool is_close) {
  if (async_thread_ != nullptr || is_abort_dump_) return -1;

  async_thread_ = make_unique<thread>(&EPubDumper::dump, this, is_close);

  return 0;
}

int EPubDumper::close() {
  is_abort_dump_ = true;

  if (async_thread_ != nullptr) {
    if (this_thread::get_id() == async_thread_->get_id()) {
      thread(&EPubDumper::close, this).detach();
      return 0;
    }

    if (async_thread_->joinable()) async_thread_->join();
    async_thread_ = nullptr;
  }

  int status = 0;

  if (output_archive_ != nullptr) {
    status = zip_close(output_archive_);
    if (status < 0) LOG("epub output archive close error: %s", zip_error_str(output_archive_, status));
    output_archive_ = nullptr;
  }

  if (input_archive_ != nullptr) {
    status = zip_close(input_archive_);
    if (status < 0) LOG("epub input archive close error: %s", zip_error_str(input_archive_, status));
    input_archive_ = nullptr;
  }

  encryption_key_.clear();
  encrypted_index_map_.clear();

  is_abort_dump_ = false;

  return 0;
}

int EPubDumper::readPath(const string& path, string& buffer, size_t offset) {
  if (input_archive_ == nullptr) return ZIP_ER_ZIPCLOSED;

  zip_stat_t stat{};

  int status = zip_stat(input_archive_, path.c_str(), ZIP_FL_UNCHANGED, &stat);
  if (status != ZIP_ER_OK) return status;

  if (!encrypted_index_map_.contains(stat.index)) return archive_read(input_archive_, &stat, buffer, offset);

  buffer.resize(offset + encrypted_index_map_[stat.index]);
  return archive_read_encrypted(input_archive_, &stat, encryption_key_, buffer, offset);
}

int EPubDumper::readIndex(uint64_t index, string& buffer, size_t offset) {
  if (input_archive_ == nullptr) return ZIP_ER_ZIPCLOSED;

  zip_stat_t stat{};

  int status = zip_stat_index(input_archive_, index, ZIP_FL_UNCHANGED, &stat);
  if (status != ZIP_ER_OK) return status;

  if (!encrypted_index_map_.contains(stat.index)) return archive_read(input_archive_, &stat, buffer, offset);

  buffer.resize(offset + encrypted_index_map_[stat.index]);
  return archive_read_encrypted(input_archive_, &stat, encryption_key_, buffer, offset);
}

int EPubDumper::readXMLPath(const string& path, ptree& pt) {
  string buffer;

  int status = readPath(path, buffer);
  if (status != ZIP_ER_OK) return status;

  #ifdef _DEBUG
  LOG("epub read xml path(%s): %s", path.c_str(), buffer.c_str());
  #endif

  stringstream ss(buffer);
  read_xml(ss, pt);

  return ZIP_ER_OK;
}

int EPubDumper::readXMLIndex(uint64_t index, ptree& pt) {
  string buffer;

  int status = readIndex(index, buffer);
  if (status != ZIP_ER_OK) return status;

  #ifdef _DEBUG
  LOG("epub read xml index(%lld): %s", index, buffer.c_str());
  #endif

  stringstream ss(buffer);
  read_xml(ss, pt);

  return ZIP_ER_OK;
}