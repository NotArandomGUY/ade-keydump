#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

class EPubDumper {
public:

  EPubDumper();

  ~EPubDumper();

  inline bool is_open() { return input_archive_ != nullptr || output_archive_ != nullptr; }

  int open(const std::string& path, const std::string& encryption_key);

  int dump(bool is_close = true);

  int dumpAsync(bool is_close = true);

  int close();

private:

  struct zip* input_archive_;
  struct zip* output_archive_;

  std::string encryption_key_;
  std::map<uint64_t, size_t> encrypted_index_map_;

  std::unique_ptr<std::thread> async_thread_;
  std::atomic<bool> is_abort_dump_;

  int readPath(const std::string& path, std::string& buffer, size_t offset = 0);

  int readIndex(uint64_t index, std::string& buffer, size_t offset = 0);

  int readXMLPath(const std::string& path, boost::property_tree::ptree& pt);

  int readXMLIndex(uint64_t index, boost::property_tree::ptree& pt);

};