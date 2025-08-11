#pragma once

#define AES_BLOCK_SIZE 16
#define AES128_ROUNDS 11
#define AES256_ROUNDS 15
#define AES128_KEY_SIZE 16
#define AES256_KEY_SIZE 32

union AESBlock {
  uint32_t l[AES_BLOCK_SIZE / sizeof(uint32_t)];
  uint8_t c[AES_BLOCK_SIZE];
};

template <uint32_t R>
union AESSubKey {
  AESBlock b[R];
  uint32_t l[(R * AES_BLOCK_SIZE) / sizeof(uint32_t)];
  uint8_t c[R * AES_BLOCK_SIZE];
};

void aes128_cbc_enc(uint8_t* data, size_t len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);
void aes128_cbc_dec(uint8_t* data, size_t len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);
void aes128_cbc_pkcs7_enc(uint8_t* data, size_t& len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);
void aes128_cbc_pkcs7_dec(uint8_t* data, size_t& len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);

void aes256_cbc_enc(uint8_t* data, size_t len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);
void aes256_cbc_dec(uint8_t* data, size_t len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);
void aes256_cbc_pkcs7_enc(uint8_t* data, size_t& len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);
void aes256_cbc_pkcs7_dec(uint8_t* data, size_t& len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]);