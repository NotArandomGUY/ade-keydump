#include <pch.h>

#include "crypto/aes.h"
#include "crypto/aes-const.h"

#define forceinline __forceinline

// xor's all elements in a n byte array a by b
static forceinline void xor_dwords(uint32_t* a, uint32_t* b, int32_t n) {
  for (int32_t i = 0; i < n; i++) a[i] ^= b[i];
}

// xor the current cipher state by a specific round key
static  forceinline void xor_round_key(uint32_t* state, uint32_t* keys, int32_t round) {
  xor_dwords(state, keys + round * (16 / sizeof(uint32_t)), 16 / sizeof(uint32_t));
}

// apply the rijndael s-box to all elements in an array
// http://en.wikipedia.org/wiki/Rijndael_S-box
static forceinline void sub_bytes(uint8_t* a, int32_t n) {
  for (int32_t i = 0; i < n; i++) a[i] = ~(a[i] ^ LOOKUP_SBOX[a[i]]);
}
static forceinline void sub_bytes_inv(uint8_t* a, int32_t n) {
  for (int32_t i = 0; i < n; i++) a[i] = ~(a[i] ^ LOOKUP_SBOX_INV[a[i]]);
}

// apply the shift rows step on the 16 byte cipher state
// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
static forceinline void shift_rows(uint8_t* state) {
  uint8_t temp[16];
  memcpy(temp, state, 16);
  for (uint32_t i = 0; i < 16; i++) state[i] = temp[SHIFT_ROWS_TABLE[i]];
}
static forceinline void shift_rows_inv(uint8_t* state) {
  uint8_t temp[16];
  memcpy(temp, state, 16);
  for (uint32_t i = 0; i < 16; i++) state[i] = temp[SHIFT_ROWS_TABLE_INV[i]];
}

// perform the mix columns matrix on one column of 4 bytes
// http://en.wikipedia.org/wiki/Rijndael_mix_columns
static forceinline void mix_col(uint8_t* state, int32_t offset) {
  uint8_t a0 = state[0 + offset];
  uint8_t a1 = state[1 + offset];
  uint8_t a2 = state[2 + offset];
  uint8_t a3 = state[3 + offset];
  state[0 + offset] = LOOKUP_G2[a0] ^ LOOKUP_G3[a1] ^ a2 ^ a3;
  state[1 + offset] = LOOKUP_G2[a1] ^ LOOKUP_G3[a2] ^ a3 ^ a0;
  state[2 + offset] = LOOKUP_G2[a2] ^ LOOKUP_G3[a3] ^ a0 ^ a1;
  state[3 + offset] = LOOKUP_G2[a3] ^ LOOKUP_G3[a0] ^ a1 ^ a2;
}

// perform the mix columns matrix on each column of the 16 bytes
static forceinline void mix_cols(uint8_t* state) {
  mix_col(state, 0);
  mix_col(state, 4);
  mix_col(state, 8);
  mix_col(state, 12);
}

// perform the inverse mix columns matrix on one column of 4 bytes
// http://en.wikipedia.org/wiki/Rijndael_mix_columns
static forceinline void mix_col_inv(uint8_t* state, int32_t offset) {
  uint8_t a0 = state[0 + offset];
  uint8_t a1 = state[1 + offset];
  uint8_t a2 = state[2 + offset];
  uint8_t a3 = state[3 + offset];
  state[0 + offset] = LOOKUP_G14[a0] ^ LOOKUP_G9[a3] ^ LOOKUP_G13[a2] ^ LOOKUP_G11[a1];
  state[1 + offset] = LOOKUP_G14[a1] ^ LOOKUP_G9[a0] ^ LOOKUP_G13[a3] ^ LOOKUP_G11[a2];
  state[2 + offset] = LOOKUP_G14[a2] ^ LOOKUP_G9[a1] ^ LOOKUP_G13[a0] ^ LOOKUP_G11[a3];
  state[3 + offset] = LOOKUP_G14[a3] ^ LOOKUP_G9[a2] ^ LOOKUP_G13[a1] ^ LOOKUP_G11[a0];
}

// perform the inverse mix columns matrix on each column of the 16 bytes
static forceinline void mix_cols_inv(uint8_t* state) {
  mix_col_inv(state, 0);
  mix_col_inv(state, 4);
  mix_col_inv(state, 8);
  mix_col_inv(state, 12);
}

template <uint32_t R>
static void aes_enc_block(AESBlock& block, AESSubKey<R>& subKey) {
  // first round
  xor_round_key(block.l, subKey.l, 0);

  // middle rounds
  for (int32_t i = 1; i <= (R - 2); i++) {
    sub_bytes(block.c, AES_BLOCK_SIZE);
    shift_rows(block.c);
    mix_cols(block.c);
    xor_round_key(block.l, subKey.l, i);
  }

  // final round
  sub_bytes(block.c, AES_BLOCK_SIZE);
  shift_rows(block.c);
  xor_round_key(block.l, subKey.l, R - 1);
}

template <uint32_t R>
static void aes_dec_block(AESBlock& block, AESSubKey<R>& subKey) {
  // add final round key to state
  xor_round_key(block.l, subKey.l, R - 1);

  // reverse the middle rounds
  for (int32_t i = (R - 2); i >= 1; i--) {
    shift_rows_inv(block.c);
    sub_bytes_inv(block.c, AES_BLOCK_SIZE);
    xor_round_key(block.l, subKey.l, i);
    mix_cols_inv(block.c);
  }

  // reverse the first round
  shift_rows_inv(block.c);
  sub_bytes_inv(block.c, AES_BLOCK_SIZE);
  xor_round_key(block.l, subKey.l, 0);
}

// perform the core key schedule transform on 4 bytes, as part of the key expansion process
// http://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_core
static void aes_key_schedule_core(uint8_t* a, size_t i) {
  // rotate the output eight bits to the left
  uint8_t temp = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = temp;

  // apply rijndael's s-box on all four individual bytes in the output word
  sub_bytes(a, 4);

  // on just the first (leftmost) byte of the output word, perform the rcon operation with i
  // as the input, and exclusive or the rcon output with the first byte of the output word
  a[0] ^= LOOKUP_RCON[i];
}

template <uint32_t R, uint32_t K>
static void aes_load_key_schedule(const uint8_t key[K], AESSubKey<R>& subKey) {
  size_t bytes = K; // the count of how many bytes we've created so far
  size_t i = 1; // the rcon iteration value i is set to 1
  uint8_t t[4]; // temporary working area known as 't' in the wiki article
  memcpy(subKey.c, key, K); // the first K bytes of the expanded key are simply the encryption key

  while (bytes < (R * AES_BLOCK_SIZE)) {
    memcpy(t, subKey.c + bytes - 4, 4); // we assign the value of the previous four bytes in the expanded key to t
    aes_key_schedule_core(t, i++); // we perform the key schedule core on t, with i as the rcon iteration value & increment i by 1
    xor_dwords((uint32_t*)t, (uint32_t*)(subKey.c + bytes - AES_BLOCK_SIZE), 1); // we exclusive-or t with the four-byte block 16 bytes before the new expanded key.
    memcpy(subKey.c + bytes, t, 4); // this becomes the next 4 bytes in the expanded key
    bytes += 4; // keep track of how many expanded key bytes we've added

    // we then do the following three times to create the next twelve bytes
    for (int8_t j = 0; j < 3; j++) {
      memcpy(t, subKey.c + bytes - 4, 4); // we assign the value of the previous 4 bytes in the expanded key to t
      xor_dwords((uint32_t*)t, (uint32_t*)(subKey.c + bytes - AES_BLOCK_SIZE), 1); // we exclusive-or t with the four-byte block n bytes before
      memcpy(subKey.c + bytes, t, 4); // this becomes the next 4 bytes in the expanded key
      bytes += 4; // keep track of how many expanded key bytes we've added
    }
  }
}

template <uint32_t R, uint32_t K>
static void aes_cbc_enc(uint8_t* data, size_t len, const uint8_t key[K], uint8_t iv[AES_BLOCK_SIZE]) {
  if ((len % AES_BLOCK_SIZE) != 0) return;

  AESSubKey<R> subKey{};
  aes_load_key_schedule<R, K>(key, subKey);

  AESBlock block{};
  for (size_t i = 0; i < (len / AES_BLOCK_SIZE); i++) {
    block = *(AESBlock*)&data[i * AES_BLOCK_SIZE];

    for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
      block.c[j] ^= iv[j];
    }

    aes_enc_block<R>(block, subKey);

    *(AESBlock*)iv = block;
    *(AESBlock*)(&data[i * AES_BLOCK_SIZE]) = block;
  }
}

template <uint32_t R, uint32_t K>
static void aes_cbc_dec(uint8_t* data, size_t len, const uint8_t key[K], uint8_t iv[AES_BLOCK_SIZE]) {
  if ((len % AES_BLOCK_SIZE) != 0) return;

  AESSubKey<R> subKey{};
  aes_load_key_schedule<R, K>(key, subKey);

  AESBlock block{};
  for (size_t i = 0; i < (len / AES_BLOCK_SIZE); i++) {
    block = *(AESBlock*)&data[i * AES_BLOCK_SIZE];

    aes_dec_block<R>(block, subKey);

    for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
      block.c[j] ^= iv[j];
    }

    *(AESBlock*)iv = *(AESBlock*)&data[i * AES_BLOCK_SIZE];
    *(AESBlock*)(&data[i * AES_BLOCK_SIZE]) = block;
  }
}


static void pkcs7_unpad(uint8_t* data, size_t& len) {
  len -= data[len - 1];
}


void aes128_cbc_enc(uint8_t* data, size_t len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_enc<AES128_ROUNDS, AES128_KEY_SIZE>(data, len, key, iv);
}

void aes128_cbc_dec(uint8_t* data, size_t len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_dec<AES128_ROUNDS, AES128_KEY_SIZE>(data, len, key, iv);
}

void aes128_cbc_pkcs7_enc(uint8_t* data, size_t& len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_enc<AES128_ROUNDS, AES128_KEY_SIZE>(data, len, key, iv);
  pkcs7_unpad(data, len);
}

void aes128_cbc_pkcs7_dec(uint8_t* data, size_t& len, const uint8_t key[AES128_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_dec<AES128_ROUNDS, AES128_KEY_SIZE>(data, len, key, iv);
  pkcs7_unpad(data, len);
}


void aes256_cbc_enc(uint8_t* data, size_t len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_enc<AES256_ROUNDS, AES256_KEY_SIZE>(data, len, key, iv);
}

void aes256_cbc_dec(uint8_t* data, size_t len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_dec<AES256_ROUNDS, AES256_KEY_SIZE>(data, len, key, iv);
}

void aes256_cbc_pkcs7_enc(uint8_t* data, size_t& len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_enc<AES256_ROUNDS, AES256_KEY_SIZE>(data, len, key, iv);
  pkcs7_unpad(data, len);
}

void aes256_cbc_pkcs7_dec(uint8_t* data, size_t& len, const uint8_t key[AES256_KEY_SIZE], uint8_t iv[AES_BLOCK_SIZE]) {
  aes_cbc_dec<AES256_ROUNDS, AES256_KEY_SIZE>(data, len, key, iv);
  pkcs7_unpad(data, len);
}