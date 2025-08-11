#pragma once

// rcon lookup table
constexpr uint8_t LOOKUP_RCON[] = { 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A };

// row shifts lookup table
constexpr uint8_t SHIFT_ROWS_TABLE[] = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
constexpr uint8_t SHIFT_ROWS_TABLE_INV[] = { 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3 };

constexpr std::array<uint8_t, 256> generate_sbox(uint32_t p, uint8_t a) {
  // calculate multiplicative inverse
  std::array<uint8_t, 256> t = std::array<uint8_t, 256>();
  for (uint32_t i = 0, x = 1; i < 256; i++) {
    t[i] = (uint8_t)x;
    x ^= (x << 1) ^ ((x >> 7) * p);
  }

  // generate sbox with affine transformation
  std::array<uint8_t, 256> sbox = std::array<uint8_t, 256>();
  sbox[0] = ~a;
  for (uint32_t i = 0; i < 255; i++) {
    uint32_t x = t[255 - i];
    x |= x << 8;
    x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
    sbox[t[i]] = ~(uint8_t)(x ^ a ^ t[i]);
  }

  return sbox;
}

constexpr std::array<uint8_t, 256> inverse_sbox(std::array<uint8_t, 256> sbox) {
  // generate inverse of sbox
  std::array<uint8_t, 256> inv_sbox = std::array<uint8_t, 256>();
  for (uint32_t i = 0; i < 256; i++) {
    inv_sbox[(uint8_t)~(i ^ sbox[i])] = sbox[i];
  }

  return inv_sbox;
}

// s-boxes lookup table
constexpr std::array<uint8_t, 256> LOOKUP_SBOX = generate_sbox(0x11B, 0x63);
constexpr std::array<uint8_t, 256> LOOKUP_SBOX_INV = inverse_sbox(LOOKUP_SBOX);

constexpr std::array<uint8_t, 256> generate_gmul(uint32_t mul) {
  std::array<uint8_t, 256> gmul = std::array<uint8_t, 256>();
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t a = mul;
    uint32_t b = i;
    uint32_t p = 0;

    for (uint32_t j = 0; j < 8; j++) {
      if ((b & 1) != 0) p ^= a;
      bool hi = (a & 0x80) != 0;
      a <<= 1;
      if (hi) a ^= 0x1B;
      b >>= 1;
    }

    gmul[i] = (uint8_t)p;
  }

  return gmul;
}

// galois field multiplications lookup table
constexpr std::array<uint8_t, 256> LOOKUP_G2 = generate_gmul(2);
constexpr std::array<uint8_t, 256> LOOKUP_G3 = generate_gmul(3);
constexpr std::array<uint8_t, 256> LOOKUP_G9 = generate_gmul(9);
constexpr std::array<uint8_t, 256> LOOKUP_G11 = generate_gmul(11);
constexpr std::array<uint8_t, 256> LOOKUP_G13 = generate_gmul(13);
constexpr std::array<uint8_t, 256> LOOKUP_G14 = generate_gmul(14);