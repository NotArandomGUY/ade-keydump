#include <pch.h>

#include "utils/common.h"

using namespace std;

string hex_encode(string bytes) {
  ostringstream ss;

  ss << hex << setfill('0');

  for (size_t i = 0; i < bytes.size(); ++i) {
    ss << setw(2) << static_cast<unsigned int>(bytes[i] & 0xFF);
  }

  return ss.str();
}