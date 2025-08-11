#pragma once

#include <pch.h>

#define LOG(fmt, ...) {\
printf("[kd-payload] ");\
printf(fmt, __VA_ARGS__);\
printf("\n");\
fflush(stdout);\
}

std::string hex_encode(std::string bytes);