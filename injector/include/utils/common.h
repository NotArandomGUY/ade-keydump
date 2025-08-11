#pragma once

#include <stdio.h>

#define LOG(fmt, ...) {\
printf("[kd-injector] ");\
printf(fmt, __VA_ARGS__);\
printf("\n");\
fflush(stdout);\
}