#pragma once

#include <stdint.h>

enum _util_error {
    E_OK = 0,
    E_NAME_TO_INDEX_FAIL,
    E_SYSCTL_ERROR_1,
    E_SYSCTL_ERROR_2,
};

typedef enum _util_error util_error_t;
typedef uint8_t macaddr_t[6];

util_error_t util_get_mac(const char *interface, macaddr_t *macaddr);
