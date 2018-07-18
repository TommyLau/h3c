#pragma once

#include <net/ethernet.h>
#include <stdint.h>

enum {
    UTIL_OK = 0,
    UTIL_E_INTERFACE_LENGTH,
    UTIL_E_NAME_TO_INDEX,
    UTIL_E_SYSCTL_1,
    UTIL_E_SYSCTL_2
};

int util_get_mac(const char *interface, u_char *macaddr);
