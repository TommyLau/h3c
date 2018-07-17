#pragma once

#include <net/ethernet.h>
#include <stdint.h>

enum {
    UTIL_OK = 0,
    UTIL_NAME_TO_INDEX_FAIL,
    UTIL_SYSCTL_ERROR_1,
    UTIL_SYSCTL_ERROR_2
};

int util_get_mac(const char *interface, struct ether_addr *macaddr);
