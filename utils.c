#include <net/if.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int util_get_mac(const char *interface, u_char *macaddr) {
    size_t length = strlen(interface);

    if (length < 1 || length > IFNAMSIZ)
        return UTIL_E_INTERFACE_LENGTH;

    int index = if_nametoindex(interface);

    if (index == 0)
        return UTIL_E_NAME_TO_INDEX;

    int mib[6] = {CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, index};

    if (sysctl(mib, 6, NULL, &length, NULL, 0) < 0)
        return UTIL_E_SYSCTL_1;

    char *buf = malloc(length);

    if (sysctl(mib, 6, buf, &length, NULL, 0) < 0) {
        free(buf);
        return UTIL_E_SYSCTL_2;
    }

    struct if_msghdr *ifm = (struct if_msghdr *) buf;
    struct sockaddr_dl *sdl = (struct sockaddr_dl *) (ifm + 1);
    unsigned char *ptr = (unsigned char *) LLADDR(sdl);
    memcpy(macaddr, ptr, sizeof(struct ether_addr));
    free(buf);

    return UTIL_OK;
}
