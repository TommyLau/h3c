#include <net/if.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

util_error_t util_get_mac(const char *interface, macaddr_t *macaddr) {
    int index;

    if ((index = if_nametoindex(interface)) == 0)
        return E_NAME_TO_INDEX_FAIL;

    size_t len;
    int mib[6] = {CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, index};

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
        return E_SYSCTL_ERROR_1;

    char *buf = malloc(len);

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        free(buf);
        return E_SYSCTL_ERROR_2;
    }

    struct if_msghdr *ifm = (struct if_msghdr *) buf;
    struct sockaddr_dl *sdl = (struct sockaddr_dl *) (ifm + 1);
    unsigned char *ptr = (unsigned char *) LLADDR(sdl);
    memcpy(macaddr, ptr, sizeof(macaddr_t));
    free(buf);

    return E_OK;
}
