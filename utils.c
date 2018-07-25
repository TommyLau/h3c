#include <net/if.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_DARWIN

#include <net/if_dl.h>

#elif OS_LINUX

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#endif

#include "utils.h"

int util_get_mac(const char *interface, u_char *macaddr) {
    size_t length = strlen(interface);

    if (length < 1 || length > IFNAMSIZ)
        return UTIL_E_INTERFACE_LENGTH;

#ifdef OS_DARWIN
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
#elif OS_LINUX
    int sock = 0;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
        return UTIL_E_SOCKET;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
        return UTIL_E_IOCTL;

    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));
#endif

    return UTIL_OK;
}
