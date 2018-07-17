#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "h3c.h"

static int bpf_fd = 0;
static struct timeval timeout = {0};
static uint8_t *recv_buf = NULL;

int h3c_init(char *interface) {

    uint8_t mac_addr[6] = {0};
    FILE *fp = NULL;
    char bpf_num_str[32] = {0};
    int bpf_num = 0;

    fp = popen("sysctl debug.bpf_maxdevices", "r");
    fgets(bpf_num_str, sizeof(bpf_num_str), fp);
    bpf_num = atoi(bpf_num_str + 22);
    fclose(fp);

    for (int i = 0; i < bpf_num; i++) {
        char bpf_path[FILENAME_MAX] = {0};
        sprintf(bpf_path, "/dev/bpf%d", i);
        fprintf(stdout, "%s\n", bpf_path);
        if ((bpf_fd = open(bpf_path, O_RDWR)) >= 0)
            break;
        if (i == bpf_num - 1) {
            fprintf(stderr, "Fail to open bpf device\n");
            abort();
        }
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

    struct bpf_program bpf_pro;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    const int ci_immediate = 1, cmplt = 1;
    size_t buf_len, set_buf_len = 128;
    if (ioctl(bpf_fd, BIOCSBLEN, &set_buf_len) == -1
        || ioctl(bpf_fd, BIOCSETIF, &ifr) == -1
        || ioctl(bpf_fd, BIOCIMMEDIATE, &ci_immediate) == -1
        || ioctl(bpf_fd, BIOCSHDRCMPLT, &cmplt) == -1
        || ioctl(bpf_fd, BIOCGBLEN, &buf_len) == -1
        || ioctl(bpf_fd, BIOCSRTIMEOUT, &timeout) == -1) {
        fprintf(stderr, "ioctl fail\n");
        close(bpf_fd);
        abort();
    }

    recv_buf = malloc(buf_len);

    // TODO: Move get MAC address to a helper function
    // Get MAC address
    int ifindex;
    if ((ifindex = if_nametoindex(interface)) == 0) {
        fprintf(stderr, "Cannot open the specific network interface\n");
        close(bpf_fd);
        abort();
    }

    int mib[6] = {CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, ifindex};
    size_t sysctl_len;
    if (sysctl(mib, 6, NULL, &sysctl_len, NULL, 0) < 0) {
        fprintf(stderr, "sysctl error\n");
        free(recv_buf);
        close(bpf_fd);
        abort();
    }

    char *macbuf = malloc(sysctl_len);
    if (sysctl(mib, 6, macbuf, &sysctl_len, NULL, 0) < 0) {
        fprintf(stderr, "sysctl error\n");
        free(macbuf);
        free(recv_buf);
        close(bpf_fd);
        abort();
    }

    struct if_msghdr *ifm = (struct if_msghdr *) macbuf;
    struct sockaddr_dl *sdl = (struct sockaddr_dl *) (ifm + 1);
    unsigned char *ptr = (unsigned char *) LLADDR(sdl);
    memcpy(mac_addr, ptr, sizeof(mac_addr));
    free(macbuf);


    for (int j = 0; j < 6; ++j) {
        fprintf(stdout, "%02X ", mac_addr[j]);
    }

    free(recv_buf);

    close(bpf_fd);

    return 0;
}
