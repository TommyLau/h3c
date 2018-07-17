#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
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

    free(recv_buf);

    close(bpf_fd);

    return 0;
}
