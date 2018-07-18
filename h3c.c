#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "eapol.h"
#include "h3c.h"
#include "utils.h"

// H3C version information
const static uint8_t VERSION_INFO[32] = {
        0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E', '8', 'B', 'Z', '3', 'M', 'q', 'H', 'h',
        's', '3', 'c', 'l', 'M', 'r', 'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=', 0x20, 0x20
};

// H3C context
static h3c_context_t *h3c = NULL;

// Ethernet Interface
static const char *interface = NULL;

// MAC Address
static struct ether_addr mac_addr = {0};

// BPF Handler
static int bpf_fd = 0;

// Buffer
static uint8_t *send_buf = NULL;
static uint8_t *recv_buf = NULL;

// Timeout 30 seconds
static struct timeval timeout = {30, 0};

int h3c_init(h3c_context_t *hc) {
    // Check parameters
    if (hc == NULL || hc->interface == NULL || hc->username == NULL || hc->password == NULL)
        return H3C_E_INVALID_PARAMETERS;

    h3c = hc;

    // Init interface and get MAC address
    if (util_get_mac(interface = h3c->interface, &mac_addr) != UTIL_OK)
        return H3C_E_INIT_INTERFACE;

#if 0
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        printf("%02X ", mac_addr.octet[i]);
    }
    printf("\n");
#endif

    char bpf_str[32] = {0};
    char bpf_path[FILENAME_MAX] = {0};

    FILE *fp = popen("sysctl debug.bpf_maxdevices", "r");
    fgets(bpf_str, sizeof(bpf_str), fp);
    int bpf_num = atoi(bpf_str + 22);
    fclose(fp);

    for (int i = 0; i < bpf_num; i++) {
        sprintf(bpf_path, "/dev/bpf%d", i);

        if ((bpf_fd = open(bpf_path, O_RDWR)) >= 0)
            break;

        if (i == bpf_num - 1)
            return H3C_E_BPF_OPEN;
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    const int ci_immediate = 1, cmplt = 1;
    size_t buf_len, set_buf_len = 128;

    if (ioctl(bpf_fd, BIOCSBLEN, &set_buf_len) == -1
        || ioctl(bpf_fd, BIOCSETIF, &ifr) == -1
        || ioctl(bpf_fd, BIOCIMMEDIATE, &ci_immediate) == -1
        || ioctl(bpf_fd, BIOCSHDRCMPLT, &cmplt) == -1
        || ioctl(bpf_fd, BIOCGBLEN, &buf_len) == -1
        || ioctl(bpf_fd, BIOCSRTIMEOUT, &timeout) == -1) {
        close(bpf_fd);
        return H3C_E_IOCTL;
    }

    recv_buf = malloc(buf_len);

    return H3C_OK;
}

int h3c_cleanup() {
    fprintf(stdout, "Clean up . . .\n");

    free(recv_buf);
    close(bpf_fd);

    return H3C_OK;
}

static void h3c_signal_handler() {
    fprintf(stdout, "Exiting...\n");
    h3c_cleanup();
    exit(EXIT_SUCCESS);
}

void h3c_run() {
    signal(SIGINT, h3c_signal_handler);
    signal(SIGTERM, h3c_signal_handler);

    while (true) {
        // TODO: h3c_response
    }
}
