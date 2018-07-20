#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "eapol.h"
#include "utils.h"

#define send_buf_data (send_buf + sizeof(eapol_pkt_t))
#define recv_buf_data ((uint8_t *) recv_pkt + sizeof(eapol_pkt_t))

// Const
static const struct ether_addr PAE_GROUP_ADDR = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

// EAPoL Context
eapol_ctx_t *ctx = NULL;

// MAC Addresses
static struct ether_addr mac_addr = {0};

// BPF Handler
static int bpf_fd = 0;

// Timeout 30 seconds
static struct timeval timeout = {30, 0};

// Buffer
static size_t buf_len = BPF_MAXBUFSIZE;
static uint8_t *send_buf = NULL;
static uint8_t *recv_buf = NULL;

// Packet pointers
static eapol_pkt_t *recv_pkt = NULL;
static eapol_pkt_t *send_pkt = NULL;
static uint16_t send_len = 0;

int eapol_init(eapol_ctx_t *c) {
    if (c == NULL || c->interface == NULL || c->id == NULL || c->md5 == NULL)
        return EAPOL_E_INVALID_PARAMETERS;
    else
        ctx = c;

    // Init interface and get MAC address
    if (util_get_mac(ctx->interface, mac_addr.octet) != UTIL_OK)
        return EAPOL_E_INIT_INTERFACE;

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
            return EAPOL_E_BPF_OPEN;
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ctx->interface, sizeof(ifr.ifr_name));
    u_int flag = 1;

    if (ioctl(bpf_fd, BIOCGBLEN, &buf_len) < 0 // Get read buffer length
        || ioctl(bpf_fd, BIOCSETIF, &ifr) < 0 // Set bpf interface
        || ioctl(bpf_fd, BIOCIMMEDIATE, &flag) < 0 // Enable immediate mode
        || ioctl(bpf_fd, BIOCSHDRCMPLT, &flag) < 0 // Set header complete to 1 (not auto)
        || ioctl(bpf_fd, BIOCSRTIMEOUT, &timeout) < 0) // Time out setting
    {
        close(bpf_fd);
        return EAPOL_E_IOCTL;
    }

    if ((send_buf = malloc(buf_len)) == NULL)
        return EAPOL_E_MALLOC;

    if ((recv_buf = malloc(buf_len)) == NULL) {
        free(send_buf);
        return EAPOL_E_MALLOC;
    }

    // Setup the EAPoL request header with source MAC address and PAE group address
    ether_hdr_t *eth_hdr = (ether_hdr_t *) send_buf;
    memcpy(eth_hdr->ether_shost, mac_addr.octet, sizeof(struct ether_addr));
    memcpy(eth_hdr->ether_dhost, PAE_GROUP_ADDR.octet, sizeof(struct ether_addr));
    eth_hdr->ether_type = htons(ETHERTYPE_PAE);

    // Packet pointer to send buffer
    send_pkt = (eapol_pkt_t *) send_buf;
    recv_pkt = (eapol_pkt_t *) send_buf;

    return EAPOL_OK;
}

void eapol_cleanup() {
    free(recv_buf);
    free(send_buf);
}

static int eapol_send() {
    send_pkt->eapol_hdr.version = EAPOL_VERSION;

    if (recv_pkt->eap_hdr.type != EAP_TYPE_NONE) {
        uint16_t length = htons(send_len + sizeof(eap_hdr_t));

        send_pkt->eapol_hdr.type = EAPOL_EAP_PACKET;
        send_pkt->eapol_hdr.length = length;
        send_pkt->eap_hdr.code = EAP_RESPONSE;
        send_pkt->eap_hdr.id = recv_pkt->eap_hdr.id;
        send_pkt->eap_hdr.length = length;
        send_pkt->eap_hdr.type = recv_pkt->eap_hdr.type;
        send_len += sizeof(eapol_pkt_t);
    } else if (send_pkt->eapol_hdr.type == EAPOL_START || send_pkt->eapol_hdr.type == EAPOL_LOGOFF) {
        send_pkt->eapol_hdr.length = 0;
        send_len = sizeof(ether_hdr_t) + sizeof(eapol_hdr_t);
    } else {
        // What happened?!
        return EAPOL_E_SEND;
    }

    if (write(bpf_fd, send_buf, send_len) == -1) {
        return EAPOL_E_SEND;
    }

    // Set EAP type to none
    recv_pkt->eap_hdr.type = EAP_TYPE_NONE;

    return EAPOL_OK;
}

static inline int eapol_recv() {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(bpf_fd, &readset);
    ioctl(bpf_fd, BIOCFLUSH);

    if (select(bpf_fd + 1, &readset, NULL, NULL, &timeout) != 1)
        return EAPOL_E_RECV;

    if (read(bpf_fd, recv_buf, buf_len) == -1)
        return EAPOL_E_RECV;

    // The receive packet without BPF header
    recv_pkt = (eapol_pkt_t *) (recv_buf + ((struct bpf_hdr *) recv_buf)->bh_hdrlen);

    return EAPOL_OK;
}

int eapol_start() {
    send_pkt->eapol_hdr.type = EAPOL_START;

    return eapol_send();
}

int eapol_logoff() {
    send_pkt->eapol_hdr.type = EAPOL_LOGOFF;

    return eapol_send();
}

static int eapol_send_id() {
    ctx->id(send_buf_data, &send_len);

    return eapol_send();
}

static inline int eapol_send_md5() {
    ctx->md5(recv_pkt->eap_hdr.id, recv_buf_data, send_buf_data, &send_len);

    return eapol_send();
}

int eapol_dispatcher() {
    if (eapol_recv() != EAPOL_OK)
        return EAPOL_E_RECV;

    // Ignore non EAPoL ethernet type
    if (ntohs(recv_pkt->eth_hdr.ether_type) != ETHERTYPE_PAE
        || memcmp(recv_pkt->eth_hdr.ether_dhost, mac_addr.octet, sizeof(struct ether_addr)) != 0) {
        return EAPOL_OK;
    }

    if (recv_pkt->eapol_hdr.type != EAPOL_EAP_PACKET)
        return EAPOL_OK;

    switch (recv_pkt->eap_hdr.code) {
        case EAP_REQUEST:
            switch (recv_pkt->eap_hdr.type) {
                case EAP_TYPE_IDENTITY:
                    fprintf(stderr, "EAP_TYPE_IDENTITY\n");
                    return eapol_send_id();

                case EAP_TYPE_MD5:
                    fprintf(stderr, "EAP_TYPE_MD5\n");
                    eapol_send_md5();
                    break;

                case EAP_TYPE_H3C:
                    fprintf(stderr, "EAP_TYPE_H3C\n");
                    break;

                default:
                    fprintf(stderr, "Unknown EAP request type: %d\n", recv_pkt->eap_hdr.type);
            }
            break;

        case EAP_RESPONSE:
            fprintf(stdout, "EAP Response\n");
            break;

        case EAP_SUCCESS:
            fprintf(stdout, "EAP Success\n");
            break;

        case EAP_FAILURE:
            fprintf(stdout, "EAP Failure\n");
            return EAPOL_E_AUTH_FAILURE;

        case 10:
            // TODO: Show message
            break;

        default:
            fprintf(stderr, "Unknown EAP code: %d\n", recv_pkt->eap_hdr.code);
    }

    return EAPOL_OK;
}
