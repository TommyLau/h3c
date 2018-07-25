#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef OS_DARWIN

#include <net/bpf.h>

#elif OS_LINUX

#include <linux/if_packet.h>
#include <netinet/in.h>

#endif

#include "eapol.h"
#include "utils.h"

#ifdef OS_DARWIN
#define EAPOL_BUF_LEN BPF_MAXBUFSIZE
#define EAPOL_ETH_P_PAE ETHERTYPE_PAE
#elif OS_LINUX
#define EAPOL_BUF_LEN 4096
#define EAPOL_ETH_P_PAE ETH_P_PAE
#endif

#define send_buf_data (send_buf + sizeof(eapol_pkt_t))
#define recv_buf_data ((uint8_t *) recv_pkt + sizeof(eapol_pkt_t))

// Const
static const struct ether_addr PAE_GROUP_ADDR = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

// EAPoL Context
eapol_ctx_t *ctx = NULL;

// MAC Addresses
static struct ether_addr mac_addr = {0};

#ifdef OS_LINUX
// Socket Address
static struct sockaddr_ll sock_addr = {0};
#endif

// Handler
static int fd = 0;

#ifdef OS_DARWIN
// Timeout 30 seconds
static struct timeval timeout = {30, 0};
#endif

// Buffer
static size_t buf_len = EAPOL_BUF_LEN;
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
    if (util_get_mac(ctx->interface, (uint8_t *) &mac_addr) != UTIL_OK)
        return EAPOL_E_INIT_INTERFACE;

#ifdef OS_DARWIN
    char bpf_str[32] = {0};
    char bpf_path[FILENAME_MAX] = {0};

    FILE *fp = popen("sysctl debug.bpf_maxdevices", "r");
    fgets(bpf_str, sizeof(bpf_str), fp);
    int bpf_num = atoi(bpf_str + 22);
    fclose(fp);

    for (int i = 0; i < bpf_num; i++) {
        sprintf(bpf_path, "/dev/bpf%d", i);

        if ((fd = open(bpf_path, O_RDWR)) >= 0)
            break;

        if (i == bpf_num - 1)
            return EAPOL_E_BPF_OPEN;
    }
#elif OS_LINUX
    if ((fd = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_ETH_P_PAE))) < 0)
        return EAPOL_E_INIT_INTERFACE;
#endif

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ctx->interface, sizeof(ifr.ifr_name));

#ifdef OS_DARWIN
    u_int flag = 1;

    if (ioctl(fd, BIOCGBLEN, &buf_len) < 0 // Get read buffer length
        || ioctl(fd, BIOCSETIF, &ifr) < 0 // Set bpf interface
        || ioctl(fd, BIOCIMMEDIATE, &flag) < 0 // Enable immediate mode
        || ioctl(fd, BIOCSHDRCMPLT, &flag) < 0 // Set header complete to 1 (not auto)
        || ioctl(fd, BIOCSRTIMEOUT, &timeout) < 0) // Time out setting
    {
        close(fd);
        return EAPOL_E_IOCTL;
    }
#elif OS_LINUX
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0
        || !(ifr.ifr_flags & IFF_UP)
        || ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        return EAPOL_E_IOCTL;

    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_ifindex = ifr.ifr_ifindex;
    sock_addr.sll_protocol = htons(EAPOL_ETH_P_PAE);

    if (bind(fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) == -1)
        return EAPOL_E_BIND;
#endif

    if ((send_buf = malloc(buf_len)) == NULL)
        return EAPOL_E_MALLOC;

    if ((recv_buf = malloc(buf_len)) == NULL) {
        free(send_buf);
        return EAPOL_E_MALLOC;
    }

    // Setup the EAPoL request header with source MAC address and PAE group address
    ether_hdr_t *eth_hdr = (ether_hdr_t *) send_buf;
    memcpy(eth_hdr->ether_shost, &mac_addr, sizeof(struct ether_addr));
    memcpy(eth_hdr->ether_dhost, &PAE_GROUP_ADDR, sizeof(struct ether_addr));
    eth_hdr->ether_type = htons(EAPOL_ETH_P_PAE);

    // Packet pointer to send buffer
    send_pkt = (eapol_pkt_t *) send_buf;
    recv_pkt = (eapol_pkt_t *) send_buf;

    return EAPOL_OK;
}

void eapol_cleanup() {
    free(recv_buf);
    free(send_buf);

#ifdef OS_DARWIN
    close(fd);
#elif OS_LINUX
    shutdown(fd, SHUT_RDWR);
#endif
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

#ifdef OS_DARWIN
    if (write(fd, send_buf, send_len) == -1)
        return EAPOL_E_SEND;
#elif OS_LINUX
    if (sendto(fd, send_buf, send_len, MSG_NOSIGNAL, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) == -1)
        return EAPOL_E_SEND;
#endif

    // Set EAP type to none
    recv_pkt->eap_hdr.type = EAP_TYPE_NONE;

    return EAPOL_OK;
}

static inline int eapol_recv() {
#ifdef OS_DARWIN
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    ioctl(fd, BIOCFLUSH);

    if (select(fd + 1, &readset, NULL, NULL, &timeout) != 1)
        return EAPOL_E_RECV;

    if (read(fd, recv_buf, buf_len) == -1)
        return EAPOL_E_RECV;

    // The receive packet without BPF header
    recv_pkt = (eapol_pkt_t *) (recv_buf + ((struct bpf_hdr *) recv_buf)->bh_hdrlen);
#elif OS_LINUX
    socklen_t len = sizeof(sock_addr);

    if (recvfrom(fd, recv_buf, buf_len, 0, (struct sockaddr *) &sock_addr, &len) <= 0)
        return EAPOL_E_RECV;

    recv_pkt = (eapol_pkt_t *) recv_buf;
#endif

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
    if (ntohs(recv_pkt->eth_hdr.ether_type) != EAPOL_ETH_P_PAE
        || memcmp(recv_pkt->eth_hdr.ether_dhost, &mac_addr, sizeof(struct ether_addr)) != 0) {
        return EAPOL_OK;
    }

    if (recv_pkt->eapol_hdr.type != EAPOL_EAP_PACKET)
        return EAPOL_OK;

    switch (recv_pkt->eap_hdr.code) {
        case EAP_REQUEST:
            switch (recv_pkt->eap_hdr.type) {
                case EAP_TYPE_IDENTITY:
                    return eapol_send_id();

                case EAP_TYPE_MD5:
                    eapol_send_md5();
                    break;

                case EAP_TYPE_H3C:
                    // TODO: Implement H3C method
                    return EAPOL_E_UNKNOWN_EAP_REQUEST;

                default:
                    return EAPOL_E_UNKNOWN_EAP_REQUEST;
            }
            break;

        case EAP_RESPONSE:
            if (ctx->response != NULL)
                return ctx->response();
            break;

        case EAP_SUCCESS:
            if (ctx->success != NULL)
                return ctx->success();
            break;

        case EAP_FAILURE:
            if (ctx->failure != NULL)
                return ctx->failure();
            return EAPOL_E_AUTH_FAILURE;

        case 10:
            // TODO: Show message
            break;

        default:
            if (ctx->unknown != NULL)
                return ctx->unknown();
            return EAPOL_E_UNKNOWN_EAP_CODE;
    }

    return EAPOL_OK;
}
