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

// MAC Addresses
static const struct ether_addr PAE_GROUP_ADDR = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
static struct ether_addr mac_addr = {0};

// BPF Handler
static int bpf_fd = 0;

// Timeout 30 seconds
static struct timeval timeout = {30, 0};

// Buffer
static uint8_t *send_buf = NULL;
static uint8_t *recv_buf = NULL;
static size_t buf_len = BPF_MAXBUFSIZE;
static eapol_pkt_t *pkt = NULL;

int eapol_init(const char *interface) {
    // Init interface and get MAC address
    if (util_get_mac(interface, mac_addr.octet) != UTIL_OK)
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
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
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

    return EAPOL_OK;
}

void eapol_cleanup() {
    free(recv_buf);
    free(send_buf);
}

int eapol_send(int length) {
    if (write(bpf_fd, send_buf, length) == -1) {
        return EAPOL_E_SEND;
    }

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
    pkt = (eapol_pkt_t *) (recv_buf + ((struct bpf_hdr *) recv_buf)->bh_hdrlen);

    return EAPOL_OK;
}

void eapol_header(uint8_t type, uint16_t length) {
    eapol_pkt_t *p = (eapol_pkt_t *) send_buf;
    p->eapol_hdr.version = EAPOL_VERSION;
    p->eapol_hdr.type = type;
    p->eapol_hdr.length = length;
}

void eap_header(uint8_t code, uint8_t id, uint16_t length) {
    eapol_pkt_t *p = (eapol_pkt_t *) send_buf;
    p->eap_hdr.code = code;
    p->eap_hdr.id = id;
    p->eap_hdr.length = length;
}

static inline void eapol_eapol_hdr(uint8_t type, uint16_t length) {
    eapol_pkt_t *p = (eapol_pkt_t *) send_buf;
    p->eapol_hdr.version = EAPOL_VERSION;
    p->eapol_hdr.type = type;
    p->eapol_hdr.length = length;
}

static inline void eapol_eapol_hdr_only(uint8_t type) {
    eapol_eapol_hdr(type, 0);
}

int eapol_start() {
    eapol_eapol_hdr_only(EAPOL_START);

    return eapol_send(sizeof(ether_hdr_t) + sizeof(eapol_hdr_t));
}

int eapol_logoff() {
    eapol_eapol_hdr_only(EAPOL_LOGOFF);

    return eapol_send(sizeof(ether_hdr_t) + sizeof(eapol_hdr_t));
}

static int eapol_send_id(uint8_t id) {

    return EAPOL_OK;
}

int eapol_dispatcher() {
    if (eapol_recv() != EAPOL_OK)
        return EAPOL_E_RECV;

    fprintf(stdout, "Dest: [%s], Ether type: %04x\n", ether_ntoa((struct ether_addr *) pkt->eth_hdr.ether_dhost),
            ntohs(pkt->eth_hdr.ether_type));

    // Ignore non EAPoL ethernet type
    if (ntohs(pkt->eth_hdr.ether_type) != ETHERTYPE_PAE
        || memcmp(pkt->eth_hdr.ether_dhost, mac_addr.octet, sizeof(struct ether_addr)) != 0) {
        return EAPOL_OK;
    }

    fprintf(stdout, "----- OK -----: [%s], Ether type: %04X\n",
            ether_ntoa((struct ether_addr *) pkt->eth_hdr.ether_dhost),
            ntohs(pkt->eth_hdr.ether_type));

    if (pkt->eapol_hdr.type != EAPOL_EAP_PACKET) {
        fprintf(stdout, "Not EAP Packet: %02x\n", pkt->eapol_hdr.type);
        return EAPOL_OK;
    }

    switch (pkt->eap_hdr.code) {
        case EAP_REQUEST:
            fprintf(stdout, "EAP Request\n");

            switch (((eap_pkt_t *) &pkt->eap_hdr)->type) {
                case EAP_TYPE_IDENTITY:
                    fprintf(stderr, "EAP_TYPE_IDENTITY\n");
                    printf("EAP Length: %d, : %d\n", pkt->eap_hdr.length, pkt->eap_hdr.id);
                    return eapol_send_id(pkt->eap_hdr.id);

                case EAP_TYPE_MD5:
                    fprintf(stderr, "EAP_TYPE_MD5\n");
                    break;

                case EAP_TYPE_H3C:
                    fprintf(stderr, "EAP_TYPE_H3C\n");
                    break;

                default:
                    fprintf(stderr, "Unknown EAP request type\n");
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
            break;

        default:
            fprintf(stderr, "Unknown EAP code\n");
    }

    return EAPOL_OK;
}
