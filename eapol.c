#include "eapol.h"

#define EAPOL_VERSION 1
//ETHERTYPE_PAE

static const uint8_t pae_group_addr[ETHER_ADDR_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

static uint8_t send_buf[ETHER_MAX_LEN] = {0};
static uint8_t recv_buf[ETHER_MAX_LEN] = {0};

inline void eapol_header(uint8_t type, uint16_t length) {
    eapol_packet_t *p = (eapol_packet_t *) send_buf;
    p->eapol_header.version = EAPOL_VERSION;
    p->eapol_header.type = type;
    p->eapol_header.length = length;
}

inline void eap_header(uint8_t code, uint8_t id, uint16_t length) {
    eapol_packet_t *p = (eapol_packet_t *) send_buf;
    p->eap_header.code = code;
    p->eap_header.id = id;
    p->eap_header.length = length;
}

inline int eapol_send(uint16_t length) {
    // TODO: Send data
    return EAPOL_E_OK;
}

inline int eapol_recv(uint16_t length) {
    // TODO: Receive data
    return EAPOL_E_OK;
}
