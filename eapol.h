#pragma once

#include <net/ethernet.h>
#include <stdint.h>

#define EAPOL_VERSION 1

// ------------------------------------------------------------
// Enumeration
// ------------------------------------------------------------
// EAPoL Type
enum {
    EAPOL_EAP_PACKET = 0,
    EAPOL_START = 1,
    EAPOL_LOGOFF = 2
};

// EAP Code
enum {
    EAP_REQUEST = 1,
    EAP_RESPONSE = 2,
    EAP_SUCCESS = 3,
    EAP_FAILURE = 4
};

// EAP Type
enum {
    EAP_TYPE_NONE = 0,
    EAP_TYPE_IDENTITY = 1, /* RFC 3748 */
    EAP_TYPE_MD5 = 4, /* RFC 3748 */
    EAP_TYPE_H3C = 7 /* H3C iNode */
};

// EAPoL Error Code
enum {
    EAPOL_OK = 0,
    EAPOL_E_INVALID_PARAMETERS,
    EAPOL_E_INIT_INTERFACE,
    EAPOL_E_BPF_OPEN,
    EAPOL_E_IOCTL,
    EAPOL_E_MALLOC,
    EAPOL_E_SEND,
    EAPOL_E_RECV,
    EAPOL_E_AUTH_FAILURE
};


// ------------------------------------------------------------
// Define the header & packet struct of EAP and EAPoL
// ------------------------------------------------------------
// EAP Header
struct eap_hdr {
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t type;
}__attribute__((packed));

// EAPoL Header
struct eapol_hdr {
    uint8_t version;
    uint8_t type;
    uint16_t length;
}__attribute__ ((packed));

// EAPoL Packet
struct eapol_pkt {
    struct ether_header eth_hdr;
    struct eapol_hdr eapol_hdr;
    struct eap_hdr eap_hdr;
}__attribute__ ((packed));

typedef struct ether_header ether_hdr_t;
typedef struct eapol_hdr eapol_hdr_t;
typedef struct eap_hdr eap_hdr_t;
typedef struct eap_pkt eap_pkt_t;
typedef struct eapol_pkt eapol_pkt_t;


// ------------------------------------------------------------
// Define the callback function for EAP request
// ------------------------------------------------------------
// EAP Callback
typedef int (*eap_func_t)();

struct eap_cb {
    eap_func_t success;
    eap_func_t failure;
    eap_func_t eap;
    eap_func_t response;
    eap_func_t unknown;
};

typedef struct eap_cb eap_cb_t;

// EAP Request Callback
typedef int (*eap_func_send_id_t)(uint8_t *out, uint16_t *length);

typedef int (*eap_func_send_md5_t)(uint8_t id, uint8_t *in, uint8_t *out, uint16_t *length);

// ------------------------------------------------------------
// Define the EAPoL context
// ------------------------------------------------------------
struct eapol_ctx {
    const char *interface;
    eap_cb_t *eap;
    eap_func_send_id_t id;
    eap_func_send_md5_t md5;
};

typedef struct eapol_ctx eapol_ctx_t;


// ------------------------------------------------------------
// EAPoL functions
// ------------------------------------------------------------
int eapol_init(eapol_ctx_t *c);

void eapol_cleanup();

int eapol_start();

int eapol_logoff();

int eapol_dispatcher();
