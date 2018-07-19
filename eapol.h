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
    EAPOL_LOGOFF = 2,
    EAPOL_KEY = 3,
    EAPOL_ENCAPSULATED_ASF_ALERT = 4
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
    EAP_TYPE_IDENTITY = 1 /* RFC 3748 */,
    EAP_TYPE_NOTIFICATION = 2 /* RFC 3748 */,
    EAP_TYPE_NAK = 3 /* Response only, RFC 3748 */,
    EAP_TYPE_MD5 = 4, /* RFC 3748 */
    EAP_TYPE_OTP = 5 /* RFC 3748 */,
    EAP_TYPE_GTC = 6, /* RFC 3748 */
    EAP_TYPE_H3C = 7, /* H3C iNode */
    EAP_TYPE_TLS = 13 /* RFC 2716 */,
    EAP_TYPE_LEAP = 17 /* Cisco proprietary */,
    EAP_TYPE_SIM = 18 /* RFC 4186 */,
    EAP_TYPE_TTLS = 21 /* RFC 5281 */,
    EAP_TYPE_AKA = 23 /* RFC 4187 */,
    EAP_TYPE_PEAP = 25 /* draft-josefsson-pppext-eap-tls-eap-06.txt */,
    EAP_TYPE_MSCHAPV2 = 26 /* draft-kamath-pppext-eap-mschapv2-00.txt */,
    EAP_TYPE_TLV = 33 /* draft-josefsson-pppext-eap-tls-eap-07.txt */,
    EAP_TYPE_TNC = 38 /* TNC IF-T v1.0-r3; note: tentative assignment;
			           * type 38 has previously been allocated for
        			   * EAP-HTTP Digest, (funk.com) */,
    EAP_TYPE_FAST = 43 /* RFC 4851 */,
    EAP_TYPE_PAX = 46 /* RFC 4746 */,
    EAP_TYPE_PSK = 47 /* RFC 4764 */,
    EAP_TYPE_SAKE = 48 /* RFC 4763 */,
    EAP_TYPE_IKEV2 = 49 /* RFC 5106 */,
    EAP_TYPE_AKA_PRIME = 50 /* RFC 5448 */,
    EAP_TYPE_GPSK = 51 /* RFC 5433 */,
    EAP_TYPE_PWD = 52 /* RFC 5931 */,
    EAP_TYPE_EKE = 53 /* RFC 6124 */,
    EAP_TYPE_EXPANDED = 254 /* RFC 3748 */
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
    EAPOL_E_RECV
};


// ------------------------------------------------------------
// Define the header & packet struct of EAP and EAPoL
// ------------------------------------------------------------
/*
// EAP Header
struct eap_hdr {
    uint8_t code;
    uint8_t id;
    uint16_t length;
}__attribute__ ((packed));

// EAP Packet
struct eap_pkt {
    struct eap_hdr hdr;
    uint8_t type;
}__attribute__((packed));
 */

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

struct eap_req_cb {
    eap_func_send_id_t id;
    eap_func_send_md5_t md5;
};

typedef struct eap_req_cb eap_req_cb_t;


// ------------------------------------------------------------
// Define the EAPoL context
// ------------------------------------------------------------
struct eapol_ctx {
    const char *interface;
    eap_cb_t *eap;
    eap_req_cb_t *req;
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
