#pragma once

#include <net/ethernet.h>
#include <stdint.h>

#define EAPOL_VERSION 1

enum {
    EAPOL_EAP_PACKET = 0,
    EAPOL_START = 1,
    EAPOL_LOGOFF = 2,
    EAPOL_KEY = 3,
    EAPOL_ENCAPSULATED_ASF_ALERT = 4
};

enum {
    EAP_REQUEST = 1,
    EAP_RESPONSE = 2,
    EAP_SUCCESS = 3,
    EAP_FAILURE = 4
};

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

enum {
    EAPOL_OK = 0,
    EAPOL_E_INIT_INTERFACE,
    EAPOL_E_BPF_OPEN,
    EAPOL_E_IOCTL,
    EAPOL_E_MALLOC,
    EAPOL_E_SEND,
    EAPOL_E_RECV
};

struct eapol_hdr {
    uint8_t version;
    uint8_t type;
    uint16_t length;
}__attribute__ ((packed));

struct eap_hdr {
    uint8_t code;
    uint8_t id;
    uint16_t length;
}__attribute__ ((packed));

struct eapol_pkt {
    struct ether_header eth_hdr;
    struct eapol_hdr eapol_hdr;
    struct eap_hdr eap_hdr;
}__attribute__ ((packed));

typedef struct ether_header ether_hdr_t;
typedef struct eapol_hdr eapol_hdr_t;
typedef struct eap_hdr eap_hdr_t;
typedef struct eapol_pkt eapol_pkt_t;

typedef int (*eapol_cb_t)();

struct eapol_callback {
    eapol_cb_t success;
    eapol_cb_t failure;
    eapol_cb_t eap;
    eapol_cb_t response;
    eapol_cb_t unknown;
};

typedef struct eapol_callback eapol_callback_t;

int eapol_init(const char *interface);

void eapol_cleanup();

int eapol_send(int length);

void eapol_header(uint8_t type, uint16_t length);

void eap_header(uint8_t code, uint8_t id, uint16_t length);

int eapol_start();

int eapol_dispatcher();
