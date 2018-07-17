#pragma once

#include <net/ethernet.h>
#include <stdint.h>

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
    EAPOL_E_OK = 0
};

struct eapol_header {
    uint8_t version;
    uint8_t type;
    uint16_t length;
}__attribute__ ((packed));

struct eap_header {
    uint8_t code;
    uint8_t id;
    uint16_t length;
}__attribute__ ((packed));

struct eapol_packet {
    struct ether_header eth_header;
    struct eapol_header eapol_header;
    struct eap_header eap_header;
}__attribute__ ((packed));

typedef struct eapol_header eapol_header_t;
typedef struct eap_header eap_header_t;
typedef struct eapol_packet eapol_packet_t;
