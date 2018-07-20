#pragma once

#include "eapol.h"

enum {
    H3C_OK = 0,
    H3C_E_INVALID_PARAMETERS,
    H3C_E_EAPOL_INIT,
    H3C_E_EAPOL_START,
    H3C_E_EAPOL_RESPONSE,
    H3C_S_EAP_START,
    H3C_S_EAP_RESPONSE,
    H3C_S_EAP_SUCCESS,
    H3C_S_EAP_FAILURE,
    H3C_S_EAP_UNKNOWN,
    H3C_S_EAP_TYPE_IDENTITY,
    H3C_S_EAP_TYPE_MD5,
    H3C_S_EAP_TYPE_H3C,
};


typedef void (h3c_output_cb_t)(int stat);

struct h3c_ctx {
    const char *interface;
    const char *username;
    const char *password;
    h3c_output_cb_t *output;
};

typedef struct h3c_ctx h3c_ctx_t;

const char *h3c_desc(int code);

int h3c_init(h3c_ctx_t *c);

void h3c_cleanup();

void h3c_run();
