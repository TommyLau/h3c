#pragma once

#include "eapol.h"

enum {
    H3C_OK = 0,
    H3C_E_INVALID_PARAMETERS,
    H3C_E_EAPOL_INIT,
    H3C_S_INIT
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

int h3c_start();

int h3c_logoff();

void h3c_run();
