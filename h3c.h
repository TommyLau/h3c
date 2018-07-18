#pragma once

#include "eapol.h"

enum {
    H3C_OK = 0,
    H3C_E_INVALID_PARAMETERS,
    H3C_E_EAPOL_INIT,
    H3C_E_START_FAIL,
    H3C_E_LOGOFF_FAIL
};

struct h3c_context {
    char *interface;
    char *username;
    char *password;
    eapol_callback_t *callback;
};

typedef struct h3c_context h3c_context_t;

int h3c_init(h3c_context_t *hc);

void h3c_cleanup();

int h3c_start();

int h3c_logoff();

void h3c_run();
