#pragma once

#include "eapol.h"

enum {
    H3C_OK = 0,
    H3C_E_INVALID_PARAMETERS,
    H3C_E_INIT_INTERFACE,
    H3C_E_BPF_OPEN,
    H3C_E_IOCTL
};

struct h3c_context {
    char *interface;
    char *username;
    char *password;
    eapol_callback_t *callback;
};

typedef struct h3c_context h3c_context_t;

int h3c_init(h3c_context_t *hc);

int h3c_cleanup();

void h3c_run();
