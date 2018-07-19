#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eapol.h"
#include "h3c.h"

// H3C version information
const static uint8_t VERSION_INFO[32] = {
        0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E', '8', 'B', 'Z', '3', 'M', 'q', 'H', 'h',
        's', '3', 'c', 'l', 'M', 'r', 'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=', 0x20, 0x20
};

// H3C context
static h3c_ctx_t *ctx = NULL;

// EAP context and callback
static eap_req_cb_t erc = {0};
static eapol_ctx_t ec = {0};

static int h3c_send_id(uint8_t *data, uint16_t *length) {
    memcpy(data, VERSION_INFO, sizeof(VERSION_INFO));
    memcpy(data + sizeof(VERSION_INFO), ctx->username, strlen(ctx->username));
    *length = sizeof(VERSION_INFO) + strlen(ctx->username);

    return EAPOL_OK;
}

int h3c_init(h3c_ctx_t *c) {
    // Check parameters
    if (c == NULL || c->interface == NULL || c->username == NULL || c->password == NULL
        || strlen(c->interface) == 0 || strlen(c->username) == 0 || strlen(c->password) == 0)
        return H3C_E_INVALID_PARAMETERS;
    else
        ctx = c;

    erc.id = h3c_send_id;
    ec.interface = ctx->interface;
    ec.eap = NULL;
    ec.req = &erc;

    if (eapol_init(&ec) != EAPOL_OK)
        return H3C_E_EAPOL_INIT;

    return H3C_OK;
}

void h3c_cleanup() {
    fprintf(stdout, "Clean up . . .\n");
    eapol_logoff();
    eapol_cleanup();
}

static void h3c_signal_handler() {
    fprintf(stdout, "Exiting...\n");
    h3c_cleanup();
    exit(EXIT_SUCCESS);
}

void h3c_run() {
    if (eapol_start() != EAPOL_OK) {
        fprintf(stderr, "Failed to send EAPoL authentication.\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, h3c_signal_handler);
    signal(SIGTERM, h3c_signal_handler);

    while (true) {
        if (eapol_dispatcher() != EAPOL_OK) {
            fprintf(stderr, "Failed to response.\n");
            exit(EXIT_FAILURE);
        }
    }
}
