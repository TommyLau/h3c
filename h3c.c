#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "eapol.h"
#include "h3c.h"

// H3C version information
const static uint8_t VERSION_INFO[32] = {
        0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E', '8', 'B', 'Z', '3', 'M', 'q', 'H', 'h',
        's', '3', 'c', 'l', 'M', 'r', 'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=', 0x20, 0x20
};

// H3C context
static h3c_context_t *h3c = NULL;

int h3c_init(h3c_context_t *hc) {
    // Check parameters
    if (hc == NULL || hc->interface == NULL || hc->username == NULL || hc->password == NULL)
        return H3C_E_INVALID_PARAMETERS;

    h3c = hc;

    if (eapol_init(h3c->interface) != EAPOL_OK)
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
