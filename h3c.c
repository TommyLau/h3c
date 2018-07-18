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
    h3c_logoff();
    eapol_cleanup();
}

static void h3c_signal_handler() {
    fprintf(stdout, "Exiting...\n");
    h3c_cleanup();
    exit(EXIT_SUCCESS);
}

int h3c_start() {
    eapol_header(EAPOL_START, 0);

    printf("ether_hdr_t: %ld, eapol_hdr_t: %ld\n",
           sizeof(eapol_hdr_t),
           sizeof(eapol_hdr_t));

    if (eapol_send(sizeof(ether_hdr_t) + sizeof(eapol_hdr_t)) != EAPOL_OK)
        return H3C_E_START_FAIL;

    return H3C_OK;
}

int h3c_logoff() {
    eapol_header(EAPOL_LOGOFF, 0);

    if (eapol_send(sizeof(ether_hdr_t) + sizeof(eapol_hdr_t)) != EAPOL_OK)
        return H3C_E_LOGOFF_FAIL;

    return H3C_OK;
}

void h3c_run() {
    signal(SIGINT, h3c_signal_handler);
    signal(SIGTERM, h3c_signal_handler);

    while (true) {
        if (eapol_dispatcher() != EAPOL_OK) {
            fprintf(stderr, "Failed to response.\n");
            exit(EXIT_FAILURE);
        }
    }
}
