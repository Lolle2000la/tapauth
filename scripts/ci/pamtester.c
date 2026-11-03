/*
 * pamtester.c — minimal stand-in for the upstream `pamtester` utility.
 *
 * WHY THIS EXISTS
 *   The E2E suite drives the real Linux-PAM C ABI (pam_sm_authenticate ->
 *   pam_tapauth.so) through `pamtester`. Ubuntu and Fedora ship the genuine
 *   tool, but Arch Linux has no `pamtester` in its official repositories (it is
 *   AUR-only, and pulling AUR packages into CI is not acceptable), so the Arch
 *   E2E container compiles this file instead:
 *
 *       gcc -o /usr/bin/pamtester scripts/ci/pamtester.c -lpam -lpam_misc
 *
 * SCOPE / CONTRACT
 *   This is NOT a general-purpose pamtester replacement and is never installed
 *   on a real system — only inside the disposable Arch CI container. It mirrors
 *   only the surface test-e2e.sh relies on:
 *     - CLI:    pamtester [-v] <service> <user> <operation> (-v accepted, ignored)
 *     - ops:    authenticate | open_session | close_session
 *     - conv:   misc_conv, matching upstream
 *     - exit:   0 on PAM_SUCCESS, non-zero otherwise (the suite asserts on exit
 *               codes only, so it is drop-in compatible with the real tool)
 *   If the suite ever needs another operation or option, extend it here rather
 *   than assuming upstream parity.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {
    char *service = NULL;
    char *user = NULL;
    char *operation = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            continue;
        }
        if (!service) {
            service = argv[i];
        } else if (!user) {
            user = argv[i];
        } else if (!operation) {
            operation = argv[i];
        }
    }

    if (!service || !user || !operation) {
        fprintf(stderr, "Usage: pamtester [-v] <service> <user> <operation>\n");
        return 1;
    }

    pam_handle_t *pamh = NULL;
    int ret = pam_start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        /* pamh is frequently unusable after a failed pam_start, so report the
         * numeric PAM error rather than passing a possibly-NULL handle. */
        fprintf(stderr, "pam_start failed (PAM error %d)\n", ret);
        return 1;
    }

    if (strcmp(operation, "authenticate") == 0) {
        ret = pam_authenticate(pamh, 0);
    } else if (strcmp(operation, "open_session") == 0) {
        ret = pam_open_session(pamh, 0);
    } else if (strcmp(operation, "close_session") == 0) {
        ret = pam_close_session(pamh, 0);
    } else {
        fprintf(stderr, "Unsupported operation: %s\n", operation);
        pam_end(pamh, PAM_ABORT);
        return 1;
    }

    pam_end(pamh, ret);
    return (ret == PAM_SUCCESS) ? 0 : 1;
}
