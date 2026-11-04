/*
 * conv_thread_token_check.c — a throwaway PAM module for the conversation
 * threading E2E (scripts/ci/test-pam-conv-thread.sh).
 *
 * WHY THIS EXISTS
 *   The threaded path collects the host's password on a worker thread with
 *   `pam_get_authtok`, which caches it in the PAM handle (`pam_set_item`,
 *   libpam/pam_get_authtok.c:202).  That cached token is what makes password
 *   fallback possible *after* `pam_tapauth.so` has already returned: the next
 *   module in the stack reads it instead of prompting again — the prompt has
 *   already been consumed.
 *
 *   So a test that only looks at `pam_authenticate`'s return code cannot tell
 *   "the password was collected and handed on" from "the password was
 *   swallowed and the stack failed for an unrelated reason".  This module is
 *   stacked directly after the module under test so that the difference is
 *   observable.
 *
 * WHAT IT DOES
 *   - Reads `PAM_AUTHTOK` with `pam_get_item`.
 *   - Writes the verdict to the path given by the `marker=` option, on every
 *     path, so the script can prove the module ran at all:
 *       match     — the cached token was readable and equal to `expected=`
 *       mismatch  — the cached token was readable but different (or the stack
 *                   line carried no `expected=`, which can never match)
 *       no-token  — no cached token was visible to this module
 *   - Returns PAM_SUCCESS only on a match.
 *
 *   `expected=` is compared byte for byte against the token, and a line that
 *   omits it can never produce a `match`.  The token itself is never written
 *   out; the marker only records the verdict, so a failing run does not leave
 *   the password on disk.
 *
 * Never install this.  It is compiled into a temporary directory as a shared
 * object and referenced by absolute path from a private PAM confdir.
 */

#define _GNU_SOURCE

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#define OPT_EXPECTED "expected="
#define OPT_MARKER "marker="

static void write_marker(const char *path, const char *verdict) {
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        return;
    }
    fprintf(f, "%s\n", verdict);
    fclose(f);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                  const char **argv) {
    (void)flags;

    const char *expected = NULL;
    const char *marker = NULL;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], OPT_EXPECTED, strlen(OPT_EXPECTED)) == 0) {
            expected = argv[i] + strlen(OPT_EXPECTED);
        } else if (strncmp(argv[i], OPT_MARKER, strlen(OPT_MARKER)) == 0) {
            marker = argv[i] + strlen(OPT_MARKER);
        }
    }

    const void *item = NULL;
    int ret = pam_get_item(pamh, PAM_AUTHTOK, &item);

    const char *verdict;
    if (ret != PAM_SUCCESS || item == NULL) {
        verdict = "no-token";
    } else if (expected != NULL && strcmp((const char *)item, expected) == 0) {
        verdict = "match";
    } else {
        verdict = "mismatch";
    }

    if (marker != NULL) {
        /* Written on every path: the file proves this module ran, its content
         * proves whether the token cached by the previous module was usable. */
        write_marker(marker, verdict);
    }

    if (strcmp(verdict, "match") != 0) {
        pam_syslog(pamh, LOG_NOTICE, "tapauth conv-thread token check: %s", verdict);
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                             const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
