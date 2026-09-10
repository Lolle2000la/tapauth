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
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, ret));
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
