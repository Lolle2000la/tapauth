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
 *   on a real system — only inside disposable CI containers/test roots. It
 *   mirrors only the surface the test scripts rely on:
 *     - CLI:    pamtester [-v] [--conv-err] [--null-conv] <service> <user> <operation>
 *     - ops:    authenticate | open_session | close_session
 *     - conv:   upstream `misc_conv` semantics, plus optional failure injection
 *     - exit:   0 on PAM_SUCCESS, non-zero otherwise (the E2E suite asserts on
 *               exit codes only, so it is drop-in compatible with the real
 *               tool); 3 when `--null-conv` makes pam_start() itself fail.
 *   One deliberate simplification: upstream `misc_conv` supports
 *   PAM_BINARY_PROMPT through `pam_binary_handler_fn`, this stand-in does not
 *   (neither does any code under test use it). If the suite ever needs another
 *   operation or option, extend it here rather than assuming upstream parity.
 *
 * OPTIONS (besides `-v`, which is accepted and ignored like upstream)
 *   --conv-err    The conversation callback answers PAM_CONV_ERR for every
 *                 message without reading stdin, emulating a host that refuses
 *                 to talk to the module. Nothing is printed for those calls;
 *                 the messages are still written to the conversation log.
 *   --null-conv   Pass a NULL conversation to pam_start(). A module that runs
 *                 without a conversation must not crash. If libpam rejects the
 *                 NULL conversation, this prints
 *                 `pam_start failed (PAM error N)` and exits 3 so the caller
 *                 can SKIP the case instead of reporting a failure.
 *
 * OUTPUT
 *   - `PAM_RESULT=<int>` is always printed to stdout once the operation has
 *     returned (it is not printed when pam_start() itself failed under
 *     `--null-conv`, because no operation ran — the exit code 3 says so).
 *   - Exit code: 0 iff the operation returned PAM_SUCCESS, else 1.
 *   - If $PAMTESTER_CONV_LOG is set, the conversation is logged to that file,
 *     one line per call (newlines and control characters escaped):
 *
 *       START T=0.000
 *       SEQ=1 T=0.012 STYLE=TEXT_INFO MSG=TapAuth: Waiting for your phone...
 *       SEQ=2 T=0.014 STYLE=PROMPT_ECHO_OFF MSG=Password:
 *       RETURN T=2.018 CODE=9
 *
 *     STYLE is TEXT_INFO, ERROR_MSG, PROMPT_ECHO_ON, PROMPT_ECHO_OFF or
 *     BINARY_PROMPT. `T` is seconds since process start, `%.3f`; SEQ numbers
 *     the messages from 1 (START/RETURN carry no SEQ). START is the first line
 *     and RETURN the last; on a `--null-conv` pam_start failure RETURN records
 *     the pam_start code and the process exits 3.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <security/pam_appl.h>

static struct timespec g_start;

static double elapsed_secs(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - g_start.tv_sec) +
           (double)(now.tv_nsec - g_start.tv_nsec) / 1e9;
}

/* Set when --conv-err was passed: every message is refused. */
static int g_conv_err = 0;
/* Conversation log ($PAMTESTER_CONV_LOG), NULL when logging is off. */
static FILE *g_log = NULL;
/* 1-based message counter for the SEQ field. */
static unsigned long g_seq = 0;

/*
 * Escape a message for the single-line conversation log: backslash, newline,
 * carriage return and tab get their C spelling, any other control byte their
 * \xNN form. Everything else is copied through (including non-ASCII bytes).
 */
static void log_escaped(const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", g_log);
            break;
        case '\n':
            fputs("\\n", g_log);
            break;
        case '\r':
            fputs("\\r", g_log);
            break;
        case '\t':
            fputs("\\t", g_log);
            break;
        default:
            if (*p < 0x20 || *p == 0x7f) {
                fprintf(g_log, "\\x%02x", *p);
            } else {
                fputc(*p, g_log);
            }
        }
    }
}

static const char *style_name(int style) {
    switch (style) {
    case PAM_PROMPT_ECHO_OFF:
        return "PROMPT_ECHO_OFF";
    case PAM_PROMPT_ECHO_ON:
        return "PROMPT_ECHO_ON";
    case PAM_ERROR_MSG:
        return "ERROR_MSG";
    case PAM_TEXT_INFO:
        return "TEXT_INFO";
    case PAM_BINARY_PROMPT:
        return "BINARY_PROMPT";
    default:
        return "UNKNOWN";
    }
}

/* Record one conversation message in the log, if logging is enabled. */
static void log_message(int style, const char *text) {
    if (!g_log) {
        return;
    }
    g_seq++;
    fprintf(g_log, "SEQ=%lu T=%.3f STYLE=%s MSG=", g_seq, elapsed_secs(),
            style_name(style));
    log_escaped(text ? text : "");
    fputc('\n', g_log);
    fflush(g_log);
}

/*
 * Conversation callback with upstream `misc_conv` semantics: prompts are
 * printed and answered from stdin, PAM_TEXT_INFO/PAM_ERROR_MSG are displayed.
 * EOF on a prompt is *not* a conversation error upstream (`misc_conv`'s `nc ==
 * 0` branch): the callback returns PAM_SUCCESS with a NULL response entry for
 * that message, i.e. "the host had nothing to say". Every call is additionally
 * written to $PAMTESTER_CONV_LOG when that is set.
 *
 * With --conv-err every call is refused (PAM_CONV_ERR) without reading stdin or
 * rendering anything — messages included, so a module that sends a
 * PAM_TEXT_INFO also sees the error. That is what a host whose conversation is
 * unusable looks like.
 */
static int conv_fn(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr) {
    (void)appdata_ptr;

    *resp = NULL;
    if (num_msg <= 0 || msg == NULL) {
        return PAM_CONV_ERR;
    }

    if (g_conv_err) {
        for (int i = 0; i < num_msg; i++) {
            if (msg[i] != NULL) {
                log_message(msg[i]->msg_style, msg[i]->msg);
            }
        }
        return PAM_CONV_ERR;
    }

    struct pam_response *reply = calloc((size_t)num_msg, sizeof(*reply));
    if (reply == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        const struct pam_message *m = msg[i];
        if (m == NULL) {
            goto fail;
        }
        log_message(m->msg_style, m->msg);

        switch (m->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON: {
            char buf[PAM_MAX_MSG_SIZE + 2];
            fputs(m->msg ? m->msg : "", stdout);
            fflush(stdout);
            if (fgets(buf, (int)sizeof(buf), stdin) == NULL) {
                /* EOF: upstream misc_conv returns PAM_SUCCESS with no answer
                 * (its `nc == 0` branch) — this response stays NULL and the
                 * remaining messages are not asked. Not PAM_CONV_ERR. */
                goto done;
            }
            buf[strcspn(buf, "\n")] = '\0';
            reply[i].resp = strdup(buf);
            if (reply[i].resp == NULL) {
                goto fail;
            }
            reply[i].resp_retcode = 0;
            break;
        }
        case PAM_ERROR_MSG:
            fprintf(stderr, "%s\n", m->msg ? m->msg : "");
            break;
        case PAM_TEXT_INFO:
            fprintf(stdout, "%s\n", m->msg ? m->msg : "");
            break;
        default:
            /* Upstream handles PAM_BINARY_PROMPT via pam_binary_handler_fn;
             * this stand-in deliberately leaves it unsupported. */
            goto fail;
        }
    }

done:
    *resp = reply;
    return PAM_SUCCESS;

fail:
    for (int i = 0; i < num_msg; i++) {
        free(reply[i].resp);
    }
    free(reply);
    return PAM_CONV_ERR;
}

static struct pam_conv conv = {
    conv_fn,
    NULL
};

int main(int argc, char *argv[]) {
    char *service = NULL;
    char *user = NULL;
    char *operation = NULL;
    int null_conv = 0;

    clock_gettime(CLOCK_MONOTONIC, &g_start);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            continue;
        }
        if (strcmp(argv[i], "--conv-err") == 0) {
            g_conv_err = 1;
            continue;
        }
        if (strcmp(argv[i], "--null-conv") == 0) {
            null_conv = 1;
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
        fprintf(stderr,
                "Usage: pamtester [-v] [--conv-err] [--null-conv] "
                "<service> <user> <operation>\n");
        return 1;
    }

    const char *log_path = getenv("PAMTESTER_CONV_LOG");
    if (log_path && *log_path) {
        g_log = fopen(log_path, "w");
        if (g_log) {
            fputs("START T=0.000\n", g_log);
            fflush(g_log);
        } else {
            fprintf(stderr, "pamtester: cannot open PAMTESTER_CONV_LOG '%s': %s\n",
                    log_path, strerror(errno));
        }
    }

    pam_handle_t *pamh = NULL;
    const struct pam_conv *conv_ptr = null_conv ? NULL : &conv;
    int ret = pam_start(service, user, conv_ptr, &pamh);
    if (ret != PAM_SUCCESS) {
        /* pamh is frequently unusable after a failed pam_start, so report the
         * numeric PAM error rather than passing a possibly-NULL handle. */
        fprintf(stderr, "pam_start failed (PAM error %d)\n", ret);
        if (g_log) {
            /* No operation ran; record why so the log still ends with RETURN. */
            fprintf(g_log, "RETURN T=%.3f CODE=%d\n", elapsed_secs(), ret);
            fclose(g_log);
        }
        /* A NULL conversation is a deliberate probe (--null-conv): report it
         * with a distinct exit code so the caller can SKIP rather than FAIL. */
        return null_conv ? 3 : 1;
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
        if (g_log) {
            fprintf(g_log, "RETURN T=%.3f CODE=%d\n", elapsed_secs(), PAM_ABORT);
            fclose(g_log);
        }
        return 1;
    }

    printf("PAM_RESULT=%d\n", ret);
    fflush(stdout);

    if (g_log) {
        fprintf(g_log, "RETURN T=%.3f CODE=%d\n", elapsed_secs(), ret);
        fclose(g_log);
        g_log = NULL;
    }

    pam_end(pamh, ret);
    return (ret == PAM_SUCCESS) ? 0 : 1;
}
