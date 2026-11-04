/*
 * conv_thread_harness.c — drives a real PAM stack through pam_tapauth.so to
 * prove the threaded-conversation path end to end.
 *
 * WHY THIS EXISTS
 *   `client-pam` picks between two GUI strategies at runtime:
 *
 *     - Threaded: a native worker thread calls `pam_get_authtok` (and therefore
 *       the host's conversation) while the calling thread waits for the phone.
 *     - Sequential: the conversation is never touched; the module only waits
 *       for the daemon.
 *
 *   The choice is an allowlist keyed on the calling process (see
 *   `conversation_mode` in client-pam/src/pam_logic.rs).  Neither half of that
 *   is reachable from a Rust unit test: it needs a real libpam stack, a real
 *   dynamically loaded module, and a process whose `/proc/self/exe` has the
 *   allowlisted name.
 *
 * HOW IT WORKS
 *   - A private PAM confdir (created by scripts/ci/test-pam-conv-thread.sh)
 *     holds the service file named by $CONV_TEST_SERVICE.  Its first `auth`
 *     entry is the freshly built `libclient_pam.so` by absolute path; what
 *     follows depends on the stack shape under test (see the script):
 *     `sufficient` + a token check, `required` + a token check, or
 *     `required` + `optional pam_permit.so`.  $CONV_TEST_SERVICE is therefore
 *     not fixed here.
 *   - A fake daemon listens on $TAPAUTHD_SOCK, accepts the module's connection
 *     and never answers, never closes: the module must reach the password path
 *     on its own rather than from a daemon response.
 *   - The conversation blocks in `PAM_PROMPT_ECHO_OFF` until a helper thread
 *     writes a password after ~200 ms, and records on which thread it ran and
 *     whether it had returned by the time `pam_authenticate` came back.
 *   - The script copies this binary to `$tmp/kscreenlocker_worker` and runs the
 *     copy, so `/proc/self/exe`'s basename is on the allowlist.  A symlink
 *     would not work: the kernel resolves it.
 *
 * CONTRACT
 *   Environment:
 *     CONV_TEST_CONFDIR  private PAM confdir (pam_start_confdir)
 *     TAPAUTHD_SOCK      the fake daemon's socket
 *     CONV_TEST_SERVICE  service file name inside CONV_TEST_CONFDIR
 *     CONV_TEST_EXPECT   `success` if pam_authenticate must return PAM_SUCCESS,
 *                        `non-success` if the stack must fail closed
 *
 *   The conversation assertions are the same for every shape: the harness is
 *   only ever run under an allowlisted process name, so it requires the
 *   conversation to have been entered, to have returned before
 *   `pam_authenticate` did (i.e. the worker was joined), and to have run off
 *   the calling thread.
 *
 *   Prints `RESULT: PASS` on success and exits 0.  Any other outcome prints a
 *   diagnostic, `RESULT: FAIL ...`, and exits non-zero.  Never install this.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define PASSWORD "conv-thread-harness-pw"
#define PASSWORD_DELAY_MS 200

static int conv_pipe[2] = {-1, -1};
static pthread_t main_thread;
static atomic_int conv_entered;
static atomic_int conv_returned;
static atomic_int conv_ran_on_main_thread;
static atomic_int daemon_accepted;

static void fail(const char *what) {
    fprintf(stderr, "RESULT: FAIL %s\n", what);
    fflush(stdout);
    fflush(stderr);
    exit(1);
}

/* ------------------------------------------------------------------ conv --- */

static int test_conv(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata) {
    (void)appdata;

    if (num_msg <= 0 || msg == NULL || resp == NULL) {
        return PAM_CONV_ERR;
    }

    struct pam_response *out = calloc((size_t)num_msg, sizeof(*out));
    if (out == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF: {
            /* Record where the prompt landed before blocking: with the
             * threaded strategy this must not be the thread that called
             * pam_authenticate. */
            atomic_store(&conv_ran_on_main_thread,
                         pthread_equal(pthread_self(), main_thread) ? 1 : 0);
            atomic_store(&conv_entered, 1);

            char buf[64];
            ssize_t n;
            do {
                n = read(conv_pipe[0], buf, sizeof buf - 1);
            } while (n < 0 && errno == EINTR);

            atomic_store(&conv_returned, 1);
            if (n <= 0) {
                free(out);
                return PAM_CONV_ERR;
            }
            buf[n] = '\0';
            char *nl = strchr(buf, '\n');
            if (nl != NULL) {
                *nl = '\0';
            }
            out[i].resp = strdup(buf);
            out[i].resp_retcode = 0;
            if (out[i].resp == NULL) {
                free(out);
                return PAM_BUF_ERR;
            }
            break;
        }
        case PAM_PROMPT_ECHO_ON:
            out[i].resp = strdup("conv-thread-harness");
            out[i].resp_retcode = 0;
            if (out[i].resp == NULL) {
                free(out);
                return PAM_BUF_ERR;
            }
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            /* Informational only: return immediately. */
            break;
        default:
            free(out);
            return PAM_CONV_ERR;
        }
    }

    *resp = out;
    return PAM_SUCCESS;
}

static void *password_helper(void *arg) {
    (void)arg;

    struct timespec delay = {
        .tv_sec = PASSWORD_DELAY_MS / 1000,
        .tv_nsec = (long)(PASSWORD_DELAY_MS % 1000) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }

    const char *pw = PASSWORD "\n";
    ssize_t n = write(conv_pipe[1], pw, strlen(pw));
    (void)n;
    return NULL;
}

/* ----------------------------------------------------------- fake daemon --- */

typedef struct {
    int fd;
} conn_arg;

/*
 * Consume whatever the module sends and then hold the connection open: closing
 * it would surface as POLLHUP and turn the run into an IPC error, and sending
 * a response would let the daemon win the race the test is measuring.
 */
static void *conn_reader(void *arg) {
    int fd = ((conn_arg *)arg)->fd;
    free(arg);

    char buf[512];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) {
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    /* Deliberately never closed. */
    return NULL;
}

static void *daemon_accept_loop(void *arg) {
    int listen_fd = ((conn_arg *)arg)->fd;
    free(arg);

    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        atomic_fetch_add(&daemon_accepted, 1);

        conn_arg *ca = calloc(1, sizeof(*ca));
        if (ca == NULL) {
            fail("calloc for connection thread");
        }
        ca->fd = fd;

        pthread_t tid;
        if (pthread_create(&tid, NULL, conn_reader, ca) != 0) {
            fail("pthread_create for connection thread");
        }
        pthread_detach(tid);
    }

    return NULL;
}

static int start_fake_daemon(const char *sock_path) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fail("TAPAUTHD_SOCK path too long");
    }
    strcpy(addr.sun_path, sock_path);

    unlink(sock_path);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fail("socket() for fake daemon");
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fail("bind() for fake daemon");
    }
    if (listen(fd, 8) != 0) {
        fail("listen() for fake daemon");
    }

    conn_arg *ca = calloc(1, sizeof(*ca));
    if (ca == NULL) {
        fail("calloc for accept loop");
    }
    ca->fd = fd;

    pthread_t tid;
    if (pthread_create(&tid, NULL, daemon_accept_loop, ca) != 0) {
        fail("pthread_create for accept loop");
    }
    pthread_detach(tid);

    return fd;
}

/* ----------------------------------------------------------------- main --- */

int main(void) {
    const char *confdir = getenv("CONV_TEST_CONFDIR");
    const char *sock_path = getenv("TAPAUTHD_SOCK");
    const char *service = getenv("CONV_TEST_SERVICE");
    const char *expect = getenv("CONV_TEST_EXPECT");

    if (confdir == NULL || *confdir == '\0') {
        fail("CONV_TEST_CONFDIR is not set");
    }
    if (sock_path == NULL || *sock_path == '\0') {
        fail("TAPAUTHD_SOCK is not set");
    }
    if (service == NULL || *service == '\0') {
        fail("CONV_TEST_SERVICE is not set");
    }
    if (expect == NULL || *expect == '\0') {
        fail("CONV_TEST_EXPECT is not set (success|non-success)");
    }

    int expect_success;
    if (strcmp(expect, "success") == 0) {
        expect_success = 1;
    } else if (strcmp(expect, "non-success") == 0) {
        expect_success = 0;
    } else {
        fail("CONV_TEST_EXPECT must be 'success' or 'non-success'");
        return 1; /* unreachable: fail() exits */
    }

    char exe[4096];
    ssize_t exe_len = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (exe_len <= 0) {
        fail("readlink(/proc/self/exe)");
    }
    exe[exe_len] = '\0';

    const char *user = NULL;
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL && *pw->pw_name != '\0') {
        user = pw->pw_name;
    } else {
        user = "nobody";
    }

    printf("harness exe: %s\n", exe);
    printf("service    : %s\n", service);
    printf("expect     : %s\n", expect);
    printf("user       : %s\n", user);
    printf("confdir    : %s\n", confdir);
    printf("socket     : %s\n", sock_path);

    main_thread = pthread_self();

    if (pipe(conv_pipe) != 0) {
        fail("pipe() for the conversation");
    }

    start_fake_daemon(sock_path);

    pthread_t helper;
    if (pthread_create(&helper, NULL, password_helper, NULL) != 0) {
        fail("pthread_create for the password helper");
    }

    struct pam_conv conv = {test_conv, NULL};
    pam_handle_t *pamh = NULL;

    int ret = pam_start_confdir(service, user, &conv, confdir, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_start_confdir failed: %d (%s)\n", ret,
                pam_strerror(pamh, ret));
        fail("pam_start_confdir");
    }

    ret = pam_authenticate(pamh, 0);
    int auth_ret = ret;
    printf("pam_authenticate: %d (%s)\n", auth_ret, pam_strerror(pamh, auth_ret));

    /* Every assertion below is read after pam_authenticate returned: that is
     * the point of the harness. */
    int entered = atomic_load(&conv_entered);
    int returned = atomic_load(&conv_returned);
    int on_main = atomic_load(&conv_ran_on_main_thread);
    int accepted = atomic_load(&daemon_accepted);

    printf("conv_entered: %d\n", entered);
    printf("conv_returned: %d\n", returned);
    printf("conv_ran_on_main_thread: %d\n", on_main);
    printf("daemon_accepted: %d\n", accepted);

    int end_status = pam_end(pamh, auth_ret);

    /* The stack verdict is the point of the per-shape expectation: on a
     * `sufficient` line a password collected by the worker must still let the
     * stack succeed, and on a `required` line there must be no grant at all. */
    if (expect_success && auth_ret != PAM_SUCCESS) {
        fprintf(stderr,
                "expected pam_authenticate to grant (password fallback on a "
                "sufficient line), got %d\n",
                auth_ret);
        fail("pam_authenticate did not grant");
    }
    if (!expect_success && auth_ret == PAM_SUCCESS) {
        fprintf(stderr,
                "expected pam_authenticate to fail closed, got PAM_SUCCESS\n");
        fail("pam_authenticate granted a stack that must fail closed");
    }
    if (!entered) {
        fail("the conversation was never entered (threaded mode not selected?)");
    }
    if (!returned) {
        fail("the conversation had not returned when pam_authenticate returned "
             "(worker not joined before returning)");
    }
    if (on_main) {
        fail("the conversation ran on the pam_authenticate thread, not the worker");
    }
    if (accepted < 1) {
        fail("the fake daemon accepted no connection");
    }
    if (end_status != PAM_SUCCESS) {
        fail("pam_end failed");
    }

    printf("RESULT: PASS\n");
    fflush(stdout);
    return 0;
}
