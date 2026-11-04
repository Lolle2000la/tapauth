/*
 * conv_thread_harness.c — drives a real PAM stack through pam_tapauth.so to
 * prove the threaded-conversation path end to end.
 *
 * WHY THIS EXISTS
 *   `client-pam` picks between three GUI strategies at runtime:
 *
 *     - Threaded: a native worker thread calls `pam_get_authtok` (and therefore
 *       the host's conversation) while the calling thread waits for the phone.
 *     - PreCollected: the host already holds the password, so the module
 *       collects it on the calling thread and never contacts the daemon.
 *     - Sequential: the conversation is never touched; the module only waits
 *       for the daemon.
 *
 *   The choice is an allowlist keyed on the calling process (see
 *   `conversation_mode` in client-pam/src/pam_logic.rs).  None of it is
 *   reachable from a Rust unit test: it needs a real libpam stack, a real
 *   dynamically loaded module, and a process whose `/proc/self/exe` has the
 *   allowlisted name.
 *
 * HOW IT WORKS
 *   - A private PAM confdir (created by scripts/ci/test-pam-conv-thread.sh)
 *     holds the service file named by $CONV_TEST_SERVICE.  Its first `auth`
 *     entry is the freshly built `libclient_pam.so` by absolute path; what
 *     follows depends on the stack shape under test (see the script):
 *     `sufficient` + a token check, `required` + a token check, `required` +
 *     `optional pam_permit.so`, or a bare `sufficient` (the `grant` shape, whose
 *     grant comes from the phone rather than from a password the next module
 *     would have accepted).  $CONV_TEST_SERVICE is therefore not fixed here.
 *   - A fake daemon listens on $TAPAUTHD_SOCK and accepts the module's
 *     connection.  In every mode but `grant` it then only drains the request
 *     and never answers, never closes: the module must reach the password path
 *     on its own rather than from a daemon response.  In `grant` mode it waits
 *     until the conversation has been entered and then writes a granted
 *     `IpcEnvelope`, so the grant always lands while the conversation is still
 *     parked.  Its accept count is what makes "did the module contact the
 *     daemon at all?" observable.
 *   - The conversation blocks in `PAM_PROMPT_ECHO_OFF` until a helper thread
 *     writes a password after ~200 ms, and records on which thread it ran and
 *     whether it had returned by the time `pam_authenticate` came back.
 *     With $CONV_TEST_PRECOLLECT=1 it instead replays the stored password
 *     immediately, which is what swaylock/gtklock/i3lock do.  With
 *     $CONV_TEST_BLOCK=cancel it instead parks in `pthread_cond_wait` and is
 *     never signalled: the conversation can only end by being cancelled.
 *   - The script copies this binary to the allowlisted process name under test
 *     (`kscreenlocker_worker`, `swaylock`, `gdm-session-worker`) and runs the
 *     copy, so `/proc/self/exe`'s basename is on the allowlist.  A symlink
 *     would not work: the kernel resolves it.
 *
 * CONTRACT
 *   Environment:
 *     CONV_TEST_CONFDIR     private PAM confdir (pam_start_confdir)
 *     TAPAUTHD_SOCK         the fake daemon's socket
 *     CONV_TEST_SERVICE     service file name inside CONV_TEST_CONFDIR
 *     CONV_TEST_SERVICE_2   second service file in the same confdir, used by
 *                           `duplicate-cross-service` (defaults to
 *                           CONV_TEST_SERVICE)
 *     CONV_TEST_EXPECT      `success` if pam_authenticate must return
 *                           PAM_SUCCESS, `non-success` if the stack must fail
 *                           closed
 *     CONV_TEST_MODE        which assertion set applies:
 *                             threaded   — conversation entered, returned, off
 *                                          the calling thread, daemon >= 1
 *                             grant      — the daemon granted while the
 *                                          conversation was parked: entered,
 *                                          off the calling thread, NEVER
 *                                          returned, daemon >= 1
 *                             precollect — conversation entered, returned, ON
 *                                          the calling thread, daemon == 0
 *                             bypass     — conversation not entered, daemon == 0
 *                             every `duplicate*` mode runs several complete
 *                             transactions on separate handles in one process,
 *                             kept open until the end because `pam_end`
 *                             unloads the module (and with it the window):
 *                             duplicate  — user, user, (300 ms) user,
 *                                          (300 ms) user: all four must grant
 *                                          and the fake daemon must have
 *                                          accepted exactly TWO connections.
 *                                          The immediate second transaction is
 *                                          the duplicate a lock screen issues;
 *                                          it and the T0+300 ms call are
 *                                          answered from the window under any
 *                                          model, while the T0+600 ms call is
 *                                          outside the fixed 500 ms window and
 *                                          must start a real one again (a
 *                                          sliding window, which re-records on
 *                                          each hit, fails on the count).
 *                             duplicate-unavailable
 *                                        — user, user, but the fake daemon
 *                                          hangs up on the first connection, so
 *                                          both transactions conclude
 *                                          `PAM_AUTHINFO_UNAVAIL` with exactly
 *                                          ONE accepted connection: the
 *                                          concluded failure, not just a
 *                                          success, is what gets reused.  A
 *                                          second connection (which only a
 *                                          broken window produces) is granted,
 *                                          so the regression shows up in the
 *                                          verdict too.
 *                             duplicate-cross-user
 *                                        — user-a, user-b against a granting
 *                                          daemon: both must grant and the
 *                                          daemon must have accepted TWO
 *                                          connections.  A negative test: the
 *                                          window is keyed on the user, so a
 *                                          second user must always be asked for
 *                                          independently.
 *                             duplicate-cross-service
 *                                        — the same user against two different
 *                                          services (CONV_TEST_SERVICE and
 *                                          CONV_TEST_SERVICE_2), granting
 *                                          daemon: both must grant and the
 *                                          daemon must have accepted TWO
 *                                          connections.  The second negative
 *                                          test: the window is also keyed on
 *                                          the PAM service, so another stack
 *                                          must always ring the phone.
 *     CONV_TEST_PRECOLLECT  `1` makes the conversation replay the password
 *                           immediately instead of waiting for the helper
 *     CONV_TEST_BLOCK       `cancel` makes the `PAM_PROMPT_ECHO_OFF` branch park
 *                           in `pthread_cond_wait` (a POSIX cancellation point)
 *                           instead of reading the pipe.  Nothing ever signals
 *                           it, so the conversation returns only if the module
 *                           cancels the worker — which is exactly what the
 *                           `grant` assertion set measures.  Every `duplicate*`
 *                           mode implies its own park of the same kind, in
 *                           `sem_wait` (a cancellation point that holds no
 *                           mutex), because a condition-variable waiter that is
 *                           cancelled can leave its mutex held for the next
 *                           transaction.
 *
 *   Prints `RESULT: PASS` on success and exits 0.  Any other outcome prints a
 *   diagnostic, `RESULT: FAIL ...`, and exits non-zero.  Never install this.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <semaphore.h>
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
static int precollect;
/* `grant` mode: the fake daemon answers with a granted envelope, and the
 * conversation parks in a cancellation point until the module abandons it. */
static int grant_mode;
/* `duplicate-unavailable` mode: the fake daemon accepts and closes at once, so
 * the module concludes `PAM_AUTHINFO_UNAVAIL` through its IPC-error path in
 * milliseconds instead of waiting out a timeout. */
static int close_immediately;
static int block_cancel;
/* `duplicate` mode: the conversation parks in a `sem_wait` instead of the
 * condition variable.  `sem_wait` is a cancellation point and holds no mutex,
 * so a cancelled waiter cannot leave a lock behind for the next transaction. */
static int block_sem;
static sem_t conv_park_sem;
static pthread_mutex_t conv_block_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t conv_block_cv = PTHREAD_COND_INITIALIZER;
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

            if (precollect) {
                /* swaylock/gtklock/i3lock shape: the host already holds the
                 * password and the conversation is a synchronous replay.  No
                 * pipe read, so the answer is in place before the caller can
                 * do anything else. */
                atomic_store(&conv_returned, 1);
                out[i].resp = strdup(PASSWORD);
                out[i].resp_retcode = 0;
                if (out[i].resp == NULL) {
                    free(out);
                    return PAM_BUF_ERR;
                }
                break;
            }

            if (block_cancel) {
                /* THE POINT OF THE `grant` SHAPE: park in a *cancellation
                 * point* that nothing ever signals.  `pthread_cond_wait` is
                 * POSIX-required to be a cancellation point, so the module's
                 * deferred `pthread_cancel` is delivered here and the join
                 * returns — provided the module actually cancels.  A bare
                 * futex park (GLib's `g_cond_wait`) is what this shape must NOT
                 * model: there the wait restarts and a cancel never lands.
                 * `conv_returned` is deliberately left 0: this conversation
                 * never produces a password, so a grant cannot come from
                 * fallback. */
                pthread_mutex_lock(&conv_block_mu);
                for (;;) {
                    (void)pthread_cond_wait(&conv_block_cv, &conv_block_mu);
                }
            }

            if (block_sem) {
                /* THE POINT OF THE `duplicate` SHAPE: the same "never signalled,
                 * only a cancel can end it" park, but in `sem_wait`, which is a
                 * POSIX cancellation point that holds no mutex.  The
                 * condition-variable park above cannot be used here: POSIX
                 * reacquires the mutex before the cancellation cleanup handlers
                 * run, so the cancelled waiter of the first transaction can
                 * leave `conv_block_mu` held, and the second transaction's
                 * worker would block in a non-cancellable `pthread_mutex_lock`
                 * — hanging the run instead of reporting the accept count.
                 * `conv_returned` stays 0: no password is ever delivered. */
                while (sem_wait(&conv_park_sem) != 0 && errno == EINTR) {
                }
            }

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
    /* 1-based accept order: the duplicate modes need "the first connection
     * hangs up, any later one grants". */
    int index;
} conn_arg;

/*
 * A granted `IpcEnvelope`, in the length-prefixed framing every IPC message
 * uses (4-byte big-endian length, then the protobuf body):
 *
 *   00 00 00 02   body length = 2
 *   62            field 12 (`pam_response`, wire type 2) => (12 << 3) | 2
 *   00            zero-length body: `PamAuthenticateResponse {}`
 *
 * An empty response decodes as `outcome = SUCCESS` (0, the first declared
 * `PamOutcome`, so proto3 omits the default) with an empty `challenge` and
 * `detail`.  client-pam accepts exactly that: `map_pam_outcome` switches on
 * `outcome` only, and nothing correlates `challenge` against the request (the
 * proto comment calls it informational; `response_outcome` reads only the raw
 * `outcome` field).  So there is nothing to echo back from the request bytes.
 */
static const unsigned char grant_frame[] = {
    0x00, 0x00, 0x00, 0x02, /* big-endian body length */
    0x62, 0x00,             /* IpcEnvelope.pam_response {} */
};

#define GRANT_WAIT_TOTAL_MS 2000
#define GRANT_WAIT_STEP_MS 10

/*
 * Block until the host's conversation has been entered, so the grant can never
 * arrive before the worker parks (which would make the shape measure the wrong
 * race).  Bounded: a conversation that never starts is a hard failure, not a
 * wait.
 */
static void wait_for_conversation(void) {
    int waited;
    for (waited = 0; waited < GRANT_WAIT_TOTAL_MS; waited += GRANT_WAIT_STEP_MS) {
        if (atomic_load(&conv_entered)) {
            return;
        }
        struct timespec step = {
            .tv_sec = 0,
            .tv_nsec = (long)GRANT_WAIT_STEP_MS * 1000000L,
        };
        nanosleep(&step, NULL);
    }
    if (!atomic_load(&conv_entered)) {
        fail("the conversation was never entered; cannot order the grant after it");
    }
}

/*
 * Consume whatever the module sends and then hold the connection open: closing
 * it would surface as POLLHUP and turn the run into an IPC error, and sending
 * a response would let the daemon win the race the test is measuring — except
 * in `grant` mode, where winning that race *after* the conversation has parked
 * is precisely the behaviour under test.
 */
static void *conn_reader(void *arg) {
    int fd = ((conn_arg *)arg)->fd;
    int index = ((conn_arg *)arg)->index;
    free(arg);

    if (close_immediately && index == 1) {
        /* `duplicate-unavailable`: the first connection is accepted and closed
         * with no response, so the module sees POLLHUP and concludes
         * `PAM_AUTHINFO_UNAVAIL` at once (`test_gui_loop_daemon_hangup` covers
         * that path).  Any *later* connection is granted instead: with the
         * reuse window neutered the duplicate transaction really does reach the
         * daemon, and then it must be caught on the verdict too (the second
         * call would succeed instead of repeating the failure), not only on the
         * accept count. */
        close(fd);
        return NULL;
    }

    if (grant_mode || close_immediately) {
        wait_for_conversation();

        size_t off = 0;
        while (off < sizeof grant_frame) {
            ssize_t n = write(fd, grant_frame + off, sizeof grant_frame - off);
            if (n > 0) {
                off += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            fail("write() of the granted response to the module failed");
        }
    }

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
        int index = atomic_fetch_add(&daemon_accepted, 1) + 1;

        conn_arg *ca = calloc(1, sizeof(*ca));
        if (ca == NULL) {
            fail("calloc for connection thread");
        }
        ca->fd = fd;
        ca->index = index;

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

/* ------------------------------------------------------------- duplicate --- */

typedef struct {
    /* PAM service (and therefore the stack) this transaction runs against. */
    const char *service;
    const char *user;
    /* Milliseconds to sleep before starting this transaction. */
    unsigned sleep_ms;
    int expected;
} dup_step;

/*
 * The shape of a lock screen that re-enters `pam_authenticate` right after the
 * previous transaction concluded (kscreenlocker >= 6.8 queues the duplicate
 * while the first one is still running): several complete PAM transactions on
 * separate handles in one process.  Only the transactions the reuse window does
 * not cover may reach the daemon, so the fake daemon's accept count is the
 * discriminator for every variant:
 *
 *   duplicate              user, user, (300 ms) user, (300 ms) user
 *                          daemon grants twice.  The immediate duplicate and
 *                          the T0+300 ms call are hits under any model; the
 *                          T0+600 ms call is outside the fixed 500 ms window
 *                          and must start a real transaction again, while a
 *                          sliding window (which re-records on each hit) would
 *                          still answer it and leave the count at 1;
 *   duplicate-unavailable  user, user                   daemon hangs up once
 *                          both transactions conclude `PAM_AUTHINFO_UNAVAIL`
 *                          from a single connection, so a concluded failure is
 *                          reused too;
 *   duplicate-cross-user   user-a, user-b               daemon grants twice
 *                          a negative test: the window is per user, so a second
 *                          user must be asked for independently.
 *
 * The conversation is parked in a cancellation point nothing signals (see
 * `block_sem`), so no password is ever delivered and a `PAM_SUCCESS` can only
 * come from the daemon.
 */
static void run_duplicate_sequence(const char *confdir, const dup_step *steps,
                                   int count, int expected_accepts,
                                   int require_entered) {
    enum { DUP_MAX_STEPS = 4 };
    struct pam_conv conv = {test_conv, NULL};
    pam_handle_t *handles[DUP_MAX_STEPS] = {NULL, NULL, NULL, NULL};
    int verdicts[DUP_MAX_STEPS] = {PAM_SERVICE_ERR, PAM_SERVICE_ERR,
                                   PAM_SERVICE_ERR, PAM_SERVICE_ERR};

    if (count < 1 || count > DUP_MAX_STEPS) {
        fail("the duplicate sequence has an unsupported number of steps");
    }

    for (int i = 0; i < count; i++) {
        if (steps[i].sleep_ms > 0) {
            struct timespec delay = {
                .tv_sec = (time_t)(steps[i].sleep_ms / 1000),
                .tv_nsec = (long)(steps[i].sleep_ms % 1000) * 1000000L,
            };
            while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
            }
        }

        int ret = pam_start_confdir(steps[i].service, steps[i].user, &conv,
                                    confdir, &handles[i]);
        if (ret != PAM_SUCCESS) {
            fprintf(stderr,
                    "pam_start_confdir (transaction %d, service %s) failed: %d\n",
                    i + 1, steps[i].service, ret);
            fail("pam_start_confdir (duplicate)");
        }

        ret = pam_authenticate(handles[i], 0);
        verdicts[i] = ret;
        printf("pam_authenticate #%d (user %s, service %s): %d (%s)\n", i + 1,
               steps[i].user, steps[i].service, ret,
               pam_strerror(handles[i], ret));
    }

    /* Every handle is ended only now.  libpam `dlclose()`s the module image in
     * `pam_end`, so an end sitting between two transactions would unmap the
     * module and the next `pam_authenticate` would map a *fresh* copy with an
     * empty reuse window (measured: the module disappears from
     * /proc/self/maps at pam_end).  The shape would then measure glibc's
     * unload, not the fix.  Keeping the transactions open is also what the real
     * host does: kscreenlocker re-enters `pam_authenticate` inside one open
     * transaction. */
    for (int i = count - 1; i >= 0; i--) {
        int end_status = pam_end(handles[i], verdicts[i]);
        if (end_status != PAM_SUCCESS) {
            fail("pam_end failed (duplicate)");
        }
    }

    int entered = atomic_load(&conv_entered);
    int accepted = atomic_load(&daemon_accepted);
    printf("conv_entered: %d\n", entered);
    printf("daemon_accepted: %d\n", accepted);

    for (int i = 0; i < count; i++) {
        if (verdicts[i] != steps[i].expected) {
            fprintf(stderr,
                    "transaction %d (user %s, service %s) returned %d, "
                    "expected %d: the shape cannot judge the reuse window on "
                    "the wrong verdict\n",
                    i + 1, steps[i].user, steps[i].service, verdicts[i],
                    steps[i].expected);
            fail("pam_authenticate returned the wrong code");
        }
    }
    if (require_entered && !entered) {
        fail("the conversation was never entered (threaded mode not selected?)");
    }
    if (accepted != expected_accepts) {
        fprintf(stderr,
                "the fake daemon accepted %d connection(s), expected exactly "
                "%d: every transaction the reuse window does not cover must "
                "reach the daemon, and every one it covers must not\n",
                accepted, expected_accepts);
        fail("the duplicate transaction reached the daemon the wrong number of "
             "times");
    }
}

/* ----------------------------------------------------------------- main --- */

int main(void) {
    const char *confdir = getenv("CONV_TEST_CONFDIR");
    const char *sock_path = getenv("TAPAUTHD_SOCK");
    const char *service = getenv("CONV_TEST_SERVICE");
    const char *expect = getenv("CONV_TEST_EXPECT");
    const char *assert_mode = getenv("CONV_TEST_MODE");

    if (confdir == NULL || *confdir == '\0') {
        fail("CONV_TEST_CONFDIR is not set");
    }
    if (sock_path == NULL || *sock_path == '\0') {
        fail("TAPAUTHD_SOCK is not set");
    }
    if (service == NULL || *service == '\0') {
        fail("CONV_TEST_SERVICE is not set");
    }
    /* Second service file, for the cross-service shape.  Optional elsewhere:
     * it then simply repeats the primary service. */
    const char *service2 = getenv("CONV_TEST_SERVICE_2");
    if (service2 == NULL || *service2 == '\0') {
        service2 = service;
    }
    if (expect == NULL || *expect == '\0') {
        fail("CONV_TEST_EXPECT is not set (success|non-success)");
    }
    if (assert_mode == NULL || *assert_mode == '\0') {
        assert_mode = "threaded";
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

    int mode_threaded = strcmp(assert_mode, "threaded") == 0;
    int mode_grant = strcmp(assert_mode, "grant") == 0;
    int mode_precollect = strcmp(assert_mode, "precollect") == 0;
    int mode_bypass = strcmp(assert_mode, "bypass") == 0;
    int mode_duplicate = strcmp(assert_mode, "duplicate") == 0;
    int mode_dup_unavail = strcmp(assert_mode, "duplicate-unavailable") == 0;
    int mode_dup_cross_user = strcmp(assert_mode, "duplicate-cross-user") == 0;
    int mode_dup_cross_service =
        strcmp(assert_mode, "duplicate-cross-service") == 0;
    int duplicate_mode = mode_duplicate || mode_dup_unavail ||
                         mode_dup_cross_user || mode_dup_cross_service;
    if (!mode_threaded && !mode_grant && !mode_precollect && !mode_bypass &&
        !duplicate_mode) {
        fail("CONV_TEST_MODE must be 'threaded', 'grant', 'precollect', 'bypass', "
             "'duplicate', 'duplicate-unavailable', 'duplicate-cross-user' or "
             "'duplicate-cross-service'");
        return 1; /* unreachable: fail() exits */
    }

    const char *precollect_env = getenv("CONV_TEST_PRECOLLECT");
    precollect = (precollect_env != NULL && strcmp(precollect_env, "1") == 0) ||
                 mode_precollect;

    /* The granting variants also need the daemon to grant a second connection:
     * with the reuse window neutered the duplicate transaction really does
     * reach the daemon, and only then is the accepted count what makes the
     * regression visible.  `duplicate-unavailable` needs the opposite on the
     * first connection -- a hang-up -- and gets it from `close_immediately`
     * below; any later connection there is granted, so the regression is caught
     * on the verdict as well as the count. */
    grant_mode = mode_grant || mode_duplicate || mode_dup_cross_user ||
                 mode_dup_cross_service;
    close_immediately = mode_dup_unavail;

    const char *block_env = getenv("CONV_TEST_BLOCK");
    if (block_env != NULL && *block_env != '\0') {
        if (strcmp(block_env, "cancel") != 0) {
            fail("CONV_TEST_BLOCK must be 'cancel' (or unset)");
            return 1; /* unreachable: fail() exits */
        }
        block_cancel = 1;
    }
    if (block_cancel && precollect) {
        fail("CONV_TEST_BLOCK=cancel contradicts CONV_TEST_PRECOLLECT=1");
        return 1; /* unreachable: fail() exits */
    }
    /* Every duplicate mode parks the conversation in its own cancellation
     * point (a semaphore), so they must not also take the condition-variable
     * park and they need no CONV_TEST_BLOCK.  Either way no password is ever
     * delivered, so a `PAM_SUCCESS` can only come from the daemon. */
    block_sem = duplicate_mode;
    if (block_sem && block_cancel) {
        fail("the duplicate modes must not be combined with CONV_TEST_BLOCK=cancel");
        return 1; /* unreachable: fail() exits */
    }
    if (block_sem && sem_init(&conv_park_sem, 0, 0) != 0) {
        fail("sem_init for the duplicate park");
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
    printf("mode       : %s\n", assert_mode);
    printf("precollect : %d\n", precollect);
    printf("block      : %s\n",
           block_cancel ? "cancel"
                        : (block_sem ? "sem (duplicate)" : "none"));
    printf("user       : %s\n", user);
    printf("confdir    : %s\n", confdir);
    printf("socket     : %s\n", sock_path);

    main_thread = pthread_self();

    if (pipe(conv_pipe) != 0) {
        fail("pipe() for the conversation");
    }

    start_fake_daemon(sock_path);

    /* Only the blocking conversation reads the pipe; the pre-collected replay
     * answers immediately and must not depend on a helper thread. */
    if (!precollect) {
        pthread_t helper;
        if (pthread_create(&helper, NULL, password_helper, NULL) != 0) {
            fail("pthread_create for the password helper");
        }
    }

    struct pam_conv conv = {test_conv, NULL};
    pam_handle_t *pamh = NULL;

    /* The duplicate shapes own their own handles (one per transaction), so they
     * divert before the single-handle flow below.  The two cross-* modes are
     * negative tests: they must fail if the window ever drops the username (or
     * the PAM service) from its key. */
    if (duplicate_mode) {
        const char *other_user =
            strcmp(user, "nobody") == 0 ? "daemon" : "nobody";
        const char *other_service = service2;
        const dup_step success_steps[] = {
            /* T0: concludes, and is the first daemon contact. */
            {service, user, 0, PAM_SUCCESS},
            /* The modelled 0.37 ms duplicate: a hit under every model. */
            {service, user, 0, PAM_SUCCESS},
            /* T0 + ~300 ms: still a hit under *both* a fixed window and a
             * sliding one that re-records on each hit, so this step alone
             * proves nothing about which the module implements. */
            {service, user, 300, PAM_SUCCESS},
            /* T0 + ~600 ms: 600 ms after the *original* verdict, so a fixed
             * window misses and a new transaction must start (daemon contact
             * 2).  A sliding window would have re-recorded at T0 + ~300 ms and
             * would still hit here, leaving the count at 1.  `nanosleep` never
             * sleeps *less* than requested, so overshoot can only push this
             * further outside the window, never back inside it. */
            {service, user, 300, PAM_SUCCESS},
        };
        const dup_step unavailable_steps[] = {
            {service, user, 0, PAM_AUTHINFO_UNAVAIL},
            {service, user, 0, PAM_AUTHINFO_UNAVAIL},
        };
        const dup_step cross_user_steps[] = {
            {service, user, 0, PAM_SUCCESS},
            {service, other_user, 0, PAM_SUCCESS},
        };
        const dup_step cross_service_steps[] = {
            {service, user, 0, PAM_SUCCESS},
            {other_service, user, 0, PAM_SUCCESS},
        };

        printf("cross-user other user: %s\n", other_user);
        printf("cross-service other service: %s\n", other_service);
        if (mode_duplicate) {
            run_duplicate_sequence(confdir, success_steps, 4,
                                   2 /* T0 and T0+600 ms */, 1);
        } else if (mode_dup_unavail) {
            run_duplicate_sequence(confdir, unavailable_steps, 2, 1, 0);
        } else if (mode_dup_cross_user) {
            run_duplicate_sequence(confdir, cross_user_steps, 2,
                                   2 /* one per user */, 1);
        } else {
            run_duplicate_sequence(confdir, cross_service_steps, 2,
                                   2 /* one per service */, 1);
        }
        printf("RESULT: PASS\n");
        fflush(stdout);
        return 0;
    }

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

    /* The per-mode assertion set.  Each one pins a *different* strategy, so a
     * regression that silently switches strategy fails on the count/thread
     * assertions even when the stack verdict still matches. */
    if (mode_threaded) {
        if (!entered) {
            fail("the conversation was never entered (threaded mode not selected?)");
        }
        if (!returned) {
            fail("the conversation had not returned when pam_authenticate "
                 "returned (worker not joined before returning)");
        }
        if (on_main) {
            fail("the conversation ran on the pam_authenticate thread, not the worker");
        }
        if (accepted < 1) {
            fail("the fake daemon accepted no connection");
        }
    } else if (mode_grant) {
        /* The phone granted while the host's conversation was parked in a
         * cancellation point.  All four facts are needed to rule out every
         * other explanation for PAM_SUCCESS:
         *   - nothing was collected, so this is not password fallback;
         *   - the daemon was contacted, so the grant came from the wire;
         *   - the worker ran off the calling thread, so the threaded strategy
         *     is what was exercised. */
        if (!entered) {
            fail("the conversation was never entered (threaded mode not selected?)");
        }
        if (on_main) {
            fail("the conversation ran on the pam_authenticate thread, not the worker");
        }
        if (returned) {
            fail("the conversation returned a password: a grant here cannot be "
                 "distinguished from password fallback (worker not cancelled?)");
        }
        if (accepted < 1) {
            fail("the fake daemon accepted no connection");
        }
    } else if (mode_precollect) {
        if (!entered) {
            fail("the conversation was never entered (pre-collected replay not selected?)");
        }
        if (!returned) {
            fail("the conversation had not returned when pam_authenticate returned");
        }
        if (!on_main) {
            fail("the pre-collected replay ran off the pam_authenticate thread; a "
                 "pre-collected host must be served synchronously on it");
        }
        if (accepted != 0) {
            fail("a pre-collected host contacted the daemon: the password was "
                 "already typed, so the phone must not be consulted");
        }
    } else {
        if (entered) {
            fail("the conversation was entered: a bypassed service must not "
                 "touch the conversation");
        }
        if (accepted != 0) {
            fail("a bypassed service contacted the daemon");
        }
    }
    if (end_status != PAM_SUCCESS) {
        fail("pam_end failed");
    }

    printf("RESULT: PASS\n");
    fflush(stdout);
    return 0;
}
