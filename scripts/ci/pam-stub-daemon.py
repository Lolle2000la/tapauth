#!/usr/bin/env python3
"""Tiny stand-in for ``tapauthd`` that accepts PAM connections and never answers.

Why this exists
---------------
The PAM module's blocking verdicts (wait for the phone, GUI timeout, daemon
error) need a daemon that is *reachable* but *silent*, so the outcome is decided
by the module's own deadline instead of by anything the daemon says. A real
``tapauthd`` would answer (or multicast), and a *missing* socket exercises a
different path entirely (fast "cannot connect" failure), so neither can be used
for the TTY-less wait tests in ``scripts/ci/test-pam-host-cases.sh``.

Scope
-----
* ``pam-stub-daemon.py <socket-path>`` creates the Unix socket, accepts
  connections in a loop, reads (and discards) whatever arrives, never replies
  and keeps the connection open.
* Exits cleanly on SIGTERM/SIGINT (within ~0.2 s) and unlinks the socket it
  created on the way out.
* The socket path must not exist yet: an ``EADDRINUSE`` bind is reported and the
  process exits non-zero. It never unlinks or replaces a pre-existing file, so a
  caller that binds the production path (the host-case harness) owns the path
  and refuses to start while something else is there.
* Python 3 stdlib only.
"""

import errno
import os
import signal
import socket
import sys

CHUNK = 4096
POLL = 0.2


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: pam-stub-daemon.py <socket-path>\n")
        return 2

    path = argv[1]
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(path)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            sys.stderr.write(
                f"pam-stub-daemon: {path} already exists; refusing to replace it "
                "(remove it yourself if it is stale)\n"
            )
        else:
            sys.stderr.write(f"pam-stub-daemon: cannot bind {path}: {exc}\n")
        listener.close()
        return 1
    listener.listen(8)
    # Short timeouts keep the loop responsive to SIGTERM even while a client
    # connection is open and silent (a blocking recv() would otherwise resume
    # after the signal handler returns).
    listener.settimeout(POLL)

    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    print(f"pam-stub-daemon: listening on {path}", flush=True)

    conns = []
    try:
        while not stopping:
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if stopping:
                    break
                continue
            conn.settimeout(POLL)
            conns.append(conn)
            # Read and discard; the client sees an open, silent peer.
            while not stopping:
                try:
                    data = conn.recv(CHUNK)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
    finally:
        for conn in conns:
            try:
                conn.close()
            except OSError:
                pass
        try:
            listener.close()
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass

    print("pam-stub-daemon: stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
