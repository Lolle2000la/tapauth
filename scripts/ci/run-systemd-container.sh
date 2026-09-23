#!/bin/bash
# Boots a real-systemd (PID 1) container for a distro and runs the TapAuth E2E
# suite against the installed package in systemd mode.
#
# Why a dedicated orchestrator: a container whose PID 1 is systemd cannot be
# combined with `--pid=host`, and it must be started detached, waited for, and
# driven through `docker exec` (the unit lifecycle is only meaningful once
# systemd is up). The plain `docker run ... run-container-e2e.sh` pattern used
# for the old dev-sandbox containers does not work for that.
#
# The container runs its OWN systemd, D-Bus, polkitd and bluetoothd (the host
# D-Bus socket is deliberately NOT bind-mounted): that is what makes Phase 7
# exercise the package's installed PolKit action, and what lets the container's
# bluetoothd own the virtual HCI adapter created by the host Bumble bridge.
set -euo pipefail

DISTRO="${1:-}"
IMAGE="${2:-}"
PACKAGE_DIR="${3:-}"
shift 3 2>/dev/null || true
# Optional command to start PID 1 (defaults to systemd). Fedora's stock image
# ships no init at all, so it is bootstrapped by installing systemd+dbus and
# exec'ing it; a `docker run` is used instead of a `docker build` because dnf is
# reliable in `docker run` on the GitHub runners but failed under buildkit.
INIT_CMD=("$@")
if [ "${#INIT_CMD[@]}" -eq 0 ]; then
    INIT_CMD=(/sbin/init)
fi

if [[ -z "$DISTRO" || -z "$IMAGE" || -z "$PACKAGE_DIR" ]]; then
    echo "Usage: $0 <distro> <image> <package-dir-in-container> [init-command...]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONTAINER_NAME="tapauth-e2e-${DISTRO}"

# Pass the emulator console auth token so `adb emu ...` works inside the
# container (the emulator itself runs on the host; --net=host makes it
# reachable).
AUTH_TOKEN_MOUNT=()
if [ -f "$HOME/.emulator_auth_token" ]; then
    AUTH_TOKEN_MOUNT=(-v "$HOME/.emulator_auth_token:/root/.emulator_auth_token:ro")
elif [ -f "/root/.emulator_auth_token" ]; then
    AUTH_TOKEN_MOUNT=(-v "/root/.emulator_auth_token:/root/.emulator_auth_token:ro")
fi

cleanup() {
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=================================================="
echo " Starting TapAuth systemd E2E on Distro: $DISTRO"
echo " Image: $IMAGE"
echo " Package directory: $PACKAGE_DIR"
echo "=================================================="

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# A rootful systemd container on a cgroup-v2 host needs:
#   --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw
# `--tmpfs /run` gives systemd its runtime dir. /dev and /tmp are shared with
# the host (vhci + adb, and the E2E logs the CI job uploads). Do NOT add
# `--tmpfs /tmp`: the host /tmp is already bind-mounted, and a second mount
# point on the same path is a docker error.
docker run -d --name "$CONTAINER_NAME" \
    --privileged \
    --cgroupns=host \
    --tmpfs /run \
    --net=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v /dev:/dev \
    -v /tmp:/tmp \
    -v "$WORKSPACE_DIR":/workspace \
    ${AUTH_TOKEN_MOUNT[@]+"${AUTH_TOKEN_MOUNT[@]}"} \
    --stop-signal=SIGRTMIN+3 \
    "$IMAGE" "${INIT_CMD[@]}" >/dev/null

echo "==> Waiting for systemd to finish booting..."
BOOTED=false
STATE=""
for i in $(seq 1 120); do
    STATE="$(docker exec "$CONTAINER_NAME" systemctl is-system-running 2>/dev/null || true)"
    case "$STATE" in
        # `degraded` is the healthy result for a bare container (a handful of
        # units like getty/binfmt/sys-kernel-*.mount can never start there);
        # only `initializing`/`unknown` mean "not up yet".
        running|degraded)
            echo "    systemd state: $STATE"
            BOOTED=true
            break
            ;;
        # `maintenance` means PID 1 dropped into rescue/emergency mode (e.g. a
        # failed unit with OnFailure=emergency). It will not become healthy, so
        # fail now with diagnostics instead of letting the suite run against a
        # broken system.
        maintenance)
            echo "❌ ERROR: $DISTRO container booted into maintenance (rescue/emergency) mode."
            echo "--- systemctl status ---"
            docker exec "$CONTAINER_NAME" systemctl status --no-pager 2>/dev/null || true
            echo "--- systemctl --failed ---"
            docker exec "$CONTAINER_NAME" systemctl --no-pager --failed 2>/dev/null || true
            echo "--- container log tail ---"
            docker logs "$CONTAINER_NAME" 2>&1 | tail -80 || true
            exit 1
            ;;
    esac
    if [ $((i % 15)) -eq 0 ]; then
        echo "    ... still waiting (state: ${STATE:-unknown}, ${i}s)"
    fi
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
        echo "❌ ERROR: $DISTRO container exited during boot. Last log lines:"
        docker logs "$CONTAINER_NAME" 2>&1 | tail -50 || true
        exit 1
    fi
    sleep 1
done
if [ "$BOOTED" != true ]; then
    echo "❌ ERROR: $DISTRO container did not reach a running systemd state (last state: ${STATE:-unknown})."
    echo "--- systemctl status ---"
    docker exec "$CONTAINER_NAME" systemctl status --no-pager 2>/dev/null || true
    echo "--- systemctl --failed ---"
    docker exec "$CONTAINER_NAME" systemctl --no-pager --failed 2>/dev/null || true
    echo "--- container log tail ---"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -80 || true
    exit 1
fi
docker exec "$CONTAINER_NAME" systemctl --no-pager --failed 2>/dev/null || true

# The suite itself (install deps + package, verify posture, run test-e2e.sh).
docker exec "$CONTAINER_NAME" \
    /workspace/scripts/ci/run-container-e2e.sh "$DISTRO" "$PACKAGE_DIR"

echo "=================================================="
echo "🎉 SYSTEMD E2E PASSED ON DISTRO: $DISTRO"
echo "=================================================="
