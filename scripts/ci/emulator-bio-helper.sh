#!/bin/bash
# Helper script to manage automated biometric verification on the Android Emulator
set -e

# Ensure adb is in PATH
if ! command -v adb &> /dev/null; then
    for p in "/usr/local/lib/android/sdk/platform-tools" "$ANDROID_HOME/platform-tools" "$ANDROID_SDK_ROOT/platform-tools" "$HOME/Android/Sdk/platform-tools"; do
        if [ -x "$p/adb" ]; then
            export PATH="$PATH:$p"
            break
        fi
    done
fi

ACTION="${1:-setup}"

case "$ACTION" in
    setup)
        # Optional arg 2: package under test. When real fingerprint enrollment is
        # unavailable, the fallback (the e2e app build's auto-approve) only works
        # if that package is installed, so the caller passes it for verification.
        PKG="${2:-}"
        echo "==> Setting up biometric handling in Android Emulator..."
        # Set lock screen PIN
        adb shell locksettings set-pin 1234 2>/dev/null || true
        # Configure Android Virtual Biometrics HAL (Android 14/15/16)
        adb shell settings put secure biometric_virtual_enabled 1 2>/dev/null || true
        adb shell setprop persist.vendor.fingerprint.virtual.type rear 2>/dev/null || true
        adb shell setprop persist.vendor.fingerprint.virtual.enrollments 1 2>/dev/null || true
        adb shell setprop vendor.fingerprint.virtual.enrollments 1 2>/dev/null || true

        # Detect whether this image still implements `cmd fingerprint enroll`.
        # Newer images (API 36+) removed the subcommand; it then prints
        # "Unrecognized command", which the previous `2>/dev/null || true`
        # guards swallowed, silently no-op'ing enrollment while this script
        # still reported success. Probe the shell command's own help text.
        if adb shell cmd fingerprint help 2>&1 | grep -qw enroll; then
            echo "    'cmd fingerprint enroll' is supported; performing real enrollment."
            adb shell cmd fingerprint reset >/dev/null 2>&1 || true
            adb shell cmd fingerprint sync >/dev/null 2>&1 || true
            # Enroll fingerprint 1 (for both virtual HAL and traditional emulator HAL)
            adb shell cmd fingerprint enroll 0 >/dev/null 2>&1 &
            ENROLL_PID=$!
            sleep 0.5
            for _ in {1..10}; do
                adb emu finger touch 1 >/dev/null 2>&1 || true
                sleep 0.2
            done
            wait $ENROLL_PID 2>/dev/null || true
            # Verify the enrollment actually landed (entry format: "1: name (id=1)").
            if adb shell cmd fingerprint list 2>/dev/null | grep -qE '\(id=[0-9]+\)|^[[:space:]]*[0-9]+:'; then
                echo "✅ Test biometric profile enrolled (Finger 1 / Virtual Biometrics HAL)."
            else
                echo "⚠️  WARNING: could not confirm fingerprint enrollment via 'cmd fingerprint list'."
                echo "    If nothing is enrolled, the e2e build's auto-approve fallback still covers the suite."
            fi
        else
            echo "⚠️  'cmd fingerprint enroll' is NOT supported on this image (removed in newer Android APIs)."
            echo "    Falling back to the e2e app build's auto-approve behavior: with no biometrics enrolled,"
            echo "    pending requests are granted ~1s after the prompt (AuthRequestManager.autoApproveInE2e)."
            # The fallback only works with the e2e build installed. Fail loudly
            # here instead of letting every auth phase hang until its timeout.
            if [ -n "$PKG" ] && [ -z "$(adb shell pm path "$PKG" 2>/dev/null)" ]; then
                echo "❌ ERROR: e2e package '$PKG' is not installed; the auto-approve fallback cannot work."
                exit 1
            fi
            echo "✅ Auto-approve fallback active (no biometrics enrolled on this image)."
        fi
        ;;

    deny)
        # Arg 2: the package under test. The dev-deny receiver only exists in the
        # e2e build variant (BuildConfig.E2E_TESTING + exported receiver), so the
        # caller tells us which package to target instead of guessing.
        PKG="${2:-dev.rourunisen.tapauth.e2e}"
        echo "    Triggering biometric denial for $PKG (finger 2 / cancel / dev-deny broadcast)..."
        # Finger 2 is not enrolled, causing biometric failure
        adb emu finger touch 2 >/dev/null 2>&1 || true
        # Explicit denial broadcast (no-op unless the e2e variant is installed)
        adb shell am broadcast -p "$PKG" -a dev.rourunisen.tapauth.ACTION_DEV_DENY >/dev/null 2>&1 || true
        # Also simulate negative / cancel button if prompt is active
        adb shell input keyevent KEYCODE_BACK >/dev/null 2>&1 || true
        ;;

    start-auto-grant)
        echo "==> Starting background biometric auto-grant listener..."
        LOGCAT_LOG="/tmp/bio-auto-grant.log"

        cat << 'EOF' > /tmp/bio_auto_grant.py
import subprocess, signal, sys

print("Biometric auto-grant daemon started...")
sys.stdout.flush()

proc = subprocess.Popen(['adb', 'logcat', '-v', 'brief', '*:V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def shutdown(*_):
    # The `adb logcat` child is in its own process, so killing this script alone
    # would leave it running (and holding the adb connection) on the runner.
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    sys.exit(0)


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

# Deliberately broad keyword set: a stray `finger touch 1` while no prompt is
# showing is a no-op, whereas a missed prompt hangs the authentication phase
# until the daemon timeout.
try:
    for line in iter(proc.stdout.readline, ''):
        if any(k in line for k in ['Showing biometric prompt', 'BiometricPrompt', 'BiometricPromptActivity', 'FingerprintService', 'fingerprint', 'Biometric availability']):
            subprocess.run(['adb', 'emu', 'finger', 'touch', '1'], capture_output=True)
            print(f"Auto-granted fingerprint touch for prompt: {line.strip()}")
            sys.stdout.flush()
finally:
    proc.terminate()
EOF

        python3 /tmp/bio_auto_grant.py > "$LOGCAT_LOG" 2>&1 &
        BIO_PID=$!
        echo "$BIO_PID" > /tmp/bio-auto-grant.pid
        echo "    Auto-grant daemon running with PID $BIO_PID (logs: $LOGCAT_LOG)"
        ;;

    stop-auto-grant)
        if [ -f /tmp/bio-auto-grant.pid ]; then
            PID=$(cat /tmp/bio-auto-grant.pid)
            kill "$PID" 2>/dev/null || true
            rm -f /tmp/bio-auto-grant.pid
            echo "    Stopped auto-grant daemon."
        fi
        ;;

    *)
        echo "Usage: $0 {setup [package]|deny [package]|start-auto-grant|stop-auto-grant}"
        exit 1
        ;;
esac
