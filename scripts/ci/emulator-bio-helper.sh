#!/bin/bash
# Helper script to manage automated biometric verification on the Android Emulator
set -e

ACTION="${1:-setup}"

case "$ACTION" in
    setup)
        echo "==> Enrolling test biometric credentials in Android Emulator..."
        # Set lock screen PIN
        adb shell locksettings set-pin 1234 2>/dev/null || true
        # Touch enrolled finger 1
        adb emu finger touch 1 2>/dev/null || true
        echo "✅ Test biometric profile enrolled (Finger 1)."
        ;;

    grant)
        echo "    Triggering biometric grant (finger touch 1)..."
        adb emu finger touch 1
        ;;

    deny)
        echo "    Triggering biometric denial (finger touch 2 / cancel)..."
        # Finger 2 is not enrolled, causing biometric failure
        adb emu finger touch 2 2>/dev/null || true
        sleep 0.5
        # Also simulate negative / cancel button if prompt is active
        adb shell input keyevent KEYCODE_BACK 2>/dev/null || true
        ;;

    start-auto-grant)
        echo "==> Starting background biometric auto-grant listener..."
        LOGCAT_LOG="/tmp/bio-auto-grant.log"
        python3 - << 'PY' > "$LOGCAT_LOG" 2>&1 &
import subprocess, time, sys

print("Biometric auto-grant daemon started...")
sys.stdout.flush()

# Monitor logcat for BiometricPrompt or AuthenticationRequest
proc = subprocess.Popen(['adb', 'logcat', '-v', 'brief', 'AuthenticationService:D', 'BleGattService:D', 'BiometricPrompt:D', '*:S'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

try:
    for line in iter(proc.stdout.readline, ''):
        # When request or prompt detected, trigger finger touch after a brief delay
        if 'Handling AuthenticationRequest' in line or 'Showing biometric prompt' in line or 'BiometricPrompt' in line:
            time.sleep(0.3)
            subprocess.run(['adb', 'emu', 'finger', 'touch', '1'], capture_output=True)
            print(f"Auto-granted fingerprint touch for: {line.strip()}")
            sys.stdout.flush()
finally:
    proc.terminate()
PY
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
        echo "Usage: $0 {setup|grant|deny|start-auto-grant|stop-auto-grant}"
        exit 1
        ;;
esac
