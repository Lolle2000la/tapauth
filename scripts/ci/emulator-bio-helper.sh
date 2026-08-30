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
        echo "==> Enrolling test biometric credentials in Android Emulator..."
        # Set lock screen PIN
        adb shell locksettings set-pin 1234 2>/dev/null || true
        # Configure Android Virtual Biometrics HAL (Android 14/15/16)
        adb shell settings put secure biometric_virtual_enabled 1 2>/dev/null || true
        adb shell setprop persist.vendor.fingerprint.virtual.type rear 2>/dev/null || true
        adb shell setprop persist.vendor.fingerprint.virtual.enrollments 1 2>/dev/null || true
        adb shell setprop vendor.fingerprint.virtual.enrollments 1 2>/dev/null || true
        adb shell cmd fingerprint reset 2>/dev/null || true
        adb shell cmd fingerprint sync 2>/dev/null || true
        # Enroll fingerprint 1 (for both virtual HAL and traditional emulator HAL)
        adb shell cmd fingerprint enroll 0 2>/dev/null &
        ENROLL_PID=$!
        sleep 0.5
        for i in {1..10}; do
            adb emu finger touch 1 2>/dev/null || true
            sleep 0.2
        done
        wait $ENROLL_PID 2>/dev/null || true
        echo "✅ Test biometric profile enrolled (Finger 1 / Virtual Biometrics HAL)."
        ;;

    grant)
        echo "    Triggering biometric grant (finger touch 1)..."
        adb emu finger touch 1 2>/dev/null || true
        ;;

    deny)
        echo "    Triggering biometric denial (finger touch 2 / cancel / dev-deny broadcast)..."
        # Finger 2 is not enrolled, causing biometric failure
        adb emu finger touch 2 2>/dev/null || true
        # Send explicit denial broadcast to dev receiver with package targeting
        adb shell am broadcast -p dev.rourunisen.tapauth.e2e -a dev.rourunisen.tapauth.ACTION_DEV_DENY 2>/dev/null || adb shell am broadcast -p dev.rourunisen.tapauth.debug -a dev.rourunisen.tapauth.ACTION_DEV_DENY 2>/dev/null || adb shell am broadcast -a dev.rourunisen.tapauth.ACTION_DEV_DENY 2>/dev/null || true
        # Also simulate negative / cancel button if prompt is active
        adb shell input keyevent KEYCODE_BACK 2>/dev/null || true
        ;;

    start-auto-grant)
        echo "==> Starting background biometric auto-grant listener..."
        LOGCAT_LOG="/tmp/bio-auto-grant.log"

        cat << 'EOF' > /tmp/bio_auto_grant.py
import subprocess, time, sys

print("Biometric auto-grant daemon started...")
sys.stdout.flush()

proc = subprocess.Popen(['adb', 'logcat', '-v', 'brief', '*:V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

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
        echo "Usage: $0 {setup|grant|deny|start-auto-grant|stop-auto-grant}"
        exit 1
        ;;
esac
