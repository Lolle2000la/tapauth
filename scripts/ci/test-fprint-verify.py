#!/usr/bin/env python3
"""E2E helper for testing the virtual fprintd D-Bus interface.

Maintains a single persistent D-Bus connection to:
1. Subscribe to net.reactivated.Fprint.Device.VerifyStatus signal
2. Call net.reactivated.Fprint.Device.Claim(username)
3. Call net.reactivated.Fprint.Device.VerifyStart("any")
4. Wait for VerifyStatus("verify-match", done=True)
5. Call net.reactivated.Fprint.Device.Release()
"""

import sys

try:
    from gi.repository import Gio, GLib
except ImportError:
    print("gi.repository not available; skipping Python fprint test", file=sys.stderr)
    sys.exit(2)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <device_path> <username> [timeout_secs]")
        sys.exit(1)

    dev_path = sys.argv[1]
    username = sys.argv[2]
    timeout_secs = int(sys.argv[3]) if len(sys.argv) > 3 else 15

    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    loop = GLib.MainLoop()
    result = {"status": None, "done": False}

    def on_signal(connection, sender_name, object_path, interface_name, signal_name, parameters, user_data):
        res, done = parameters.unpack()
        print(f"Received {signal_name}: result={res}, done={done}")
        result["status"] = res
        result["done"] = done
        if done:
            loop.quit()

    def on_timeout(user_data):
        print("Timeout waiting for VerifyStatus signal", file=sys.stderr)
        loop.quit()
        return False

    sub_id = bus.signal_subscribe(
        "net.reactivated.Fprint",
        "net.reactivated.Fprint.Device",
        "VerifyStatus",
        dev_path,
        None,
        Gio.DBusSignalFlags.NONE,
        on_signal,
        None,
    )

    # 1. Claim
    print(f"Claiming device {dev_path} for user {username}...")
    bus.call_sync(
        "net.reactivated.Fprint",
        dev_path,
        "net.reactivated.Fprint.Device",
        "Claim",
        GLib.Variant("(s)", (username,)),
        GLib.VariantType("()"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )

    # 2. VerifyStart
    print("Starting verification (VerifyStart)...")
    bus.call_sync(
        "net.reactivated.Fprint",
        dev_path,
        "net.reactivated.Fprint.Device",
        "VerifyStart",
        GLib.Variant("(s)", ("any",)),
        GLib.VariantType("()"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )

    # 3. Wait for signal
    GLib.timeout_add_seconds(timeout_secs, on_timeout, None)
    loop.run()

    # 4. Release
    print("Releasing device...")
    try:
        bus.call_sync(
            "net.reactivated.Fprint",
            dev_path,
            "net.reactivated.Fprint.Device",
            "Release",
            None,
            GLib.VariantType("()"),
            Gio.DBusCallFlags.NONE,
            5000,
            None,
        )
    except Exception as e:
        print(f"Warning during release: {e}", file=sys.stderr)

    bus.signal_unsubscribe(sub_id)

    if result["status"] == "verify-match" and result["done"]:
        print("SUCCESS: Received verify-match signal with done=True")
        sys.exit(0)
    else:
        print(
            f"FAILURE: Expected verify-match, got status={result['status']}, done={result['done']}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
