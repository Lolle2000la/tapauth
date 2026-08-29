# BLE Advertising Unavailable: BlueZ / Kernel Version Mismatch

## Symptoms

`tapauthd` logs the following on every authentication attempt and falls back
to UDP-only:

```
Failed to start BLE advertising (attempt 1): Bluetooth operation failed: Failed to register advertisement. Retrying...
Failed to start BLE advertising (attempt 2): Bluetooth operation failed: Failed to register advertisement. Retrying...
...
```

Newer builds detect this condition and emit a single warning instead:

```
BLE advertising is unavailable on this system: Bluetooth operation failed: Failed to register advertisement
(known BlueZ/kernel incompatibility, see docs/ble-advertisement-bluez-kernel-mismatch.md).
Fix: upgrade BlueZ to >= 5.87 or boot an older kernel. Falling back to UDP-only for authentication.
```

BLE discovery never starts; the Android device cannot see the machine over
Bluetooth. UDP (Local Network) authentication continues to work.

## Root Cause

This is **not a TapAuth bug** — every application that registers a BLE
advertisement through BlueZ's D-Bus API is affected on these version
combinations, including `bluetoothctl` itself:

```
$ bluetoothctl
[bluetooth]# menu advertise
[bluetooth]# advertise on
Failed to register advertisement: org.bluez.Error.Failed
```

The failure chain:

1. Recent kernels (mainline 6.18+ and derivative stable series such as
   Ubuntu's `7.0.0-28` and later) added strict length validation to the
   kernel's `MGMT_OP_ADD_EXT_ADV_DATA` command
   (kernel commit `d3f7d17960ed` — *"Bluetooth: MGMT: validate Add Extended
   Advertising Data length"*).
2. `bluetoothd` versions **older than 5.87** have a bug where they send extra
   bytes with that command (they use the size of the legacy
   `mgmt_cp_add_advertising` struct instead of `mgmt_cp_add_ext_adv_data`).
3. The kernel rejects the malformed command with
   `Invalid Parameters (0x0d)`, and `bluetoothd` surfaces this to D-Bus
   clients as `org.bluez.Error.Failed: "Failed to register advertisement"`.

BlueZ **5.87** fixed the daemon-side bug (commit `2a6968b40378` —
*"advertising: Fix sending extra bytes with MGMT_OP_ADD_EXT_ADV_DATA"*),
which is why the same TapAuth build works on distributions shipping
BlueZ ≥ 5.87 but fails on, for example, Ubuntu 26.04 (ships BlueZ 5.85 with
new 7.0.x kernels).

## Confirming You Are Affected

```bash
bluetoothctl --version   # < 5.87 → affected daemon
uname -r                 # 6.18+ / 7.0.0-28+ → validating kernel
```

A decisive test: `bluetoothctl advertise on` fails with
`Failed to register advertisement` while the legacy kernel MGMT path still
works (`sudo btmgmt add-adv -c 1`). If `bluetoothctl` succeeds, the BLE
problem lies elsewhere (adapter power state, rfkill, etc.).

## Fixes

Any **one** of the following resolves it:

1. **Upgrade BlueZ to ≥ 5.87** (preferred). Once your distribution ships it
   (for Ubuntu this arrives as a package update/SRU), a regular
   `sudo apt update && sudo apt upgrade` is enough. No TapAuth changes
   needed.
2. **Temporarily boot a kernel without the strict validation** — for
   Ubuntu 26.04, kernel `7.0.0-27-generic` predates the change and works
   (select it in the GRUB "Advanced options" menu).
3. **Disable BLE transport** (`enable_ble = false` in
   `/etc/tapauth/config.toml`, or via the tapauth-config GUI) to silence the
   warnings if you only use UDP anyway.

## References

- BlueZ issue: <https://github.com/bluez/bluez/issues/2269>
- BlueZ fix: `2a6968b40378` (*advertising: Fix sending extra bytes with
  MGMT_OP_ADD_EXT_ADV_DATA*, released with BlueZ 5.87)
- Kernel validation that exposed it: `d3f7d17960ed` (*Bluetooth: MGMT:
  validate Add Extended Advertising Data length*)
- Kernel-side backward-compatibility fix: `149324fc762c` (*Bluetooth: MGMT:
  Fix backward compatibility with userspace*)
- Ubuntu kernel regression report:
  <https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2161852>
- Raspberry Pi kernel regression report (same signature):
  <https://github.com/raspberrypi/linux/issues/7473>
