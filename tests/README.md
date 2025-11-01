# TapAuth Integration Tests

Non-interactive integration tests for the TapAuth daemon IPC interface.

## Overview

These tests validate the daemon's IPC protocol without requiring actual Android devices. They test:

- **Health checks**: Basic socket connectivity
- **Authentication timeouts**: Daemon behavior when no device responds
- **Cancellation**: Sending cancel requests during authentication
- **Concurrent requests**: Multiple simultaneous auth flows
- **Error handling**: Malformed messages and edge cases

## Running the Tests

### Quick Start

```bash
# From the repository root
sudo ./tests/run-integration-tests.sh
```

The script will:
1. Build the daemon and tests
2. Start a test daemon instance (via systemd or manually)
3. Run all integration tests
4. Clean up automatically

### Manual Execution

If you prefer to manage the daemon yourself:

```bash
# Terminal 1: Start the daemon
sudo RUST_LOG=info TAPAUTHD_SOCK=/run/tapauthd/tapauthd-test.sock ./target/release/tapauthd

# Terminal 2: Run tests
export TAPAUTHD_SOCK=/run/tapauthd/tapauthd-test.sock
cargo test --test integration_test -- --nocapture --test-threads=1
```

## Test Scenarios

### `test_health_check`
Connects to the daemon and sends an empty frame (zero-length message). Verifies the daemon handles it gracefully without crashing.

### `test_auth_timeout`
Sends an authentication request with a 2-second timeout. Since no device is available to respond, validates that the daemon returns `PamOutcome::Denied` after the timeout expires.

### `test_cancel_request`
1. Sends an auth request with a 10-second timeout
2. After 500ms, sends a cancel request for the same `request_id`
3. Validates that:
   - The cancel ack returns `PamOutcome::Ignore`
   - The original auth request returns `PamOutcome::Denied`
   - The daemon broadcasts cancellation packets

### `test_concurrent_requests`
Spawns two threads that each send an auth request with unique `request_id` values. Verifies that the daemon handles concurrent clients correctly and each gets an appropriate response.

### `test_malformed_message`
Sends garbage data (invalid protobuf) to the daemon. Validates that the daemon either:
- Closes the connection gracefully, OR
- Responds with an error message

Does not crash or hang.

### `test_empty_frame`
Sends a zero-length frame (health check variant). Similar to `test_health_check` but explicitly tests the empty frame path.

## Architecture

```
tests/
├── Cargo.toml              # Test crate manifest
├── build.rs                # Generates protobuf code for IPC messages
├── integration_test.rs     # Test implementations
├── run-integration-tests.sh # Test runner script (builds, runs daemon, executes tests)
└── README.md               # This file
```

The tests:
- Use `prost` to encode/decode IPC messages
- Connect directly to the Unix socket at `$TAPAUTHD_SOCK`
- Use the same protobuf schema as the PAM module (`proto/ipc.proto`)
- Run serially (`--test-threads=1`) to avoid socket conflicts

## Requirements

- Root privileges (daemon binds to `/run/tapauthd/`)
- `cargo` and Rust toolchain
- Optional: `systemd` for socket activation mode

## Environment Variables

- `TAPAUTHD_SOCK`: Override the daemon socket path (default: `/run/tapauthd/tapauthd-test.sock`)
- `RUST_LOG`: Set daemon logging level (e.g., `debug`, `info`)

## Limitations

These tests do **not** cover:
- Actual Android device pairing and authentication (requires physical devices)
- BLE/UDP transport correctness (mocked by timeouts)
- Configuration file validation (tested elsewhere)
- Privilege drop behavior (requires real systemd environment)

For device-based end-to-end testing, use `client-pam/build-test-pam.sh` with `pamtester`.

## Troubleshooting

**Socket permission denied:**
```bash
sudo chown root:$USER /run/tapauthd/tapauthd-test.sock
sudo chmod 0660 /run/tapauthd/tapauthd-test.sock
```

**Daemon not starting:**
- Check logs: `sudo journalctl -u tapauthd-test.service -f` (systemd mode)
- Or check `/tmp/tapauthd-test.log` (manual mode)

**Tests hang:**
- Ensure `--test-threads=1` is set (tests must run serially)
- Verify no other process is using the test socket path

**Build errors:**
- Ensure `proto/ipc.proto` exists and is valid
- Run `cargo clean` and rebuild
