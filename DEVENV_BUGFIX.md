# Development Environment - Bug Fix

**Date**: 2025-10-19  
**Issue**: Missing dependencies in Dockerfile  
**Status**: ✅ **FIXED**

---

## Problem

When running `./dev-start.sh`, the build failed with two missing dependencies:

1. **Protocol Buffers Compiler** (`protoc`)
   - Error: `Could not find protoc`
   - Required by: `prost-build` in `shared/build.rs`
   - Used for: Compiling `.proto` files to Rust code

2. **TPM Libraries** (`tss2-sys`)
   - Error: `Failed to find tss2-sys library`
   - Required by: `tss-esapi-sys` (optional TPM feature)
   - Used for: TPM hardware security module support

---

## Solution

Updated `Dockerfile.dev` to include missing packages:

```dockerfile
# Protocol Buffers compiler (required for build.rs)
protobuf-compiler \

# TPM development libraries (for optional TPM feature)
libtss2-dev \
```

---

## Verification

Build now completes successfully:

```bash
./dev-start.sh
# ✅ Docker image builds successfully
# ✅ All TapAuth components compile
# ✅ PAM module installed
# ✅ GUI installed
# ✅ Container ready for testing
```

Build time: ~1 minute 07 seconds (with warm cache)

---

## Testing

Container is now fully functional:

```bash
./dev-shell.sh

# Inside container:
build-tapauth  # ✅ Works
run-gui        # ✅ Works
test-pam-auth root  # ✅ Ready for testing
```

---

## Updated Files

- **`Dockerfile.dev`**: Added `protobuf-compiler` and `libtss2-dev` packages

---

**Status**: ✅ Development environment fully operational!
