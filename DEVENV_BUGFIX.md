# Development Environment - Bug Fix

**Date**: 2025-10-19  
**Issue**: Missing dependencies in Dockerfile  
**Status**: ✅ **FIXED**

---

## Problems Found

When running `./dev-start.sh` and `run-gui`, four missing dependency groups were discovered:

1. **Protocol Buffers Compiler** (`protoc`)
   - Error: `Could not find protoc`
   - Required by: `prost-build` in `shared/build.rs`
   - Used for: Compiling `.proto` files to Rust code

2. **TPM Libraries** (`tss2-sys`)
   - Error: `Failed to find tss2-sys library`
   - Required by: `tss-esapi-sys` (optional TPM feature)
   - Used for: TPM hardware security module support

3. **X11-XCB Library** (`libX11-xcb`)
   - Error: `libX11-xcb.so.1: cannot open shared object file`
   - Required by: `iced_winit` (GUI framework)
   - Used for: X11 window system bridge to XCB

4. **X11 Extension Libraries** (`libXi`, `libXrandr`, `libXcursor`, etc.)
   - Error: `libXi.so.6: cannot open shared object file`
   - Required by: `winit` (window system abstraction used by iced)
   - Used for: Mouse/keyboard input, display configuration, cursor management, rendering, multi-monitor support

5. **Graphics Rendering Libraries** (Mesa/wgpu)
   - Error: `Available adapters: []` followed by panic in `wgpu-core`
   - Required by: `wgpu` (WebGPU implementation used by iced for rendering)
   - Used for: GPU rendering or software fallback rendering
   - Root cause: No GPU drivers available in container, and no software rendering fallback

6. **X11 Authorization and Window Management / XWayland Compatibility** ✅ **FIXED**
   - Error: `BadAccess (attempt to access private resource denied)` and `BadDrawable (invalid Pixmap or Window parameter)`
   - Context: GUI window briefly appears but then crashes during window mapping
   - Occurs after software rendering is set up correctly (llvmpipe detected)
   - Root cause: **Vulkan backend incompatibility with XWayland compositor**
     - Host system runs Wayland with XWayland (not pure X11)
     - wgpu's Vulkan backend has issues with XWayland's compositor
     - OpenGL backend has better XWayland compatibility
   - Solution: Force OpenGL backend with `ENV WGPU_BACKEND=gl`

---

## Solution

Updated `Dockerfile.dev` to include missing packages:

```dockerfile
# Protocol Buffers compiler (required for build.rs)
protobuf-compiler \

# TPM development libraries (for optional TPM feature)
libtss2-dev \

# X11-XCB bridge library (required for GUI)
libx11-xcb1 \
libx11-xcb-dev \

# X11 extension libraries (required by winit for GUI)
libxi6 \              # Input extension (mouse/keyboard)
libxi-dev \
libxrandr2 \          # RandR extension (display configuration)
libxrandr-dev \
libxcursor1 \         # Cursor library
libxcursor-dev \
libxrender1 \         # Render extension
libxrender-dev \
libxinerama1 \        # Xinerama extension (multi-monitor)
libxinerama-dev \
libxkbcommon-x11-0 \  # XKB common library for X11

# Mesa/DRI for software rendering (wgpu without GPU)
mesa-vulkan-drivers \  # Vulkan software renderer
mesa-utils \           # Mesa utilities
libgl1-mesa-dri \      # DRI drivers
libgl1-mesa-glx \      # OpenGL implementation
libegl1-mesa \         # EGL implementation
libgbm1 \              # Generic Buffer Management
libdrm2 \              # Direct Rendering Manager

# Environment variables for software rendering
ENV LIBGL_ALWAYS_SOFTWARE=1
ENV GALLIUM_DRIVER=llvmpipe

# Force OpenGL backend (XWayland compatibility)
ENV WGPU_BACKEND=gl
```

**Additional Configuration:**
- X11 authentication: Mount `.Xauthority` file in docker-compose
- X11 permissions: Run `xhost +local:docker` on host before starting container

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
