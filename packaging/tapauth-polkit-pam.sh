#!/bin/bash
# polkit vendor-drift protection (installed by tapauth / tapauth-git).
#
# Arch ships the polkit PAM vendor stack in /usr/lib/pam.d/polkit-1.
# TapAuth seeds a /etc/pam.d/polkit-1 override (which shadows the vendor
# file forever) and inserts its `sufficient pam_tapauth.so` line. When
# polkit is upgraded, the new vendor stack would remain shadowed by the
# stale override, silently missing any upstream changes (new module
# options, stack reordering). This script is run by the shipped libalpm
# PostTransaction hook (targets usr/lib/pam.d/polkit-1) and:
#   1. re-seeds /etc/pam.d/polkit-1 from the NEW vendor file, and
#   2. re-inserts the TapAuth line after the #%PAM-1.0 header,
# but ONLY when TapAuth has patched the file before — identified by the
# ${file}.tapauth-bak marker created by the package install scriptlet. If
# the marker is absent, TapAuth never touched polkit-1 and this is a no-op.
# The backup is refreshed to the new vendor file so a later removal
# restores the current upstream stack.

vendor=/usr/lib/pam.d/polkit-1
file=/etc/pam.d/polkit-1
[ -f "$vendor" ] || exit 0
[ -f "$file" ] || exit 0
[ -f "${file}.tapauth-bak" ] || exit 0
[ -L "$file" ] && exit 0

line="auth    sufficient    pam_tapauth.so"

cp -p "$vendor" "${file}.tapauth-bak" 2>/dev/null || exit 0
if ! cp -p "$vendor" "$file" 2>/dev/null; then
    exit 0
fi
if grep -q "pam_tapauth\.so" "$file" 2>/dev/null; then
    exit 0
fi
if head -n1 "$file" | grep -q '^#%PAM-1.0'; then
    sed -i "1a $line" "$file" 2>/dev/null
else
    sed -i "1i $line" "$file" 2>/dev/null
fi
echo "tapauth: re-applied TapAuth PAM integration to $file after polkit change"
