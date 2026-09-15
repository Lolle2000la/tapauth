#!/bin/bash
# PAM vendor-drift protection (installed by tapauth / tapauth-git).
#
# TapAuth patches /etc/pam.d/{sudo,su,polkit-1} and keeps a one-time
# ${file}.tapauth-bak marker. Some vendor stacks live in /usr/lib/pam.d
# (e.g. polkit-1) and are shadowed forever by our /etc/pam.d override;
# others (sudo, su) are the /etc/pam.d vendor files themselves and are
# replaced on package upgrade. In either case an upstream change would be
# silently missed. This script is run by the shipped libalpm PostTransaction
# hook (targets usr/lib/pam.d/polkit-1, etc/pam.d/sudo, etc/pam.d/su) and,
# for each service:
#   1. re-seeds the override from the NEW vendor file when one exists, and
#   2. re-inserts the TapAuth line — after the #%PAM-1.0 header, or, for su,
#      before the first auth include (after pam_rootok/pam_wheel),
# but ONLY when TapAuth patched the file before (identified by the
# ${file}.tapauth-bak marker created by the package install scriptlet). If
# the marker is absent, TapAuth never touched the file and this is a no-op.
# The snapshot is refreshed from the current unpatched file so it stays
# current (removal now strips only the TapAuth line rather than restoring
# this snapshot; the explicit install.sh/uninstall.sh --restore-pam-backups
# path uses it).
# Idempotent: the line is only inserted when missing.

line="auth    sufficient    pam_tapauth.so"

# _reapply <service>
# Re-applies the TapAuth line to /etc/pam.d/<service> when TapAuth patched it
# before and the line is currently missing.
_reapply() {
    local svc="$1"
    local vendor="/usr/lib/pam.d/${svc}"
    local file="/etc/pam.d/${svc}"
    [ -f "$file" ] || return 0
    [ -L "$file" ] && return 0
    [ -f "${file}.tapauth-bak" ] || return 0
    if [ -f "$vendor" ]; then
        cp -p "$vendor" "${file}.tapauth-bak" 2>/dev/null || return 0
        cp -p "$vendor" "$file" 2>/dev/null || return 0
    fi
    grep -q "pam_tapauth\.so" "$file" 2>/dev/null && return 0
    # Refresh the snapshot from the current (unpatched) stack so it stays
    # current for the explicit rollback path, then insert the line.
    cp -p "$file" "${file}.tapauth-bak" 2>/dev/null || true
    if [ "$svc" = "su" ]; then
        # PAM_USER for su is the TARGET user: insert after the
        # pam_rootok/pam_wheel block, before the first auth include
        # (common-auth / system-auth / @include), never at the top.
        local anchor
        anchor=$(awk '
            /^[[:space:]]*#/ { next }
            /(common-auth|system-auth)/ || ($1 == "auth" && /(include|substack)/) { print NR; exit }
        ' "$file")
        if [ -n "$anchor" ]; then
            sed -i "${anchor}i $line" "$file" 2>/dev/null
            echo "tapauth: re-applied TapAuth PAM integration to $file after vendor change"
            return 0
        fi
    fi
    if head -n1 "$file" | grep -q '^#%PAM-1.0'; then
        sed -i "1a $line" "$file" 2>/dev/null
    else
        sed -i "1i $line" "$file" 2>/dev/null
    fi
    echo "tapauth: re-applied TapAuth PAM integration to $file after vendor change"
}

for _svc in sudo su polkit-1; do
    _reapply "$_svc"
done
