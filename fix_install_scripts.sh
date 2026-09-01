#!/bin/bash
for f in packaging/arch/tapauth.install packaging/arch-git/tapauth-git.install; do
  # Fix 1: pre_remove
  sed -i -e '/pre_remove() {/,/^}/c\
pre_remove() {\
  systemctl disable --now tapauthd.socket tapauthd.service 2>/dev/null || true\
  # Remove pam_tapauth.so lines to prevent lockout after uninstall\
  local failed_files=()\
  for pam_file in /etc/pam.d/*; do\
    [ -f "$pam_file" ] || continue\
    if grep -q "pam_tapauth\\.so" "$pam_file" 2>/dev/null; then\
      if sed -i '\''/pam_tapauth\\.so/d'\'' "$pam_file" 2>/dev/null; then\
        echo ":: Removed pam_tapauth.so from $pam_file"\
      else\
        failed_files+=("$pam_file")\
      fi\
    fi\
  done\
  if [ ${#failed_files[@]} -gt 0 ]; then\
    echo ":: WARNING: Could not automatically remove pam_tapauth.so from:"\
    for f in "${failed_files[@]}"; do echo "::   $f"; done\
    echo ":: Please remove these references manually to avoid authentication lockouts!"\
  fi\
}' "$f"

  # Fix 3: post_install
  sed -i 's|systemd-tmpfiles --create /usr/lib/tmpfiles.d/tapauth.conf|systemd-tmpfiles --create /usr/lib/tmpfiles.d/tapauth.conf\n  chown tapauthd:tapauthd /etc/tapauth 2>/dev/null || true|g' "$f"
  sed -i '/mkdir -p \/etc\/tapauth/d' "$f"

done
