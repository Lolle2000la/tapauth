import os

pre_remove_replacement = """pre_remove() {
  systemctl disable --now tapauthd.socket tapauthd.service 2>/dev/null || true
  # Remove pam_tapauth.so lines to prevent lockout after uninstall
  local failed_files=()
  for pam_file in /etc/pam.d/*; do
    [ -f "$pam_file" ] || continue
    if grep -q "pam_tapauth\\.so" "$pam_file" 2>/dev/null; then
      if sed -i '/pam_tapauth\\.so/d' "$pam_file" 2>/dev/null; then
        echo ":: Removed pam_tapauth.so from $pam_file"
      else
        failed_files+=("$pam_file")
      fi
    fi
  done
  if [ ${#failed_files[@]} -gt 0 ]; then
    echo ":: WARNING: Could not automatically remove pam_tapauth.so from:"
    for f in "${failed_files[@]}"; do echo "::   $f"; done
    echo ":: Please remove these references manually to avoid authentication lockouts!"
  fi
}"""

import re

for filepath in ["packaging/arch/tapauth.install", "packaging/arch-git/tapauth-git.install"]:
    with open(filepath, "r") as f:
        content = f.read()
    
    # Fix 1: pre_remove
    content = re.sub(r'pre_remove\(\) \{.*?\n\}', pre_remove_replacement, content, flags=re.DOTALL)
    
    # Fix 3: post_install
    content = content.replace("systemd-tmpfiles --create /usr/lib/tmpfiles.d/tapauth.conf", 
                              "systemd-tmpfiles --create /usr/lib/tmpfiles.d/tapauth.conf\n  chown tapauthd:tapauthd /etc/tapauth 2>/dev/null || true")
    
    content = content.replace("    mkdir -p /etc/tapauth\n", "")
    
    with open(filepath, "w") as f:
        f.write(content)

