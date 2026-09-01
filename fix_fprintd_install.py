import re

logic_to_add = """
  # Detect pam_fprintd.so references and offer to replace them with the decisive TapAuth line
  local pam_decisive="auth    [success=done default=bad]    /usr/lib/security/pam_tapauth.so"
  local repaired=0
  for pam_file in /etc/pam.d/kde-fingerprint /etc/pam.d/gdm-fingerprint /etc/pam.d/fingerprint-auth; do
    [ -f "$pam_file" ] || continue
    if grep -q "pam_fprintd\.so" "$pam_file" 2>/dev/null && ! grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
      sed -i "s|.*pam_fprintd\.so.*|$pam_decisive|" "$pam_file" 2>/dev/null && {
        echo ":: Replaced pam_fprintd.so with pam_tapauth.so in $pam_file"
        repaired=$((repaired + 1))
      } || echo ":: WARNING: Could not update $pam_file — please replace pam_fprintd.so lines manually"
    fi
  done
  if [ "$repaired" -gt 0 ]; then
    echo ":: Lock screen fingerprint stack updated to use TapAuth. You may need to log out and back in."
  else
    echo ":: To enable lock screen unlock, ensure /etc/pam.d/kde-fingerprint or gdm-fingerprint"
    echo ":: contains: auth    [success=done default=bad]    /usr/lib/security/pam_tapauth.so"
  fi"""

for filepath in ["packaging/arch/tapauth-fprintd.install", "packaging/arch-git/tapauth-fprintd-git.install"]:
    with open(filepath, "r") as f:
        content = f.read()
    
    # insert before the closing brace of post_install
    content = re.sub(r'(post_install\(\) \{.*?)(\n\})', lambda m: m.group(1) + logic_to_add + m.group(2), content, flags=re.DOTALL)
    
    with open(filepath, "w") as f:
        f.write(content)

