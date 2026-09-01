import re

with open("packaging/tapauth.spec", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if line.strip() == "Recommends:     fprintd-pam":
        continue
    new_lines.append(line)

content = "".join(new_lines)

post_fprintd_note = """
echo "TapAuth virtual fprintd bridge enabled."
echo "For lock screen integration, ensure /etc/pam.d/kde-fingerprint or"
echo "gdm-fingerprint contains: auth [success=done default=bad] /usr/lib/security/pam_tapauth.so"
"""

content = content.replace("%post fprintd\n", "%post fprintd\n" + post_fprintd_note)

with open("packaging/tapauth.spec", "w") as f:
    f.write(content)

