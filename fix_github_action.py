import re

with open(".github/workflows/release-arch-git.yml", "r") as f:
    content = f.read()

# Add concurrency
concurrency_block = """concurrency:
  group: aur-git-push
  cancel-in-progress: false

permissions:"""

content = content.replace("permissions:", concurrency_block)


# Replace the sync block
old_sync_step = """          # Synchronize from repository packaging/arch-git/
          cp packaging/arch-git/PKGBUILD aur-repo/PKGBUILD
          cp packaging/arch-git/tapauth-git.install aur-repo/tapauth-git.install
          cp packaging/arch-git/tapauth-fprintd-git.install aur-repo/tapauth-fprintd-git.install
          cp packaging/arch-git/.SRCINFO aur-repo/.SRCINFO

          cd aur-repo

          # Check if git diff exists in aur-repo
          if git diff --quiet PKGBUILD .SRCINFO tapauth-git.install tapauth-fprintd-git.install; then
            echo "No changes in tapauth-git packaging files. Skipping commit."
            exit 0
          fi

          git add PKGBUILD .SRCINFO tapauth-git.install tapauth-fprintd-git.install
          git commit -m "Automated sync from main (${GITHUB_SHA::8})"
          git push origin master"""

new_sync_step = """          # Synchronize from repository packaging/arch-git/
          cp packaging/arch-git/PKGBUILD aur-repo/PKGBUILD
          cp packaging/arch-git/tapauth-git.install aur-repo/tapauth-git.install
          cp packaging/arch-git/tapauth-fprintd-git.install aur-repo/tapauth-fprintd-git.install

          # Regenerate .SRCINFO via makepkg (must run as non-root)
          docker run --rm -v "$(pwd)/aur-repo:/pkg" archlinux:base-devel \\
            bash -c "useradd -m builder && chown -R builder:builder /pkg && su builder -c 'cd /pkg && makepkg --printsrcinfo > .SRCINFO'"

          cd aur-repo

          if git diff --quiet PKGBUILD .SRCINFO tapauth-git.install tapauth-fprintd-git.install; then
            echo "No changes in tapauth-git packaging files. Skipping commit."
            exit 0
          fi

          git add PKGBUILD .SRCINFO tapauth-git.install tapauth-fprintd-git.install
          git commit -m "Automated sync from main (${GITHUB_SHA::8})"
          git push origin master"""

content = content.replace(old_sync_step, new_sync_step)

with open(".github/workflows/release-arch-git.yml", "w") as f:
    f.write(content)

