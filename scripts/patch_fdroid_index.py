import json
import hashlib
import os
import sys


def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def main():
    tag = os.environ.get("GITHUB_REF_NAME")
    if not tag:
        print("CRITICAL: GITHUB_REF_NAME environment variable is missing.")
        sys.exit(1)

    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("CRITICAL: GITHUB_REPOSITORY environment variable is missing.")
        sys.exit(1)

    index_path = "fdroid/repo/index-v2.json"
    entry_path = "fdroid/repo/entry.json"

    if not os.path.exists(index_path) or not os.path.exists(entry_path):
        print("CRITICAL: F-Droid metadata generation targets not found.")
        sys.exit(1)

    with open(index_path, "r", encoding="utf-8") as f:
        index_data = json.load(f)

    packages = index_data.get("packages", {})
    for app_id, app_info in packages.items():
        versions = app_info.get("versions", {})
        for version_hash, version_info in versions.items():
            if "file" in version_info and "name" in version_info["file"]:
                original_filename = os.path.basename(version_info["file"]["name"])
                version_info["file"]["name"] = (
                    f"https://github.com/{repo}/releases/download/"
                    f"{tag}/{original_filename}"
                )

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2)

    new_sha256 = compute_sha256(index_path)
    new_size = os.path.getsize(index_path)

    with open(entry_path, "r", encoding="utf-8") as f:
        entry_data = json.load(f)

    if "index" not in entry_data:
        print("CRITICAL: entry.json is missing the 'index' object — cannot update hashes.")
        sys.exit(1)

    entry_data["index"]["sha256"] = new_sha256
    entry_data["index"]["size"] = new_size

    with open(entry_path, "w", encoding="utf-8") as f:
        json.dump(entry_data, f, indent=2)

    print("Successfully patched F-Droid index redirects to GitHub Releases.")


if __name__ == "__main__":
    main()
