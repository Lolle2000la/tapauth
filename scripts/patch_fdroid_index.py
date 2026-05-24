import json
import os
import sys
import urllib.request


def main():
    tag = os.environ.get("GITHUB_REF_NAME")
    repo = os.environ.get("GITHUB_REPOSITORY")

    if not tag or not repo:
        print("CRITICAL: Environment parameters GITHUB_REF_NAME or GITHUB_REPOSITORY are missing.")
        sys.exit(1)

    index_path = "fdroid/repo/index-v2.json"
    if not os.path.exists(index_path):
        print(f"CRITICAL: Target file {index_path} was not found.")
        sys.exit(1)

    owner, repo_name = repo.split("/")
    live_index_url = f"https://{owner}.github.io/{repo_name}/fdroid/repo/index-v2.json"

    old_versions = {}
    try:
        print(f"Fetching current deployment index from {live_index_url}...")
        req = urllib.request.Request(
            live_index_url,
            headers={"User-Agent": "Mozilla/5.0 (F-Droid Index Merger Pipeline)"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            old_data = json.loads(response.read().decode("utf-8"))
            old_packages = old_data.get("packages", {})
            for app_id, app_info in old_packages.items():
                if "versions" in app_info:
                    old_versions[app_id] = app_info["versions"]
        print("Successfully extracted history for preservation.")
    except Exception as e:
        print(f"No existing index detected or site is unreachable ({e}). Initializing a fresh timeline.")

    with open(index_path, "r", encoding="utf-8") as f:
        index_data = json.load(f)

    new_packages = index_data.get("packages", {})

    for app_id, old_app_versions in old_versions.items():
        if app_id in new_packages:
            if "versions" not in new_packages[app_id]:
                new_packages[app_id]["versions"] = {}
            for v_hash, v_info in old_app_versions.items():
                if v_hash not in new_packages[app_id]["versions"]:
                    new_packages[app_id]["versions"][v_hash] = v_info
        else:
            index_data["packages"][app_id] = {"versions": old_app_versions}

    for app_id, app_info in new_packages.items():
        versions = app_info.get("versions", {})
        for version_hash, version_info in versions.items():
            if "file" in version_info and "name" in version_info["file"]:
                current_file_locator = version_info["file"]["name"]

                if not current_file_locator.startswith("http"):
                    original_filename = os.path.basename(current_file_locator)
                    version_info["file"]["name"] = (
                        f"https://github.com/{repo}/releases/download/"
                        f"{tag}/{original_filename}"
                    )
                    print(f"Patched version hash {version_hash} -> Absolute GitHub Release target.")

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2)

    print("F-Droid tracking metadata lineage merge successfully completed.")


if __name__ == "__main__":
    main()
