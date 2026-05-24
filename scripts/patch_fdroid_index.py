import json
import os
import sys
import time
import urllib.error
import urllib.request


def fetch_live_index(url, max_retries=3):
    for attempt in range(1, max_retries + 1):
        try:
            print(f"Fetching current deployment index from {url} (attempt {attempt}/{max_retries})...")
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (F-Droid Index Merger Pipeline)"},
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print("No existing index deployed yet (404). Initializing a fresh timeline.")
                return None
            print(f"CRITICAL: HTTP {e.code} fetching live index — cannot proceed safely.")
            sys.exit(1)
        except urllib.error.URLError as e:
            if attempt < max_retries:
                backoff = 2 ** attempt
                print(f"Transient network error ({e}), retrying in {backoff}s...")
                time.sleep(backoff)
            else:
                print(f"CRITICAL: Live index unreachable after {max_retries} attempts ({e}).")
                print("Refusing to overwrite repository history during a network outage.")
                sys.exit(1)


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

    old_data = fetch_live_index(live_index_url)

    old_packages = {}
    if old_data is not None:
        old_packages = old_data.get("packages", {})

    with open(index_path, "r", encoding="utf-8") as f:
        index_data = json.load(f)

    index_data.setdefault("packages", {})
    new_packages = index_data["packages"]

    for app_id, old_app_info in old_packages.items():
        old_versions = old_app_info.get("versions", {})

        if app_id in new_packages:
            new_packages[app_id].setdefault("versions", {})
            for v_hash, v_info in old_versions.items():
                if v_hash not in new_packages[app_id]["versions"]:
                    new_packages[app_id]["versions"][v_hash] = v_info
        else:
            index_data["packages"][app_id] = dict(old_app_info)

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
