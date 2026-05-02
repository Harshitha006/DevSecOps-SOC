import requests
import os

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def fetch_commit_files(repo: str, sha: str):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print("GitHub API error:", response.text)
        return []

    data = response.json()

    files = []

    for f in data.get("files", []):
        files.append({
            "path": f["filename"],
            "content": f.get("patch", "")  # diff
        })

    return files