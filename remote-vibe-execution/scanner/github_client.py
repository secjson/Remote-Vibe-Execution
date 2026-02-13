"""GitHub API integration for repository search and ingestion."""

from __future__ import annotations
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import requests

from scanner.config import ScanConfig
from scanner.models import RepoMetadata


class GitHubClient:
    """Handles GitHub API interactions and repo cloning."""

    BASE_URL = "https://api.github.com"

    def __init__(self, config: ScanConfig):
        self.config = config
        self.headers = {"Accept": "application/vnd.github+json"}
        if config.github_token:
            self.headers["Authorization"] = f"Bearer {config.github_token}"

    def search_repos(
        self, query: str, sort: str = "stars", max_results: int = 10
    ) -> list[dict]:
        """Search GitHub repositories."""
        params = {"q": query, "sort": sort, "per_page": min(max_results, 100)}
        resp = requests.get(
            f"{self.BASE_URL}/search/repositories",
            headers=self.headers,
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("items", [])[:max_results]

    def get_repo_info(self, owner: str, repo: str) -> dict:
        """Fetch repository metadata from GitHub API."""
        resp = requests.get(
            f"{self.BASE_URL}/repos/{owner}/{repo}",
            headers=self.headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def get_languages(self, owner: str, repo: str) -> dict:
        resp = requests.get(
            f"{self.BASE_URL}/repos/{owner}/{repo}/languages",
            headers=self.headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def clone_repo(self, repo_url: str, dest: Optional[str] = None) -> str:
        """Clone a repository to local disk. Returns the clone path."""
        if dest is None:
            dest = tempfile.mkdtemp(prefix="codescan_")

        clone_url = repo_url
        if self.config.github_token and "github.com" in repo_url:
            # Inject token for private repos
            clone_url = repo_url.replace(
                "https://", f"https://x-access-token:{self.config.github_token}@"
            )

        cmd = [
            "git", "clone", "--depth=1", "--single-branch", clone_url, dest
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr}")
        return dest

    def collect_metadata(self, repo_url: str, clone_path: str) -> RepoMetadata:
        """Build RepoMetadata from API + local clone."""
        meta = RepoMetadata(url=repo_url)

        # Parse owner/repo from URL
        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2:
            meta.owner = parts[-2]
            meta.name = parts[-1].replace(".git", "")

        # Try API metadata
        try:
            info = self.get_repo_info(meta.owner, meta.name)
            meta.default_branch = info.get("default_branch", "main")
            meta.stars = info.get("stargazers_count", 0)
            meta.forks = info.get("forks_count", 0)
        except Exception:
            pass

        try:
            meta.languages = self.get_languages(meta.owner, meta.name)
        except Exception:
            pass

        # Local metadata
        clone = Path(clone_path)
        files = list(clone.rglob("*"))
        meta.file_count = sum(1 for f in files if f.is_file())
        meta.total_size_kb = sum(
            f.stat().st_size for f in files if f.is_file()
        ) // 1024

        # Last commit
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%H %aI"],
                capture_output=True, text=True, cwd=clone_path
            )
            if result.returncode == 0:
                meta.last_commit = result.stdout.strip()
        except Exception:
            pass

        return meta


def ingest_repo(config: ScanConfig) -> tuple[str, RepoMetadata]:
    """
    Ingest a repository - either clone from URL or use local path.
    Returns (local_path, metadata).
    """
    client = GitHubClient(config)

    if config.repo_url:
        clone_path = client.clone_repo(config.repo_url)
        meta = client.collect_metadata(config.repo_url, clone_path)
        return clone_path, meta
    elif config.repo_path:
        path = os.path.abspath(config.repo_path)
        if not os.path.isdir(path):
            raise FileNotFoundError(f"Repo path not found: {path}")
        meta = RepoMetadata(url=f"file://{path}", name=os.path.basename(path))
        meta.file_count = sum(1 for _ in Path(path).rglob("*") if _.is_file())
        return path, meta
    else:
        raise ValueError("Must provide either repo_url or repo_path")
