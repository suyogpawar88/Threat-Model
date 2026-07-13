#!/usr/bin/env python3
"""
Code repository MCP connector for appsec-threat-modeler.

GitHub-flavored by default (REPO_PROVIDER=github using the GitHub REST API),
since it is the most common target. The tool surface (get_file, list_tree,
search_code, get_recent_commits) maps cleanly onto GitLab/Bitbucket REST APIs
too -- swap the request URLs/auth headers in _headers()/_api() if the org
uses one of those instead; the tool signatures Claude calls do not need to
change.

Required env vars:
  REPO_PROVIDER   'github' (default) | 'gitlab' | 'bitbucket'
  REPO_TOKEN      personal access token / app token with read-only repo scope
  REPO_OWNER      org or user that owns the repo
  REPO_NAME       repository name
"""
import os
import base64
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("repo-connector")

PROVIDER = os.environ.get("REPO_PROVIDER", "github").lower()
TOKEN = os.environ.get("REPO_TOKEN", "")
OWNER = os.environ.get("REPO_OWNER", "")
NAME = os.environ.get("REPO_NAME", "")
TIMEOUT = 25
FILE_MAX_CHARS = 30000  # cap; pipe through scripts/summarize.py for large files


def _require_config():
    missing = [n for n, v in [("REPO_TOKEN", TOKEN), ("REPO_OWNER", OWNER), ("REPO_NAME", NAME)] if not v]
    if missing:
        raise RuntimeError(f"Repo connector is not configured. Missing env var(s): {', '.join(missing)}")
    if PROVIDER != "github":
        raise RuntimeError(
            f"REPO_PROVIDER={PROVIDER} is not implemented in this connector yet. "
            "This starter ships GitHub REST API support; extend _api()/_headers() "
            "for GitLab or Bitbucket using the same tool signatures."
        )


def _headers():
    return {"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"}


def _api(path: str, **params):
    url = f"https://api.github.com/repos/{OWNER}/{NAME}{path}"
    r = requests.get(url, headers=_headers(), params=params, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


@mcp.tool()
def get_file(path: str, ref: str = "") -> str:
    """Fetch a single file's contents from the repo (e.g. 'src/app.py', 'README.md').

    Truncated to FILE_MAX_CHARS. Use this to read architecture docs, IaC
    manifests (Terraform/Helm), CI config, or entry-point source files that
    describe data flows, auth, and integrations for the threat model.
    """
    _require_config()
    data = _api(f"/contents/{path.lstrip('/')}", **({"ref": ref} if ref else {}))
    if isinstance(data, list):
        raise ValueError(f"'{path}' is a directory, not a file. Use list_tree instead.")
    content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
    return content[:FILE_MAX_CHARS]


@mcp.tool()
def list_tree(path: str = "", ref: str = "") -> list:
    """List files and directories at a given path (root if path is empty).

    Use this to survey a repo's structure before deciding which files matter
    for the threat model (look for Dockerfiles, IaC, API route definitions,
    auth middleware, webhook handlers).
    """
    _require_config()
    data = _api(f"/contents/{path.lstrip('/')}" if path else "/contents", **({"ref": ref} if ref else {}))
    if not isinstance(data, list):
        raise ValueError(f"'{path}' is a file, not a directory. Use get_file instead.")
    return [{"name": item.get("name"), "path": item.get("path"), "type": item.get("type")} for item in data]


@mcp.tool()
def search_code(query: str, max_results: int = 15) -> list:
    """Search code in the repo (e.g. 'webhook secret', 'API_KEY', 'jwt.decode').

    Use this to hunt for specific patterns relevant to threat modeling:
    hardcoded secrets, auth logic, deserialization calls, admin/debug
    endpoints, or third-party integrations not mentioned in tickets/docs.
    """
    _require_config()
    url = "https://api.github.com/search/code"
    r = requests.get(url, headers=_headers(), params={"q": f"{query} repo:{OWNER}/{NAME}", "per_page": max_results}, timeout=TIMEOUT)
    r.raise_for_status()
    items = r.json().get("items", [])
    return [{"path": i.get("path"), "url": i.get("html_url")} for i in items]


@mcp.tool()
def get_recent_commits(path: str = "", max_results: int = 15) -> list:
    """List recent commits (optionally scoped to a path) with author and message.

    Recent, high-churn areas of the codebase are often where new attack
    surface has just been introduced -- useful for scoping which components
    most need fresh threat modeling attention.
    """
    _require_config()
    params = {"per_page": max_results}
    if path:
        params["path"] = path
    data = _api("/commits", **params)
    return [
        {
            "sha": c.get("sha", "")[:10],
            "message": (c.get("commit", {}).get("message", "").splitlines() or [""])[0],
            "author": c.get("commit", {}).get("author", {}).get("name"),
            "date": c.get("commit", {}).get("author", {}).get("date"),
        }
        for c in data
    ]


if __name__ == "__main__":
    mcp.run()
