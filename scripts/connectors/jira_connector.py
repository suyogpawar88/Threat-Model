#!/usr/bin/env python3
"""
Jira MCP connector for appsec-threat-modeler.

Exposes read-only tools that pull ticket/epic context (system description,
requirements, linked components) into a threat modeling session. Auth is via
a Jira Cloud API token (Basic auth: email + token).

Required env vars (set in .mcp.json / plugin config, never hardcoded):
  JIRA_BASE_URL   e.g. https://your-org.atlassian.net
  JIRA_EMAIL      the Atlassian account email tied to the API token
  JIRA_API_TOKEN  API token from https://id.atlassian.com/manage-profile/security/api-tokens
"""
import os
import sys
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("jira-connector")

BASE_URL = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
EMAIL = os.environ.get("JIRA_EMAIL", "")
API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
TIMEOUT = 25


def _require_config():
    missing = [n for n, v in [("JIRA_BASE_URL", BASE_URL), ("JIRA_EMAIL", EMAIL), ("JIRA_API_TOKEN", API_TOKEN)] if not v]
    if missing:
        raise RuntimeError(f"Jira connector is not configured. Missing env var(s): {', '.join(missing)}")


def _auth():
    return (EMAIL, API_TOKEN)


def _adf_to_text(node) -> str:
    """Flatten Jira's Atlassian Document Format description into plain text."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    text_parts = []
    if isinstance(node, dict):
        if node.get("type") == "text":
            return node.get("text", "")
        for child in node.get("content", []) or []:
            text_parts.append(_adf_to_text(child))
        if node.get("type") in ("paragraph", "heading"):
            text_parts.append("\n")
    return "".join(text_parts)


@mcp.tool()
def get_issue(issue_key: str) -> dict:
    """Fetch a single Jira issue/epic/story by key (e.g. 'PROJ-123').

    Returns summary, description, status, issue type, labels, components,
    and linked issues -- the fields most relevant for scoping a threat model
    (what is being built, what it touches, what else it connects to).
    """
    _require_config()
    url = f"{BASE_URL}/rest/api/3/issue/{issue_key}"
    params = {"fields": "summary,description,status,issuetype,labels,components,issuelinks,priority"}
    r = requests.get(url, auth=_auth(), params=params, headers={"Accept": "application/json"}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    fields = data.get("fields", {})
    links = []
    for link in fields.get("issuelinks", []) or []:
        other = link.get("outwardIssue") or link.get("inwardIssue") or {}
        if other:
            links.append({"key": other.get("key"), "summary": (other.get("fields") or {}).get("summary")})
    return {
        "key": data.get("key"),
        "summary": fields.get("summary"),
        "status": (fields.get("status") or {}).get("name"),
        "issue_type": (fields.get("issuetype") or {}).get("name"),
        "priority": (fields.get("priority") or {}).get("name"),
        "description": _adf_to_text(fields.get("description")),
        "labels": fields.get("labels", []),
        "components": [c.get("name") for c in fields.get("components", [])],
        "linked_issues": links,
        "url": f"{BASE_URL}/browse/{data.get('key')}",
    }


@mcp.tool()
def search_issues(jql: str, max_results: int = 20) -> list:
    """Search Jira issues using JQL (e.g. 'project = PROJ AND labels = threat-model').

    Returns key, summary, status, and issue type for each match -- use this to
    discover which tickets describe the system/feature being threat modeled
    before pulling full detail with get_issue.
    """
    _require_config()
    url = f"{BASE_URL}/rest/api/3/search"
    params = {"jql": jql, "maxResults": max_results, "fields": "summary,status,issuetype"}
    r = requests.get(url, auth=_auth(), params=params, timeout=TIMEOUT)
    r.raise_for_status()
    issues = r.json().get("issues", [])
    return [
        {
            "key": i["key"],
            "summary": i["fields"].get("summary"),
            "status": (i["fields"].get("status") or {}).get("name"),
            "issue_type": (i["fields"].get("issuetype") or {}).get("name"),
        }
        for i in issues
    ]


@mcp.tool()
def get_epic_children(epic_key: str, max_results: int = 50) -> list:
    """List all child issues (stories/tasks) under an epic.

    Use this to enumerate the full scope of a feature/system before threat
    modeling it -- an epic's children often reveal components and data flows
    not mentioned in the epic description itself.
    """
    return search_issues(f'"Epic Link" = {epic_key} OR parent = {epic_key}', max_results)


if __name__ == "__main__":
    mcp.run()
