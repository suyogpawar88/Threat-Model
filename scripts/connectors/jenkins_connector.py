#!/usr/bin/env python3
"""
Jenkins MCP connector for appsec-threat-modeler.

Exposes read-only tools that pull pipeline/build context -- job config summary,
recent build status, and console log tail -- so the threat model can reason
about the CI/CD data flow (build triggers, artifact publishing, deploy steps,
secrets usage) as part of the system under review.

Required env vars:
  JENKINS_BASE_URL   e.g. https://jenkins.your-org.com
  JENKINS_USER       Jenkins username
  JENKINS_API_TOKEN  API token from Jenkins > User > Configure > API Token
"""
import os
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("jenkins-connector")

BASE_URL = os.environ.get("JENKINS_BASE_URL", "").rstrip("/")
USER = os.environ.get("JENKINS_USER", "")
API_TOKEN = os.environ.get("JENKINS_API_TOKEN", "")
TIMEOUT = 25
CONSOLE_LOG_MAX_CHARS = 20000  # cap raw payload; use scripts/summarize.py to compress further


def _require_config():
    missing = [n for n, v in [("JENKINS_BASE_URL", BASE_URL), ("JENKINS_USER", USER), ("JENKINS_API_TOKEN", API_TOKEN)] if not v]
    if missing:
        raise RuntimeError(f"Jenkins connector is not configured. Missing env var(s): {', '.join(missing)}")


def _auth():
    return (USER, API_TOKEN)


@mcp.tool()
def get_job(job_path: str) -> dict:
    """Fetch a Jenkins job's config summary by path (e.g. 'folder/job-name').

    Returns description, whether it's parameterized (secrets/inputs surface),
    SCM/repo URL if configured, and the most recent build number/status --
    useful for mapping the CI/CD pipeline into the data flow diagram.
    """
    _require_config()
    url = f"{BASE_URL}/job/{job_path.strip('/').replace('/', '/job/')}/api/json"
    r = requests.get(url, auth=_auth(), params={"tree": "description,buildable,property[parameterDefinitions[name,type]],lastBuild[number,result,timestamp],scm[userRemoteConfigs[url]]"}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    params = []
    for prop in data.get("property", []) or []:
        for pd in prop.get("parameterDefinitions", []) or []:
            params.append({"name": pd.get("name"), "type": pd.get("type")})
    last_build = data.get("lastBuild") or {}
    return {
        "job_path": job_path,
        "description": data.get("description"),
        "buildable": data.get("buildable"),
        "parameters": params,
        "last_build_number": last_build.get("number"),
        "last_build_result": last_build.get("result"),
        "url": f"{BASE_URL}/job/{job_path.strip('/').replace('/', '/job/')}/",
    }


@mcp.tool()
def get_build(job_path: str, build_number: str = "lastBuild") -> dict:
    """Fetch a specific build's metadata (result, duration, triggered-by, artifacts).

    build_number can be a number or 'lastBuild'/'lastSuccessfulBuild'/'lastFailedBuild'.
    Use this to understand what a pipeline run actually does -- deploy targets,
    artifact publishing steps -- which often reveal trust boundary crossings.
    """
    _require_config()
    path = job_path.strip("/").replace("/", "/job/")
    url = f"{BASE_URL}/job/{path}/{build_number}/api/json"
    r = requests.get(url, auth=_auth(), timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    causes = []
    for action in data.get("actions", []) or []:
        for cause in action.get("causes", []) or []:
            if cause.get("shortDescription"):
                causes.append(cause["shortDescription"])
    artifacts = [a.get("relativePath") for a in data.get("artifacts", []) or []]
    return {
        "job_path": job_path,
        "number": data.get("number"),
        "result": data.get("result"),
        "duration_ms": data.get("duration"),
        "triggered_by": causes,
        "artifacts": artifacts,
        "url": data.get("url"),
    }


@mcp.tool()
def get_console_log_tail(job_path: str, build_number: str = "lastBuild", max_chars: int = CONSOLE_LOG_MAX_CHARS) -> str:
    """Fetch the tail of a build's console log (truncated to max_chars).

    Console logs can be huge -- this returns only the tail and caps length.
    For very large or noisy logs, pipe the result through
    scripts/summarize.py before adding it to the threat-modeling context, to
    keep token usage down.
    """
    _require_config()
    path = job_path.strip("/").replace("/", "/job/")
    url = f"{BASE_URL}/job/{path}/{build_number}/consoleText"
    r = requests.get(url, auth=_auth(), timeout=TIMEOUT)
    r.raise_for_status()
    text = r.text
    return text[-max_chars:] if len(text) > max_chars else text


if __name__ == "__main__":
    mcp.run()
