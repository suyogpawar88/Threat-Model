#!/usr/bin/env python3
"""
ServiceNow MCP connector for appsec-threat-modeler.

Exposes read-only tools over the ServiceNow Table API to pull change
requests, incidents, and risk/compliance records that provide context for a
threat model -- e.g. an existing Change Request describing the deployment,
or prior Incidents against the same service (real-world evidence of
likelihood, not just theoretical risk).

Required env vars:
  SERVICENOW_INSTANCE_URL   e.g. https://your-instance.service-now.com
  SERVICENOW_USER
  SERVICENOW_PASSWORD       or an OAuth/API-key-backed service account credential
"""
import os
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("servicenow-connector")

INSTANCE_URL = os.environ.get("SERVICENOW_INSTANCE_URL", "").rstrip("/")
USER = os.environ.get("SERVICENOW_USER", "")
PASSWORD = os.environ.get("SERVICENOW_PASSWORD", "")
TIMEOUT = 25


def _require_config():
    missing = [n for n, v in [("SERVICENOW_INSTANCE_URL", INSTANCE_URL), ("SERVICENOW_USER", USER), ("SERVICENOW_PASSWORD", PASSWORD)] if not v]
    if missing:
        raise RuntimeError(f"ServiceNow connector is not configured. Missing env var(s): {', '.join(missing)}")


def _auth():
    return (USER, PASSWORD)


@mcp.tool()
def get_record(table: str, sys_id: str) -> dict:
    """Fetch a single ServiceNow record by table name and sys_id.

    Common tables: 'change_request', 'incident', 'problem', 'sn_risk_risk',
    'sn_compliance_policy_statement'. Returns the raw field set trimmed to
    the most relevant fields (number, short_description, description, state,
    priority, assignment_group).
    """
    _require_config()
    url = f"{INSTANCE_URL}/api/now/table/{table}/{sys_id}"
    r = requests.get(url, auth=_auth(), headers={"Accept": "application/json"}, timeout=TIMEOUT)
    r.raise_for_status()
    result = r.json().get("result", {})
    return {
        "table": table,
        "sys_id": result.get("sys_id"),
        "number": result.get("number"),
        "short_description": result.get("short_description"),
        "description": result.get("description"),
        "state": result.get("state"),
        "priority": result.get("priority"),
        "assignment_group": result.get("assignment_group"),
    }


@mcp.tool()
def search_table(table: str, query: str, max_results: int = 20) -> list:
    """Search a ServiceNow table using an encoded query string (sysparm_query syntax).

    Example query: 'short_descriptionLIKEpayment^ORDERBYDESCsys_created_on'.
    Use this to find prior incidents/changes related to the system being
    threat modeled -- real incident history is strong evidence for the
    Likelihood score of a threat.
    """
    _require_config()
    url = f"{INSTANCE_URL}/api/now/table/{table}"
    params = {"sysparm_query": query, "sysparm_limit": max_results, "sysparm_fields": "sys_id,number,short_description,state,priority,sys_created_on"}
    r = requests.get(url, auth=_auth(), params=params, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json().get("result", [])


@mcp.tool()
def get_compliance_gaps(policy_query: str = "compliance_status=partially_compliant", max_results: int = 50) -> list:
    """Fetch compliance/control records flagged as partially or non-compliant.

    Targets tables like 'sn_compliance_policy_statement' or
    'sn_grc_compliance_result' depending on the GRC module in use -- adjust
    policy_query to match the instance's actual field/table names. Use this
    to seed the 'Compensating Controls & Gap Recommendations' section of the
    threat model report with real, tracked compliance gaps rather than only
    inferred ones.
    """
    _require_config()
    return search_table("sn_compliance_policy_statement", policy_query, max_results)


if __name__ == "__main__":
    mcp.run()
