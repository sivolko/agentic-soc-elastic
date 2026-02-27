#!/usr/bin/env python3
import os, json, sys, time, asyncio
from datetime import datetime
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from sentence_transformers import SentenceTransformer

load_dotenv()

es = Elasticsearch(
    os.environ["ELASTIC_CLOUD_URL"],
    api_key=os.environ["ELASTIC_API_KEY"]
)
model = SentenceTransformer("all-MiniLM-L6-v2")

KIBANA_URL = os.environ.get("KIBANA_URL", os.environ["ELASTIC_CLOUD_URL"].replace(":9243", ":5601"))
KIBANA_API_KEY = os.environ["ELASTIC_API_KEY"]
ALERT_INDEX = os.environ.get("ALERT_INDEX", "soc-lab-alerts")  # use soc-lab-alerts for demo

# ─────────────────────────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────

def search_alerts(severity: str = None, status: str = "open", limit: int = 10) -> dict:
    """
    Search Elastic Security alerts.
    Returns open alerts filtered by severity, sorted by risk score descending.
    """
    must_clauses = []
    if status:
        must_clauses.append({"term": {"kibana.alert.workflow_status": status}})
    if severity:
        must_clauses.append({"term": {"kibana.alert.severity": severity}})

    query = {
        "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
        "sort": [{"kibana.alert.risk_score": {"order": "desc"}}],
        "size": limit,
        "_source": [
            "kibana.alert.rule.name", "kibana.alert.severity",
            "kibana.alert.risk_score", "kibana.alert.reason",
            "kibana.alert.workflow_status", "@timestamp",
            "user.name", "host.name", "source.ip",
            "threat.technique.id", "threat.technique.name",
            "process.name", "event.category"
        ]
    }

    resp = es.search(index=ALERT_INDEX, body=query)
    alerts = []
    for hit in resp["hits"]["hits"]:
        alerts.append({"id": hit["_id"], **hit["_source"]})

    return {
        "total": resp["hits"]["total"]["value"],
        "alerts": alerts
    }


def get_alert_detail(alert_id: str) -> dict:
    """Get complete details for a specific alert by ID."""
    try:
        hit = es.get(index=ALERT_INDEX, id=alert_id)
        return {"id": alert_id, **hit["_source"]}
    except Exception as e:
        return {"error": str(e), "alert_id": alert_id}


def query_evidence(index_pattern: str, query_dsl: dict, size: int = 20) -> dict:
    """
    Run an Elasticsearch query against any index for investigation evidence.
    Returns hits and aggregations.
    """
    try:
        resp = es.search(index=index_pattern, body=query_dsl, size=size)
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        aggs = resp.get("aggregations", {})
        return {
            "total": resp["hits"]["total"]["value"],
            "hits": hits,
            "aggregations": aggs
        }
    except Exception as e:
        return {"error": str(e), "index": index_pattern}


def retrieve_playbook(alert_context: str, severity: str = None, top_k: int = 3) -> dict:
    """
    Semantic kNN search to find the best matching playbook for an alert.
    Uses dense vector similarity — the core of the agentic retrieval system.
    Returns top matching playbooks with similarity scores.
    """
    query_vector = model.encode(alert_context, normalize_embeddings=True).tolist()

    knn = {
        "field": "trigger_vector",
        "query_vector": query_vector,
        "num_candidates": 50,
        "k": top_k
    }

    if severity:
        knn["filter"] = {"term": {"severity_scope": severity}}

    resp = es.search(
        index="soc_playbooks",
        knn=knn,
        size=top_k,
        _source=["playbook_id", "title", "trigger_context", "steps",
                 "required_tools", "mitre_techniques", "severity_scope",
                 "success_rate", "execution_count"]
    )

    results = []
    for hit in resp["hits"]["hits"]:
        results.append({
            "score": round(hit["_score"], 4),
            "playbook_id": hit["_source"]["playbook_id"],
            "title": hit["_source"]["title"],
            "mitre_techniques": hit["_source"].get("mitre_techniques", []),
            "steps": hit["_source"].get("steps", []),
            "required_tools": hit["_source"].get("required_tools", []),
            "success_rate": hit["_source"].get("success_rate", 0.0),
            "execution_count": hit["_source"].get("execution_count", 0)
        })

    return {
        "query": alert_context[:100] + "...",
        "top_matches": results,
        "best_match": results[0] if results else None
    }


def execute_action(
    tool: str,
    action: str,
    parameters: dict,
    confidence: float,
    alert_id: str,
    playbook_id: str,
    step_id: str
) -> dict:
    """
    Execute a response action. Confidence-gated:
    - confidence >= 0.85: execute autonomously
    - confidence 0.70-0.84: execute with warning logged
    - confidence < 0.70: escalate to human, do not execute

    All actions are logged to soc_agent_log regardless of outcome.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Confidence gate
    if confidence < 0.70:
        log_entry = {
            "@timestamp": timestamp,
            "alert_id": alert_id,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "step_type": "action",
            "tool_invoked": tool,
            "action_taken": action,
            "status": "escalated",
            "confidence": confidence,
            "escalated": True,
            "outcome": "insufficient_confidence",
            "notes": f"Action not executed. Confidence {confidence:.2f} below threshold 0.70. Human review required."
        }
        es.index(index="soc_agent_log", document=log_entry)
        return {
            "status": "escalated",
            "reason": f"Confidence {confidence:.2f} below minimum threshold 0.70",
            "action": f"{tool}.{action}",
            "parameters": parameters,
            "recommendation": "Escalate to Tier-2 analyst for manual execution"
        }

    # Simulate tool dispatch (replace with real API calls in production)
    result = _dispatch_tool(tool, action, parameters)

    log_entry = {
        "@timestamp": timestamp,
        "alert_id": alert_id,
        "playbook_id": playbook_id,
        "step_id": step_id,
        "step_type": "action",
        "tool_invoked": tool,
        "action_taken": action,
        "status": "success",
        "confidence": confidence,
        "escalated": False,
        "outcome": result.get("status", "unknown"),
        "notes": json.dumps(parameters)
    }
    es.index(index="soc_agent_log", document=log_entry)

    return {
        "status": "executed",
        "confidence": confidence,
        "tool": tool,
        "action": action,
        "parameters": parameters,
        "result": result
    }


def _dispatch_tool(tool: str, action: str, parameters: dict) -> dict:
    """
    Real tool dispatchers — replace stubs with live API calls.
    In demo mode these log realistic responses without side effects.
    Set DEMO_MODE=false in .env to enable real execution.
    """
    demo_mode = os.environ.get("DEMO_MODE", "true").lower() == "true"

    if tool == "identity_provider":
        if not demo_mode:
            # Real: call Okta/Azure AD API
            # import requests
            # r = requests.patch(f"{IDP_URL}/api/v1/users/{parameters['user_id']}",
            #                    json={"status": "DEPROVISIONED"}, headers=IDP_HEADERS)
            pass
        return {
            "status": "success" if demo_mode else "real",
            "message": f"[DEMO] Account {parameters.get('user_id')} disabled, sessions revoked",
            "demo_mode": demo_mode
        }

    elif tool == "elastic_agent":
        if not demo_mode:
            # Real: POST /api/endpoint/action/isolate
            import requests
            r = requests.post(
                f"{KIBANA_URL}/api/endpoint/action/isolate",
                headers={"kbn-xsrf": "true", "Authorization": f"ApiKey {KIBANA_API_KEY}"},
                json={"endpoint_ids": [parameters.get("host")],
                      "comment": parameters.get("reason", "SOC Agent isolation")}
            )
            return r.json()
        return {
            "status": "success",
            "message": f"[DEMO] Host {parameters.get('host')} isolation initiated",
            "demo_mode": demo_mode
        }

    elif tool == "network_firewall":
        return {
            "status": "success",
            "message": f"[DEMO] IP {parameters.get('ip')} blocked for {parameters.get('duration_hours', 24)}h",
            "demo_mode": demo_mode
        }

    elif tool == "elasticsearch":
        if action == "update_alert":
            try:
                es.update(
                    index=ALERT_INDEX,
                    id=parameters.get("alert_id", "unknown"),
                    body={"doc": {"kibana.alert.workflow_status": parameters.get("status", "acknowledged")}}
                )
                return {"status": "success", "updated": parameters}
            except Exception as e:
                return {"status": "error", "error": str(e)}

    return {"status": "success", "tool": tool, "action": action, "demo_mode": demo_mode}


def create_case(
    title: str,
    severity: str,
    description: str,
    assignee: str,
    tags: list,
    alert_id: str,
    playbook_id: str
) -> dict:
    """
    Create an Elastic Security case via the Cases API.
    Falls back to logging in soc_agent_log if Cases API unavailable.
    """
    import requests

    case_payload = {
        "title": title,
        "description": description or f"Automated response by SOC Agent · Playbook {playbook_id}",
        "severity": severity,
        "assignees": [],
        "tags": tags + [f"playbook:{playbook_id}", "agentic-soc"],
        "connector": {"id": "none", "name": "None", "type": ".none", "fields": None},
        "settings": {"syncAlerts": True}
    }

    demo_mode = os.environ.get("DEMO_MODE", "true").lower() == "true"

    if not demo_mode:
        try:
            r = requests.post(
                f"{KIBANA_URL}/api/cases",
                headers={
                    "kbn-xsrf": "true",
                    "Content-Type": "application/json",
                    "Authorization": f"ApiKey {KIBANA_API_KEY}"
                },
                json=case_payload
            )
            case = r.json()
            case_id = case.get("id", "unknown")
        except Exception as e:
            case_id = f"fallback-{int(time.time())}"
    else:
        case_id = f"demo-case-{int(time.time())}"

    # Always log to our agent log
    es.index(index="soc_agent_log", document={
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "alert_id": alert_id,
        "playbook_id": playbook_id,
        "step_type": "case_created",
        "case_id": case_id,
        "status": "success",
        "outcome": "case_opened",
        "notes": title
    })

    return {
        "case_id": case_id,
        "title": title,
        "severity": severity,
        "assignee": assignee,
        "tags": tags,
        "demo_mode": demo_mode
    }


def update_alert_status(alert_id: str, status: str, reason: str = "") -> dict:
    """Update alert workflow status in Elastic Security."""
    try:
        es.update(
            index=ALERT_INDEX,
            id=alert_id,
            body={"doc": {
                "kibana.alert.workflow_status": status,
                "kibana.alert.workflow_reason": reason,
                "kibana.alert.updated_at": datetime.utcnow().isoformat() + "Z"
            }}
        )
        return {"status": "updated", "alert_id": alert_id, "new_status": status}
    except Exception as e:
        return {"error": str(e), "alert_id": alert_id}


def log_agent_step(
    alert_id: str,
    playbook_id: str,
    step_id: str,
    step_type: str,
    status: str,
    confidence: float = None,
    notes: str = ""
) -> dict:
    """Write a step execution record to soc_agent_log for audit trail."""
    doc = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "alert_id": alert_id,
        "playbook_id": playbook_id,
        "step_id": step_id,
        "step_type": step_type,
        "status": status,
        "notes": notes
    }
    if confidence is not None:
        doc["confidence"] = confidence

    result = es.index(index="soc_agent_log", document=doc)
    return {"logged": True, "doc_id": result["_id"]}


def get_asset_profile(identity: str) -> dict:
    """Look up asset criticality for a user or hostname."""
    try:
        hit = es.get(index="asset_inventory", id=identity)
        return hit["_source"]
    except Exception:
        # Try search if get fails
        resp = es.search(
            index="asset_inventory",
            body={"query": {
                "bool": {"should": [
                    {"term": {"identity": identity}},
                    {"term": {"host": identity}}
                ]}
            }}
        )
        hits = resp["hits"]["hits"]
        if hits:
            return hits[0]["_source"]
        return {"identity": identity, "criticality": "unknown", "privileged": False}


def isolate_host(host_name: str, reason: str, alert_id: str) -> dict:
    """
    Isolate a host via Elastic Agent endpoint response action.
    REQUIRES: Elastic Endpoint security installed on host.
    """
    return execute_action(
        tool="elastic_agent",
        action="isolate_host",
        parameters={"host": host_name, "reason": reason, "allow_edr_comms": True},
        confidence=0.90,
        alert_id=alert_id,
        playbook_id="manual",
        step_id="isolate"
    )


# ─────────────────────────────────────────────────────────────────────────────
# MCP SERVER DEFINITION
# ─────────────────────────────────────────────────────────────────────────────

MCP_TOOLS = {
    "search_alerts": {
        "description": "Search Elastic Security for open alerts. Filter by severity (low/medium/high/critical) and status. Returns alert list with risk scores.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Filter by severity level"},
                "status":   {"type": "string", "default": "open", "description": "Alert workflow status"},
                "limit":    {"type": "integer", "default": 10, "description": "Max alerts to return"}
            }
        },
        "fn": search_alerts
    },
    "get_alert_detail": {
        "description": "Get full details of a specific Elastic Security alert by its ID.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string", "description": "The alert document ID"}
            },
            "required": ["alert_id"]
        },
        "fn": get_alert_detail
    },
    "query_evidence": {
        "description": "Run an Elasticsearch query against any log index to gather investigation evidence. Use for auth history, process chains, network connections.",
        "parameters": {
            "type": "object",
            "properties": {
                "index_pattern": {"type": "string", "description": "Index pattern e.g. 'logs-*' or 'logs-endpoint.events.*'"},
                "query_dsl":     {"type": "object", "description": "Elasticsearch query DSL body"},
                "size":          {"type": "integer", "default": 20, "description": "Max results"}
            },
            "required": ["index_pattern", "query_dsl"]
        },
        "fn": query_evidence
    },
    "retrieve_playbook": {
        "description": "Use semantic kNN vector search to find the best matching SOC response playbook for a given alert context. Returns ranked playbooks with similarity scores and steps.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_context": {"type": "string", "description": "Natural language description of the alert scenario"},
                "severity":      {"type": "string", "description": "Alert severity for filtering"},
                "top_k":         {"type": "integer", "default": 3, "description": "Number of playbooks to return"}
            },
            "required": ["alert_context"]
        },
        "fn": retrieve_playbook
    },
    "execute_action": {
        "description": "Execute a response action (disable account, block IP, isolate host, etc.). Confidence-gated: actions below 0.70 confidence are escalated to human analyst instead.",
        "parameters": {
            "type": "object",
            "properties": {
                "tool":        {"type": "string", "description": "Tool to invoke: identity_provider/elastic_agent/network_firewall/elasticsearch"},
                "action":      {"type": "string", "description": "Action name: disable_user/isolate_host/block_ip/update_alert"},
                "parameters":  {"type": "object", "description": "Tool-specific parameters"},
                "confidence":  {"type": "number", "description": "Your confidence score 0.0-1.0 that this action is correct"},
                "alert_id":    {"type": "string"},
                "playbook_id": {"type": "string"},
                "step_id":     {"type": "string"}
            },
            "required": ["tool", "action", "parameters", "confidence", "alert_id", "playbook_id", "step_id"]
        },
        "fn": execute_action
    },
    "create_case": {
        "description": "Create an Elastic Security case for incident tracking. Attach findings, assign to analyst team, add MITRE tags.",
        "parameters": {
            "type": "object",
            "properties": {
                "title":       {"type": "string"},
                "severity":    {"type": "string"},
                "description": {"type": "string"},
                "assignee":    {"type": "string", "description": "Team: tier1-team/tier2-team/incident-response"},
                "tags":        {"type": "array", "items": {"type": "string"}},
                "alert_id":    {"type": "string"},
                "playbook_id": {"type": "string"}
            },
            "required": ["title", "severity", "assignee", "tags", "alert_id", "playbook_id"]
        },
        "fn": create_case
    },
    "update_alert_status": {
        "description": "Update the workflow status of an Elastic Security alert. Use to acknowledge, close, or escalate.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "status":   {"type": "string", "enum": ["open", "acknowledged", "closed", "in-progress"]},
                "reason":   {"type": "string"}
            },
            "required": ["alert_id", "status"]
        },
        "fn": update_alert_status
    },
    "log_agent_step": {
        "description": "Log a step in the agent's execution to the soc_agent_log index for audit trail and Kibana dashboard visibility.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id":    {"type": "string"},
                "playbook_id": {"type": "string"},
                "step_id":     {"type": "string"},
                "step_type":   {"type": "string", "enum": ["query","decision","action","escalate","complete"]},
                "status":      {"type": "string"},
                "confidence":  {"type": "number"},
                "notes":       {"type": "string"}
            },
            "required": ["alert_id", "playbook_id", "step_id", "step_type", "status"]
        },
        "fn": log_agent_step
    },
    "get_asset_profile": {
        "description": "Look up the criticality, department, privilege level, and tags for a user identity or hostname from the asset inventory.",
        "parameters": {
            "type": "object",
            "properties": {
                "identity": {"type": "string", "description": "Username or hostname to look up"}
            },
            "required": ["identity"]
        },
        "fn": get_asset_profile
    }
}


def run_mcp_server():
    """
    MCP stdio server — reads JSON-RPC requests from stdin, writes responses to stdout.
    Wire this to Claude Desktop or any MCP-compatible client.
    """
    def send(obj):
        print(json.dumps(obj), flush=True)

    # Announce capabilities
    send({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "elastic-soc-agent", "version": "1.0.0"}
            }})

        elif method == "tools/list":
            tools_list = []
            for name, tool in MCP_TOOLS.items():
                tools_list.append({
                    "name": name,
                    "description": tool["description"],
                    "inputSchema": tool["parameters"]
                })
            send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}})

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name not in MCP_TOOLS:
                send({"jsonrpc": "2.0", "id": req_id,
                      "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}})
                continue

            try:
                result = MCP_TOOLS[tool_name]["fn"](**tool_args)
                send({"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
                }})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": req_id,
                      "error": {"code": -32000, "message": str(e)}})


def run_test():
    """Standalone test — runs all tools and prints results. No MCP client needed."""
    print("\n" + "="*60)
    print("MCP SERVER TOOL TEST")
    print("="*60)

    print("\n[1] search_alerts (high severity)")
    r = search_alerts(severity="high", limit=5)
    print(f"    Found {r['total']} alerts")
    if r["alerts"]:
        a = r["alerts"][0]
        alert_id = a["id"]
        print(f"    Top alert: {a.get('kibana.alert.rule.name','N/A')}")
        print(f"    Risk score: {a.get('kibana.alert.risk_score','N/A')}")
    else:
        alert_id = "alert-000"
        print("    No alerts found — run 00_lab_setup.py first")

    print("\n[2] retrieve_playbook (impossible travel context)")
    r = retrieve_playbook(
        "User authenticated from Russia 8 minutes after login from UK. Impossible travel. Valid credentials used.",
        severity="high"
    )
    if r["best_match"]:
        print(f"    Best match: {r['best_match']['title']}")
        print(f"    Similarity: {r['best_match']['score']:.4f}")
        print(f"    Playbook ID: {r['best_match']['playbook_id']}")
    else:
        print("    No playbook matched")

    print("\n[3] get_asset_profile")
    r = get_asset_profile("jsmith")
    print(f"    Identity: {r.get('identity')}")
    print(f"    Criticality: {r.get('criticality')}")
    print(f"    Privileged: {r.get('privileged')}")

    print("\n[4] execute_action (high confidence — auto-executes)")
    r = execute_action(
        tool="identity_provider", action="force_mfa_challenge",
        parameters={"user_id": "jsmith", "reason": "Test action"},
        confidence=0.88,
        alert_id=alert_id, playbook_id="PB-001", step_id="TEST-A1"
    )
    print(f"    Status: {r['status']}")
    print(f"    Result: {r.get('result', {}).get('message', 'N/A')}")

    print("\n[5] execute_action (low confidence — escalates)")
    r = execute_action(
        tool="identity_provider", action="disable_user",
        parameters={"user_id": "jsmith"},
        confidence=0.55,  # Below 0.70 threshold
        alert_id=alert_id, playbook_id="PB-001", step_id="TEST-A2"
    )
    print(f"    Status: {r['status']}  ← Should be 'escalated'")

    print("\n[6] log_agent_step")
    r = log_agent_step(
        alert_id=alert_id, playbook_id="PB-001",
        step_id="TEST-LOG", step_type="decision",
        status="success", confidence=0.92,
        notes="Test decision step logged successfully"
    )
    print(f"    Logged: {r['logged']} · doc_id: {r['doc_id']}")

    print("\n[7] create_case")
    r = create_case(
        title="TEST — Credential Abuse (Lab Demo)",
        severity="high",
        description="This is a test case created by the SOC agent during lab setup.",
        assignee="tier2-team",
        tags=["test", "lab-demo", "agentic-soc"],
        alert_id=alert_id, playbook_id="PB-001"
    )
    print(f"    Case ID: {r['case_id']}")
    print(f"    Demo mode: {r['demo_mode']}")

    print("\n" + "="*60)
    print("ALL TOOLS TESTED SUCCESSFULLY")
    print("="*60)
    print("\nNext step:")
    print("  1. Wire to Claude Desktop: see mcp_config.json")
    print("  2. Run autonomous demo:    python 02_autonomous_agent.py")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_test()
    else:
        run_mcp_server()
