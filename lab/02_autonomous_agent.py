#!/usr/bin/env python3

import os, sys, json, time, re, argparse
from datetime import datetime
import anthropic
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from sentence_transformers import SentenceTransformer

# Import all tool implementations from MCP server
sys.path.insert(0, os.path.dirname(__file__))
from _01_mcp_server import (
    search_alerts, get_alert_detail, query_evidence,
    retrieve_playbook, execute_action, create_case,
    update_alert_status, log_agent_step, get_asset_profile
)

load_dotenv()

es     = Elasticsearch(os.environ["ELASTIC_CLOUD_URL"], api_key=os.environ["ELASTIC_API_KEY"])
model  = SentenceTransformer("all-MiniLM-L6-v2")
claude = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

TOOL_MAP = {
    "search_alerts":      search_alerts,
    "get_alert_detail":   get_alert_detail,
    "query_evidence":     query_evidence,
    "retrieve_playbook":  retrieve_playbook,
    "execute_action":     execute_action,
    "create_case":        create_case,
    "update_alert_status": update_alert_status,
    "log_agent_step":     log_agent_step,
    "get_asset_profile":  get_asset_profile,
}

# Claude tool definitions (same as MCP but in Anthropic format)
CLAUDE_TOOLS = [
    {
        "name": "search_alerts",
        "description": "Search Elastic Security for open alerts. Returns alerts sorted by risk score.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["low","medium","high","critical"]},
                "status":   {"type": "string", "default": "open"},
                "limit":    {"type": "integer", "default": 10}
            }
        }
    },
    {
        "name": "get_alert_detail",
        "description": "Get complete details of a specific alert by ID.",
        "input_schema": {
            "type": "object",
            "properties": {"alert_id": {"type": "string"}},
            "required": ["alert_id"]
        }
    },
    {
        "name": "query_evidence",
        "description": "Run Elasticsearch query against log indices for investigation evidence. Use for auth history, process chains, network connections, file operations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "index_pattern": {"type": "string"},
                "query_dsl":     {"type": "object"},
                "size":          {"type": "integer", "default": 20}
            },
            "required": ["index_pattern", "query_dsl"]
        }
    },
    {
        "name": "retrieve_playbook",
        "description": "Semantic vector search to find the best matching SOC playbook for an alert. ALWAYS call this before executing any response steps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_context": {"type": "string"},
                "severity":      {"type": "string"},
                "top_k":         {"type": "integer", "default": 3}
            },
            "required": ["alert_context"]
        }
    },
    {
        "name": "execute_action",
        "description": "Execute a response action with confidence gating. Provide your confidence score 0-1. Below 0.70 automatically escalates to human.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool":        {"type": "string"},
                "action":      {"type": "string"},
                "parameters":  {"type": "object"},
                "confidence":  {"type": "number"},
                "alert_id":    {"type": "string"},
                "playbook_id": {"type": "string"},
                "step_id":     {"type": "string"}
            },
            "required": ["tool","action","parameters","confidence","alert_id","playbook_id","step_id"]
        }
    },
    {
        "name": "create_case",
        "description": "Create an Elastic Security case for incident tracking with full context.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title":       {"type": "string"},
                "severity":    {"type": "string"},
                "description": {"type": "string"},
                "assignee":    {"type": "string"},
                "tags":        {"type": "array", "items": {"type": "string"}},
                "alert_id":    {"type": "string"},
                "playbook_id": {"type": "string"}
            },
            "required": ["title","severity","assignee","tags","alert_id","playbook_id"]
        }
    },
    {
        "name": "update_alert_status",
        "description": "Update alert workflow status in Elastic Security (open/acknowledged/closed/in-progress).",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "status":   {"type": "string"},
                "reason":   {"type": "string"}
            },
            "required": ["alert_id","status"]
        }
    },
    {
        "name": "log_agent_step",
        "description": "Log execution step to soc_agent_log for audit trail. Call after EVERY step.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id":    {"type": "string"},
                "playbook_id": {"type": "string"},
                "step_id":     {"type": "string"},
                "step_type":   {"type": "string"},
                "status":      {"type": "string"},
                "confidence":  {"type": "number"},
                "notes":       {"type": "string"}
            },
            "required": ["alert_id","playbook_id","step_id","step_type","status"]
        }
    },
    {
        "name": "get_asset_profile",
        "description": "Look up user/host criticality, privilege level, and department from asset inventory.",
        "input_schema": {
            "type": "object",
            "properties": {"identity": {"type": "string"}},
            "required": ["identity"]
        }
    }
]

SYSTEM_PROMPT = """You are an autonomous SOC (Security Operations Center) agent running inside Elastic Security.

Your mission: For each security alert, investigate it fully and respond according to the appropriate playbook.

## Your Process (FOLLOW THIS EXACTLY):

1. **RETRIEVE PLAYBOOK FIRST** — Always call retrieve_playbook with a description of the alert context before doing anything else. The vector similarity search will find the right response procedure.

2. **GATHER EVIDENCE** — Call query_evidence to build the investigation context. Check auth history, process chains, network connections depending on the alert type.

3. **CHECK ASSET CRITICALITY** — Call get_asset_profile for the affected user/host to calibrate response severity.

4. **DECIDE WITH EVIDENCE** — Based on what you found, determine the appropriate response path from the playbook decision tree. State your confidence score (0.0-1.0).

5. **EXECUTE RESPONSE** — Call execute_action for each response step. Your confidence score determines autonomy:
   - ≥ 0.85: Execute immediately, no escalation
   - 0.70-0.84: Execute with warning logged
   - < 0.70: Action is escalated to human analyst

6. **LOG EVERY STEP** — Call log_agent_step after each major step. This feeds the Kibana dashboard.

7. **CREATE CASE** — Always create an Elastic Security case with full context and assign appropriately.

8. **UPDATE ALERT** — Mark the alert as acknowledged with your case ID.

## Rules:
- NEVER skip retrieve_playbook — it's the core of the vector-based response system
- NEVER take irreversible actions (permanent deletion, certificate revocation) autonomously — escalate these
- Always explain your confidence reasoning before calling execute_action
- Prefer reversible containment (MFA challenge, session revoke) over destructive actions (account disable) when confidence is ambiguous
- Write the final case description as if a Tier-2 analyst will read it cold — include all evidence

## You are talking to a real Elasticsearch cluster with real (lab) data. All tool calls execute immediately."""


def run_agent(alert_id: str = None, dry_run: bool = False):
    """
    Run the autonomous agent against one or all open alerts.
    """
    print("\n" + "█"*60)
    print("  ELASTIC SOC AGENT — AUTONOMOUS RESPONSE ENGINE")
    print("  " + datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
    print("█"*60)

    # Find alerts to process
    if alert_id:
        alert = get_alert_detail(alert_id)
        if "error" in alert:
            print(f"\n✗ Alert {alert_id} not found: {alert['error']}")
            return
        alerts_to_process = [{"id": alert_id, **alert}]
    else:
        result = search_alerts(status="open", limit=5)
        alerts_to_process = result.get("alerts", [])

    if not alerts_to_process:
        print("\n  No open alerts found. Run 00_lab_setup.py to inject lab data.")
        return

    print(f"\n  Found {len(alerts_to_process)} alert(s) to process\n")

    for alert in alerts_to_process[:3]:  # Process max 3 for demo
        _process_single_alert(alert, dry_run)
        print("\n" + "─"*60 + "\n")
        time.sleep(1)


def _process_single_alert(alert: dict, dry_run: bool):
    """
    Run Claude agent on a single alert using the Anthropic tool-use API.
    This is the live agentic loop.
    """
    alert_id   = alert.get("id", "unknown")
    rule_name  = alert.get("kibana.alert.rule.name", "Unknown Rule")
    severity   = alert.get("kibana.alert.severity", "medium")
    reason     = alert.get("kibana.alert.reason", "")

    print(f"\n{'━'*58}")
    print(f"  ALERT: {rule_name}")
    print(f"  ID:    {alert_id}")
    print(f"  SEV:   {severity.upper()}")
    print(f"  WHY:   {reason[:90]}...")
    print(f"{'━'*58}")

    # Initial message to Claude with full alert context
    initial_message = f"""New Elastic Security alert requires autonomous investigation and response.

Alert ID: {alert_id}
Rule: {rule_name}
Severity: {severity}
Reason: {reason}
User: {alert.get('user.name', 'N/A')}
Host: {alert.get('host.name', 'N/A')}
Source IP: {alert.get('source.ip', 'N/A')}
MITRE Technique: {alert.get('threat.technique.id', 'N/A')} — {alert.get('threat.technique.name', 'N/A')}
Event Category: {alert.get('event.category', 'N/A')}
Process: {alert.get('process.name', 'N/A')}

Begin autonomous investigation. Start by retrieving the appropriate playbook."""

    messages = [{"role": "user", "content": initial_message}]
    step_count = 0
    max_steps  = 20  # Prevent infinite loops

    while step_count < max_steps:
        step_count += 1

        print(f"\n  [Agent step {step_count}]", end=" ", flush=True)

        # Call Claude with tools
        response = claude.messages.create(
            model="claude-opus-4-6",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            tools=CLAUDE_TOOLS,
            messages=messages
        )

        # Append assistant response to conversation
        messages.append({"role": "assistant", "content": response.content})

        # Check stop reason
        if response.stop_reason == "end_turn":
            # Agent finished — print final response
            final_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_text = block.text
            print("COMPLETE")
            print(f"\n{'─'*58}")
            print("  AGENT FINAL RESPONSE:")
            print(f"{'─'*58}")
            print(final_text[:800] + ("..." if len(final_text) > 800 else ""))
            break

        if response.stop_reason != "tool_use":
            print(f"Unexpected stop: {response.stop_reason}")
            break

        # Process tool calls
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                if hasattr(block, "text") and block.text:
                    print(f"\n  💭 {block.text[:120]}")
                continue

            tool_name  = block.name
            tool_input = block.input
            tool_id    = block.id

            print(f"→ {tool_name}(", end="")

            # Print key args for visibility
            key_args = []
            for k in ["severity", "alert_id", "alert_context", "tool",
                       "action", "step_id", "status", "identity"]:
                if k in tool_input:
                    v = str(tool_input[k])[:40]
                    key_args.append(f"{k}={v!r}")
            print(", ".join(key_args[:3]) + ")", flush=True)

            # Skip actual execution in dry-run for action steps
            if dry_run and tool_name == "execute_action":
                result = {"status": "dry_run", "message": "Action skipped in dry-run mode"}
            else:
                try:
                    fn = TOOL_MAP.get(tool_name)
                    if fn:
                        result = fn(**tool_input)
                    else:
                        result = {"error": f"Unknown tool: {tool_name}"}
                except Exception as e:
                    result = {"error": str(e)}

            # Print key result info
            if isinstance(result, dict):
                status = result.get("status") or result.get("outcome") or ""
                if result.get("best_match"):
                    pb = result["best_match"]
                    print(f"    ✓ Playbook: {pb['title'][:50]} (score={pb['score']:.3f})")
                elif result.get("total") is not None:
                    print(f"    ✓ {result['total']} results")
                elif status:
                    icon = "✓" if status in ["success","executed","logged","updated"] else "⚠"
                    print(f"    {icon} {status}")
                    if result.get("message"):
                        print(f"      {result['message'][:80]}")
                    if result.get("case_id"):
                        print(f"      Case ID: {result['case_id']}")

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": json.dumps(result)
            })

        # Add tool results to conversation
        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    if step_count >= max_steps:
        print(f"\n  ⚠ Max steps ({max_steps}) reached — escalating to human")


def continuous_loop(interval_seconds: int = 30):
    """Poll for new alerts continuously."""
    print(f"\n  Starting continuous loop (polling every {interval_seconds}s)")
    print("  Press Ctrl+C to stop\n")
    while True:
        run_agent()
        print(f"\n  Next poll in {interval_seconds}s...")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Elastic SOC Autonomous Agent")
    parser.add_argument("--alert-id", help="Specific alert ID to process")
    parser.add_argument("--dry-run",  action="store_true", help="Log but don't execute actions")
    parser.add_argument("--loop",     action="store_true", help="Continuous polling mode")
    args = parser.parse_args()

    if args.loop:
        continuous_loop()
    else:
        run_agent(alert_id=args.alert_id, dry_run=args.dry_run)
