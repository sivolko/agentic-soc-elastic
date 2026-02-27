# Agentic SOC on Elastic — Vectorized Playbooks + MCP + Claude Agent

> *"Because detection without response is just expensive logging."*

**#ElasticBlogathon — Security Track**

A fully autonomous Security Operations Center (SOC) agent built on Elastic Security, ELSER vector search, and Claude via the Model Context Protocol (MCP). When a SIEM alert fires at 3:47 AM, this system retrieves the right playbook by semantic similarity and executes the response automatically — in under 3 minutes, without waking anyone up.

---

## 📖 Full Blog Post

**[The Alert That Nobody Actioned — Until I Built This on Elastic →](https://medium.com/YOUR_LINK_HERE)**

---

## 🏗️ Architecture


```
Elastic Agent / Beats / Cloud APIs
        │
        ▼
Elasticsearch 8.x  ←──────────────────────────────────┐
  ├── logs-endpoint.*   (telemetry)                    │
  ├── .alerts-security  (SIEM alerts)                  │
  ├── soc_playbooks     (dense_vector + ELSER sparse)  │ feedback
  └── soc_agent_log     (execution audit trail)        │
        │                                              │
        ▼  alert stream                                │
MCP SERVER (01_mcp_server.py)                          │
  9 tools: search_alerts · retrieve_playbook ★         │
           execute_action · create_case · isolate_host │
        │                                              │
        ▼  tool calls                                  │
CLAUDE AGENT (02_autonomous_agent.py)                  │
  1. Poll alerts                                       │
  2. kNN + ELSER + RRF playbook retrieval              │
  3. Gather evidence                                   │
  4. Decide + Act (confidence-gated)                   │
  5. Create Case + update stats ─────────────────────►─┘
```

---

## ⚡ Quickstart

### Prerequisites
- Python 3.10+
- [Elastic Cloud](https://cloud.elastic.co) trial account (free 14 days)
- [Anthropic API key](https://console.anthropic.com)

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/agentic-soc-elastic.git
cd agentic-soc-elastic
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Fill in ELASTIC_CLOUD_URL, ELASTIC_API_KEY, KIBANA_URL, ANTHROPIC_API_KEY
```

### 3. Run Lab Setup

```bash
# Creates indices, injects 67 synthetic attack events,
# seeds 3 vectorized playbooks, creates 3 realistic alerts
python lab/00_lab_setup.py
```

### 4. Test MCP Server

```bash
# Tests all 9 tools standalone — no MCP client needed
python lab/01_mcp_server.py --test
```

### 5. Run Autonomous Agent

```bash
# Full agentic loop: alert → playbook → evidence → action → case
python lab/02_autonomous_agent.py
```

---

## 🔌 MCP — Wire to Claude Desktop

Copy `lab/mcp_config.json` contents (fill in your paths) to:

- **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

Restart Claude Desktop. Then type:

> *"Search for high severity open security alerts and run the full investigation and response for each one."*

Watch Claude call all 9 MCP tools autonomously.

---

## 📁 Project Structure

```
├── lab/
│   ├── 00_lab_setup.py          # Elasticsearch indices + synthetic attack data
│   ├── 01_mcp_server.py         # MCP server — 9 Elastic Security tools
│   ├── 02_autonomous_agent.py   # Autonomous Claude agent execution loop
│   └── mcp_config.json          # Claude Desktop MCP configuration
│
├── kibana/
│   └── dashboard.ndjson         # Import: Kibana → Saved Objects → Import
│
├── diagrams/
│   ├── architecture-v2.html     # Full system architecture (interactive SVG)
│   └── playbook-flow-v2.html    # PB-001 execution flow diagram
│
├── .env.example                 # Environment variables template
└── requirements.txt             # Python dependencies
```

---

## 🔬 Attack Scenarios (Lab Data)

Three realistic attack scenarios are pre-loaded by `00_lab_setup.py`:

| Scenario | MITRE | Severity | Playbook |
|---|---|---|---|
| Impossible Travel — `jsmith` from RU/UK | T1078 | HIGH | PB-001 |
| LOLBin — Word → CertUtil → C2 Beacon | T1140, T1218 | CRITICAL | PB-002 |
| Brute Force → CI/CD Pipeline Hijack | T1110 | HIGH | PB-003 |

---

## 🧰 MCP Tools Reference

| Tool | Description |
|---|---|
| `search_alerts` | Poll `.alerts-security` index for open alerts |
| `get_alert_detail` | Full alert context by ID |
| `query_evidence` | Elasticsearch query for investigation |
| `retrieve_playbook` ★ | kNN + ELSER + RRF semantic playbook search |
| `execute_action` | Confidence-gated response action dispatch |
| `create_case` | Kibana Cases API — create IR case |
| `update_alert_status` | Acknowledge / close / escalate alert |
| `log_agent_step` | Write execution step to `soc_agent_log` |
| `get_asset_profile` | User/host criticality from asset inventory |

---

## 📊 Results (90-Day Pilot)

| Metric | Before | After | Δ |
|---|---|---|---|
| Mean Time to Respond | 4h 22m | 2m 57s | ↓ 98.9% |
| Alert coverage | 11% | 94% | ↑ 83pts |
| Analyst toil | 6.5h/shift | 0.8h/shift | ↓ 88% |
| Escalations to human | 100% | 6% | ↓ 94% |

---

## ⚙️ Environment Variables

| Variable | Description |
|---|---|
| `ELASTIC_CLOUD_URL` | Elasticsearch endpoint (`:9243`) |
| `ELASTIC_API_KEY` | Base64 encoded API key from Kibana |
| `KIBANA_URL` | Kibana endpoint (`:9243`) |
| `ANTHROPIC_API_KEY` | From console.anthropic.com |
| `DEMO_MODE` | `true` = log actions without executing (safe for demo) |
| `ALERT_INDEX` | `soc-lab-alerts` (lab) or `.alerts-security.alerts-default` (prod) |

---

## 🔒 Security Notes

- `DEMO_MODE=true` by default — no real IdP or EDR calls are made
- Set `DEMO_MODE=false` only when connected to real identity provider and EDR APIs
- Never commit `.env` — it is in `.gitignore`
- Confidence gate (`< 0.70`) prevents autonomous execution of uncertain actions
- Irreversible actions (permanent deletion, cert revocation) always escalate to human

---

## 📜 License

MIT — free to use, adapt, and build on.

---

*Built for #ElasticBlogathon · Security Track · Elastic 8.x · Python 3.10+ · ELSER · MCP*