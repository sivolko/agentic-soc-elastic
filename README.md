# Agentic SOC on Elastic — Vectorized Playbooks + MCP + Claude Agent

> *"Because detection without response is just expensive logging."*

**#ElasticBlogathon — Security Track**

A fully autonomous Security Operations Center (SOC) agent built on Elastic Security, ELSER vector search, and Claude via the Model Context Protocol (MCP). When a SIEM alert fires at 3:47 AM, this system retrieves the right playbook by semantic similarity and executes the response automatically — in under 3 minutes, without waking anyone up.

<img width="807" height="1134" alt="image" src="https://github.com/user-attachments/assets/add83657-2466-4fb2-ae15-55b7997efedf" />


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

**Automated Playbook flow**

<img width="3746" height="1696" alt="image" src="https://github.com/user-attachments/assets/b999bd0d-d406-41ed-9306-32699a40243a" />



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

## Output 

<img width="1678" height="1626" alt="image" src="https://github.com/user-attachments/assets/d462e689-2884-4671-b037-1eb43b91ef4e" />

<img width="1682" height="1407" alt="image" src="https://github.com/user-attachments/assets/5fff09ca-8943-44db-9274-dd87ec20f204" />

<img width="1687" height="1033" alt="image" src="https://github.com/user-attachments/assets/28c598ee-4d38-4c8a-8aac-e6f0839fe4d3" />









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

*Built for #ElasticBlogathon · Security Track 
