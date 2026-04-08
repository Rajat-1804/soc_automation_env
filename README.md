# 🛡️ SOC Automation Environment

> **An OpenAI Gym-style reinforcement learning environment for training and evaluating AI-powered Security Operations Center (SOC) analysts.**

[![OpenEnv Compatible](https://img.shields.io/badge/OpenEnv-Compatible-blue)](https://github.com/meta-llama/openenv)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://docker.com)
[![License: BSD](https://img.shields.io/badge/License-BSD-yellow.svg)](LICENSE)

---

## 📋 Overview

The **SOC Automation Environment** simulates a realistic Security Operations Center where an AI agent must triage, investigate, contain, and report on security incidents. The environment features **23 handcrafted scenarios** across 4 difficulty levels, covering real-world attack types and false positives that SOC analysts encounter daily.

Built for the [Meta PyTorch OpenEnv Hackathon](https://openenvhackathon.com), this environment provides a standardized interface for benchmarking LLM-based security agents.

---

## ✨ Key Features

### 🎯 Realistic SOC Workflow
- **4-Phase Incident Response**: Triage → Investigation → Containment → Reporting
- Mirrors real-world SOC analyst workflows with time pressure and investigation budgets

### 📊 23 Handcrafted Scenarios
| Difficulty | Count | Description |
|:----------:|:-----:|:------------|
| 🟢 **EASY** | 5 | Single tool reveals everything — credential stuffing, DNS false positives, AV false alerts |
| 🟡 **MEDIUM** | 6 | 2–3 targeted queries needed — lateral movement, phishing, data exfiltration, malware |
| 🔴 **HARD** | 5 | Multi-vector attacks with red herrings — ransomware staging, Kerberoasting, false positive traps |
| ⚫ **EXPERT** | 7 | APT-style threats with misleading evidence — supply chain attacks, insider threats, zero-day exploits, cloud compromise |

### 🧠 Attack Types Covered
- Credential Stuffing & Brute Force (`T1110`)
- Lateral Movement (`T1021`)
- Privilege Escalation (`T1078`)
- Phishing (`T1566`)
- Ransomware Staging (`T1486`)
- Data Exfiltration (`T1048`, `T1567`)
- Supply Chain Attacks (`T1195`)
- Zero-Day Exploits (`T1190`)
- Insider Threats
- Cloud Compromise (Cryptojacking)
- Kerberoasting (`T1558`)
- Malware / PowerShell Abuse (`T1059`)
- **False Positives** (build jobs, DNS queries, scheduled tasks, vulnerability scanners, ML workloads)

### 🏆 Dense Reward Shaping
- Rewards at every step — not just terminal
- Correct containment: **+0.90** (real threat) / **+0.60** (false positive dismissal)
- Meaningful investigation queries: **+0.45**
- MITRE ATT&CK ID grading: **+0.60** for correct identification
- Penalties for wasted queries, duplicate actions, and blown MTTR targets
- All rewards strictly clamped to `[0.01, 0.99]`

### 🔧 Investigation Tools
| Tool | Purpose | Example Query |
|:-----|:--------|:-------------|
| `logs` | Search system/network logs | IP addresses, hostnames |
| `threat_intel` | Query threat intelligence feeds | IPs, domains, file hashes |
| `asset_inventory` | Look up asset/user information | Usernames, machine names |

### ⏱️ Time Simulation
- Each action consumes simulated time (2–10 minutes)
- MTTR (Mean Time to Respond) penalties when time limits are exceeded
- Real threats escalate if not contained quickly

---

## 🏗️ Architecture

```
soc_automation_env/
├── server/                          # Environment Server
│   ├── app.py                       # FastAPI application (WebSocket + REST)
│   ├── soc_automation_env_environment.py  # Core RL environment logic
│   ├── scenarios.py                 # 23 scenario definitions
│   └── requirements.txt             # Server dependencies
├── inference.py                     # LLM-powered agent (inference script)
├── client.py                        # WebSocket client for env communication
├── models.py                        # Pydantic action/observation models
├── evaluate.py                      # Batch evaluation harness
├── solver.py                        # Baseline solver
├── openenv.yaml                     # OpenEnv configuration
├── pyproject.toml                   # Python project metadata
├── Dockerfile                       # Container deployment
├── test_local.sh                    # Local testing script
└── validate-submission.sh           # Submission validation
```

### Component Diagram

```
┌─────────────────────────────┐      WebSocket       ┌──────────────────────────┐
│       Inference Agent       │ ◄──────────────────► │    Environment Server    │
│                             │    reset() / step()   │                          │
│  ┌───────────────────────┐  │                       │  ┌────────────────────┐  │
│  │   LLM (OpenAI API)   │  │                       │  │  Scenario Engine   │  │
│  │  Qwen / Llama / etc.  │  │                       │  │  23 scenarios      │  │
│  └───────────────────────┘  │                       │  └────────────────────┘  │
│  ┌───────────────────────┐  │                       │  ┌────────────────────┐  │
│  │  SafeEntityDatabase   │  │                       │  │   Reward Shaping   │  │
│  │  ActionGuardrails     │  │   Action / Obs JSON   │  │   Phase Machine    │  │
│  │  EvidenceAnalyzer     │  │                       │  │   MTTR Tracking    │  │
│  └───────────────────────┘  │                       │  └────────────────────┘  │
└─────────────────────────────┘                       └──────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- Docker (for containerized deployment)
- An LLM API endpoint (HuggingFace, OpenAI, Ollama, etc.)

### 1. Clone & Install

```bash
git clone https://github.com/Rajat-1804/soc_automation_env.git
cd soc_automation_env
uv sync
```

### 2. Configure Environment Variables

Create a `.env` file in the project root:

```env
API_BASE_URL=https://router.huggingface.co/v1
MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
HF_TOKEN=your_huggingface_token_here
```

| Variable | Required | Default | Description |
|:---------|:--------:|:--------|:------------|
| `API_BASE_URL` | ✅ | `https://router.huggingface.co/v1` | LLM API endpoint |
| `MODEL_NAME` | ✅ | `Qwen/Qwen2.5-72B-Instruct` | Model identifier |
| `HF_TOKEN` | ✅ | — | HuggingFace / API authentication key |
| `LOCAL_IMAGE_NAME` | ❌ | — | Docker image name (if using `from_docker_image()`) |

### 3. Run the Environment Server

**Option A: Docker (Recommended)**
```bash
docker build -t soc_automation_env:latest .
docker run -p 8000:8000 soc_automation_env:latest
```

**Option B: Direct**
```bash
uv run uvicorn server.app:app --host 0.0.0.0 --port 8000
```

### 4. Run Inference

```bash
uv run python inference.py
```

---

## 📝 Action Space

The agent communicates via JSON actions with the following schema:

### Triage
```json
{"action_type": "triage"}
```

### Investigate
```json
{
  "action_type": "investigate",
  "tool_name": "logs|threat_intel|asset_inventory",
  "tool_query": "<entity from alert>"
}
```

### Contain
```json
{
  "action_type": "contain",
  "containment_action": "block_ip|isolate_machine|password_reset|escalate|dismiss"
}
```

### Report
```json
{
  "action_type": "report",
  "report_text": "<SOC summary>",
  "mitre_id": "<T-code or None>"
}
```

---

## 📊 Observation Space

Each step returns a rich observation:

| Field | Type | Description |
|:------|:-----|:------------|
| `current_phase` | `str` | Current workflow phase: TRIAGE, INVESTIGATION, CONTAINMENT, REPORTING |
| `alert_data` | `str` | The security alert text describing the incident |
| `investigation_results` | `str` | Results from the most recent tool query |
| `remaining_budget` | `int` | Remaining investigation queries (starts at 5) |
| `feedback` | `str` | System feedback, errors, or phase transition messages |
| `difficulty_level` | `int` | Scenario difficulty: 1=EASY, 2=MEDIUM, 3=HARD, 4=EXPERT |
| `investigation_quality` | `float` | Fraction of key evidence discovered (0.0–1.0) |
| `simulated_time_mins` | `int` | Elapsed simulated time since alert |
| `isolated_entities` | `list` | Entities currently isolated/unreachable |
| `done` | `bool` | Whether the episode is complete |
| `reward` | `float` | Step reward in range [0.01, 0.99] |

---

## 🤖 Inference Agent Features

The inference script (`inference.py`) includes several advanced capabilities:

### Safe Entity Database
Pre-built knowledge of known-safe entities (Google DNS, Windows system processes, internal infrastructure) to prevent false-positive containment actions.

### Action Guardrails
Hard constraints that automatically correct obviously wrong decisions:
- Prevents blocking known-safe IPs (e.g., 8.8.8.8)
- Prevents isolating machines running safe processes (e.g., `updates.exe`)
- Ensures `dismiss` actions always have `mitre_id="None"`
- Blocks repeated investigation queries

### Evidence Quality Scoring
Confidence-based analysis of investigation results to determine if more investigation is needed or if the agent should act decisively.

### Adaptive Temperature Selection
Dynamically adjusts LLM temperature based on alert characteristics:
- Known false positives → 0.1 (very decisive)
- Clear attack signals → 0.3 (moderately decisive)
- Ambiguous cases → 0.5 (exploratory)

### Few-Shot Learning
Embedded examples of correct decisions in the prompt to guide the LLM toward high-reward actions.

### Deterministic Fallback
When the LLM is unavailable, a rule-based fallback ensures the agent continues operating with reasonable decisions.

---

## 📤 STDOUT Format

The inference script emits **exactly three line types** to stdout:

```
============================================================
Running scenario: soc_incident_response
============================================================
[START] task=soc_incident_response env=soc_automation_env model=Qwen/Qwen2.5-72B-Instruct
[STEP]  step=1 action={"action_type": "triage"} reward=0.46 done=false error=null
[STEP]  step=2 action={"action_type": "investigate", ...} reward=0.50 done=false error=null
[STEP]  step=3 action={"action_type": "contain", ...} reward=0.95 done=false error=null
[STEP]  step=4 action={"action_type": "report", ...} reward=0.65 done=true error=null
[END]   success=true steps=4 score=0.6400 rewards=0.4600,0.5000,0.9500,0.6500
```

All debug, guardrail, and diagnostic output is sent to **stderr** to keep stdout clean for validator parsing.

---

## 🧪 Testing & Evaluation

### Local Test
```bash
bash test_local.sh
```

### Full Evaluation
```bash
uv run python evaluate.py
```

### Validate Submission
```bash
uv run openenv validate
```

### Push to HuggingFace
```bash
export HF_TOKEN=your_token
uv run openenv push --repo-id your-username/soc_automation_env
```

---

## 🐳 Docker Deployment

```bash
# Build
docker build -t soc_automation_env:latest .

# Run
docker run -p 8000:8000 soc_automation_env:latest

# Health check
curl http://localhost:8000/health
```

---

## 🏅 Reward Structure Summary

```
┌──────────────────────────────────────────────────────────────┐
│                      REWARD BREAKDOWN                        │
├──────────────────────────────┬───────────────────────────────┤
│ Action                       │ Reward                        │
├──────────────────────────────┼───────────────────────────────┤
│ Correct containment (threat) │ +0.90                         │
│ Correct dismissal (FP)       │ +0.60                         │
│ Correct MITRE ID report      │ +0.60                         │
│ Meaningful investigation     │ +0.45                         │
│ Triage step                  │ +0.40                         │
│ Wasted query                 │ +0.35                         │
│ Sub-optimal containment      │ +0.20                         │
│ Wrong MITRE ID               │ +0.10                         │
│ Dismissed real threat         │ +0.10                         │
│ Contained false positive     │ +0.10                         │
│ Duplicate action penalty     │ −0.10                         │
│ MTTR exceeded penalty        │ −0.10                         │
│ Invalid action               │ +0.01                         │
└──────────────────────────────┴───────────────────────────────┘
All rewards clamped to [0.01, 0.99] before returning.
```

---

## 📁 MITRE ATT&CK Coverage

| Technique ID | Name | Scenarios |
|:-------------|:-----|:----------|
| T1110 | Brute Force | Credential stuffing |
| T1190 | Exploit Public-Facing App | External scanning, Zero-day |
| T1021 | Remote Services | Lateral movement via SMB |
| T1078 | Valid Accounts | Privilege escalation, Cloud compromise |
| T1566 | Phishing | Email phishing with credential harvest |
| T1486 | Data Encrypted for Impact | Ransomware staging |
| T1048 | Exfiltration Over Alternative Protocol | Data exfiltration |
| T1567 | Exfiltration to Cloud Storage | Upload to external cloud |
| T1059 | Command and Scripting Interpreter | PowerShell malware |
| T1195 | Supply Chain Compromise | Vendor library tampering, CI/CD |
| T1558 | Steal or Forge Kerberos Tickets | Kerberoasting |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-scenario`
3. Add scenarios to `server/scenarios.py`
4. Test locally with `bash test_local.sh`
5. Submit a pull request

---

## 📜 License

This project is licensed under the BSD License. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Meta PyTorch OpenEnv](https://github.com/meta-llama/openenv) — Framework and hackathon platform
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat taxonomy
- [HuggingFace](https://huggingface.co/) — Model hosting and inference API

---

<p align="center">
  <strong>Built with ❤️ for the Meta PyTorch OpenEnv Hackathon 2026</strong>
</p>
