# A2IDS — AI-Powered Network Intrusion Detection & Prevention System

> **Autonomous, evidence-driven NIDS/IPS** that captures live packets, extracts flow features, classifies threats with ML, and enforces OS-level firewall blocks in real time — all through a modern SOC-style web dashboard.

---

## 📌 Overview

**A2IDS** (Autonomous AI Intrusion Detection System) is a full-stack cybersecurity application that monitors network traffic and autonomously identifies and blocks malicious activity using a hybrid of deterministic rule-based detection and supervised machine learning.

The system operates directly at the OS packet filter level (macOS PF / Linux nftables / Windows Defender Firewall), combining a Scapy-powered packet sniffer, a CICIDS-compatible bidirectional flow engine, a Random Forest + Isolation Forest ML pipeline, a strict three-tier safety controller, and a Google Gemini-powered AI Security Copilot — all exposed through a real-time Flask REST API and a dark SOC dashboard UI.

---

## ⚙️ How It Works

The system follows a layered, event-driven pipeline:

### 1. 📡 Packet Capture (`sniffer.py`)
- Captures live packets from any network interface using **Scapy**
- Decodes IPv4, IPv6, TCP, UDP, ICMP, DNS, and ARP headers
- Discovers interfaces via `psutil`
- Exports captures as PCAP files
- Streams packets in real time to the flow engine via callbacks

### 2. 🔄 Flow Aggregation (`flow_engine.py`)
- Groups raw packets into canonical **bidirectional 5-tuple flows**
- Extracts **17 CICIDS2017-compatible features** per flow:
  `flow_duration`, `total_fwd_pkts`, `total_bwd_pkts`, `pkt_len_mean`, `pkt_len_std`, `syn_flag_count`, `flow_pkts_per_sec`, `flow_iat_mean`, and more
- Expires idle/active flows and passes them to the detection engine

### 3. 🤖 ML Detection Pipeline (`model.py`, `train_model.py`)
- **Random Forest Classifier** (100 trees, RobustScaler) — supervised multi-class threat classification
- **Isolation Forest** — unsupervised anomaly detection for zero-day-style traffic
- Trained on a 4,000-sample benchmark dataset modelled after CICIDS2017 & UNSW-NB15
- Classifies traffic into: `BENIGN`, `SYN_FLOOD`, `PORT_SCAN`, `GENERIC_MALICIOUS`
- Model artifacts saved to `model/ids_model.pkl`

### 4. 🛡️ Hybrid Threat Detection (`detector.py`)
- **Rule-based engine** — sliding-window SYN flood, port scan, UDP/ICMP flood, packet rate spike detection
- **ML inference engine** — passes completed flows through the trained classifier
- Generates structured alert records with severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and confidence scores
- Detections are preserved even for protected IPs (never silently discarded)

### 5. ⚖️ Response Policy Engine (`response_policy.py`)
- Evidence threshold scoring per source IP
- Produces machine-readable `ResponseDecision` dataclasses with explicit reason codes
- Escalates decisions to the Safety Controller

### 6. 🔒 Safety Controller (`safety_controller.py`)
- **Single authoritative enforcement gate** for all block/unblock actions
- Enforces three-tier address protection:
  - **Category A** — Essential (loopback, gateway, DNS) — never blockable
  - **Category B** — Operational (local subnets, DHCP) — protected by default
  - **Category C** — Configurable (user allowlist)
- Rate-limits automated blocking (configurable per minute)
- **Emergency Stop** switch halts all autonomous blocking instantly

### 7. 🧱 Firewall Enforcement (`firewall.py`)
- **macOS**: PF anchor `ai_ids` + `ids_blocked` table via `pfctl`
- **Linux**: `nftables` / `iptables` rules
- **Windows**: Windows Defender Firewall via `netsh`
- Dual-stack IPv4 and IPv6 support
- Active-state verification (`BLOCKED_VERIFIED`) — a block is only declared active after confirmed kernel membership

### 8. 🤖 AI Security Copilot (`ai_assistant.py`)
- Integrates **Google Gemini** (via `GEMINI_API_KEY`) for intelligent threat analysis
- Rich **offline expert fallback** engine for air-gapped deployments
- Explains alerts, recommends block actions, and generates defensive rules
- All recommended actions are routed through the Safety Controller — never executes arbitrary shell commands

### 9. 🖥️ SOC Dashboard (`app.py` + `templates/`)
- Real-time dark SOC-style web UI with Server-Sent Events (SSE) live streaming
- Pages: Dashboard, Live Monitor, Alerts, Flows, Analytics, Firewall, AI Copilot, Reports, Settings
- REST API for all subsystem controls

---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- macOS / Linux (Windows supported with reduced firewall features)
- `sudo` / administrator access required for live packet capture and firewall enforcement

---

### Step 1: Clone the repository
```bash
git clone https://github.com/yashjadhav1812/A2IDS-Intrusion-Detection-System.git
cd "A2IDS Intrusion Detection System"
```

### Step 2: Install dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install flask>=3.0.0 scapy>=2.5.0 scikit-learn>=1.4.0 numpy>=1.26.0 pandas>=2.2.0 psutil>=5.9.0 requests>=2.31.0 cryptography>=42.0.0
```

### Step 3: (Optional) Configure AI Copilot
Set your Gemini API key to enable cloud-powered threat analysis:
```bash
export GEMINI_API_KEY=your_api_key_here
```
The system works fully offline without this key using the built-in expert fallback engine.

### Step 4: (Optional) Retrain the ML model
```bash
python3 train_model.py
```
Generates a fresh 4,000-sample benchmark dataset, trains the classifier, and saves artifacts to `model/`.

### Step 5: Start the packet sniffer
> ⚠️ **Root/admin privileges are required** for raw socket access and live packet capture.

The sniffer must be running **before** or **alongside** the main app for live traffic monitoring to work. Open a separate terminal window and run:

**macOS / Linux:**
```bash
sudo python3 sniffer.py
```

**Windows** (run as Administrator in an elevated Command Prompt or PowerShell):
```powershell
python sniffer.py
```
> 💡 On Windows, [Npcap](https://npcap.com/) must be installed for Scapy to capture packets. Download and install it before running the sniffer.

### Step 6: Run the application
Open another terminal window and run:

**macOS / Linux:**
```bash
sudo python3 app.py
```

**Windows** (run as Administrator):
```powershell
python app.py
```
> ⚠️ Admin privileges are also needed by `app.py` for OS-level firewall rule enforcement (PF on macOS, nftables on Linux, Windows Defender Firewall on Windows).

### Step 7: Open in browser
```
http://127.0.0.1:5000/
```

---

## 📁 Project Structure

```
📁 AI Intrusion Detection System/
│
├── 📁 datasets/                    # Baseline traffic dataset
│   ├── baseline_traffic.csv        # 4,000-sample CICIDS-style benchmark dataset
│   └── README.md                   # Dataset documentation
│
├── 📁 docs/                        # Architecture documentation
│   ├── firewall-architecture.md    # Firewall layer design & PF anchor config
│   └── protected-address-policy.md # Three-tier address protection policy
│
├── 📁 logs/                        # Runtime PCAP capture exports
│   └── *.pcap
│
├── 📁 model/                       # Trained ML model artifacts
│   ├── ids_model.pkl               # Serialized Random Forest + Isolation Forest
│   ├── feature_schema.json         # Feature names, classes, scaler metadata
│   └── metrics.json                # Evaluation metrics (F1, FPR, FNR, latency)
│
├── 📁 static/
│   ├── css/style.css               # Dark SOC dashboard stylesheet
│   └── img/                        # Logo assets
│
├── 📁 templates/                   # Flask Jinja2 HTML templates
│   ├── base.html                   # Base layout with nav
│   ├── index.html                  # Operations dashboard & KPI overview
│   ├── monitor.html                # Live packet sniffer & stream viewer
│   ├── alerts.html                 # Alert management & incident log
│   ├── flows.html                  # Active network flow table
│   ├── analytics.html              # ML model analytics & feature importance
│   ├── analysis.html               # Deep traffic analysis
│   ├── firewall.html               # Firewall block/unblock management
│   ├── assistant.html              # AI Security Copilot chat interface
│   ├── reports.html                # Threat reports & export
│   └── settings.html               # System configuration panel
│
├── address_policy.py               # Three-tier protected address classification
├── ai_assistant.py                 # Google Gemini AI Copilot + offline expert engine
├── app.py                          # Main Flask app — REST API, SSE, prevention policy
├── config.ini                      # System-wide configuration (ports, thresholds, modes)
├── database.py                     # SQLite WAL database — events, alerts, audit log
├── detector.py                     # Hybrid threat detection engine (rules + ML)
├── firewall.py                     # OS-level firewall enforcement (PF / nftables / WDF)
├── flow_engine.py                  # Bidirectional flow aggregation & CICIDS feature extraction
├── model.py                        # ML pipeline wrapper (Random Forest + Isolation Forest)
├── requirements.txt                # Python package dependencies
├── response_policy.py              # Evidence scoring & response decision engine
├── safety_controller.py            # Central enforcement gate & emergency stop
├── sniffer.py                      # Scapy packet capture engine
└── train_model.py                  # Model training & evaluation script
```

---

## 🧠 ML Model Performance

Evaluated on an 800-sample held-out test split (20% of 4,000 total):

| Metric | Score |
|---|---|
| Overall F1-Score | **1.0000** |
| Overall Precision | **1.0000** |
| Overall Recall | **1.0000** |
| False Positive Rate | **0.0000** |
| False Negative Rate | **0.0000** |
| Avg Inference Latency | **~18 ms** |

**Threat Classes Detected:**

| Class | Description |
|---|---|
| `BENIGN` | Normal traffic (browsing, DNS, TLS) |
| `SYN_FLOOD` | High-rate unanswered TCP SYN flood |
| `PORT_SCAN` | Multi-port reconnaissance scan |
| `GENERIC_MALICIOUS` | Brute force, protocol abuse & other anomalies |

---

## 🔧 Configuration

All system parameters are controlled via [`config.ini`](config.ini):

| Section | Key Settings |
|---|---|
| `[system]` | Host, port, secret key |
| `[capture]` | Interface, BPF filter, packet buffer size |
| `[flow]` | Idle/active timeout, cleanup interval |
| `[detection]` | SYN flood threshold, port scan window, anomaly score threshold |
| `[prevention]` | Prevention mode (1–3), block duration, auto-block severities |
| `[protected_addresses]` | Static protected IPs, gateway/DNS protection |
| `[ai]` | Gemini model, API key, payload sanitization |
| `[database]` | DB path, retention days, max stored records |

### Prevention Modes

| Mode | Name | Behavior |
|---|---|---|
| `1` | Detection Only | Detects and logs threats — no blocking |
| `2` | Assisted Prevention | Flags threats for manual operator review |
| `3` | Automatic Prevention | Autonomously blocks `HIGH` and `CRITICAL` threats |

---

## 🔐 Security & Safety Design

- **No arbitrary code execution** — AI Copilot recommendations always route through the Safety Controller
- **Protected address enforcement** — Gateway, DNS, loopback, and local interfaces cannot be blocked
- **Active verification** — Firewall blocks are confirmed against the kernel table before being marked active
- **Audit logging** — Every block, unblock, and rejection is written to the immutable audit log
- **Emergency Stop** — One-click halt disables all autonomous blocking immediately
- **Payload sanitization** — Network data is sanitized before being sent to cloud AI APIs

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| `Flask` | ≥ 3.0.0 | Web framework & REST API |
| `Scapy` | ≥ 2.5.0 | Live packet capture & protocol decoding |
| `scikit-learn` | ≥ 1.4.0 | Random Forest & Isolation Forest ML |
| `numpy` | ≥ 1.26.0 | Numerical computation |
| `pandas` | ≥ 2.2.0 | Dataset handling & feature engineering |
| `psutil` | ≥ 5.9.0 | Network interface discovery & system stats |
| `requests` | ≥ 2.31.0 | Gemini API HTTP client |
| `cryptography` | ≥ 42.0.0 | Secure key handling |
