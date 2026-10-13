
# 🛡️ Mini-SIEM: Lightweight Security Ingestion & Detection Engine

A lightweight, modular, and containerized SIEM (Security Information and Event Management) system. It features a standalone log collection agent written in Go, a centralized FastAPI backend with an in-memory temporal correlation engine powered by declarative YAML rules, SQLite relational persistence, and an interactive real-time operations dashboard[cite: 2].

---

## 🏛️ System Architecture

```text
+--------------------------+          HTTP JSON          +------------------------------+
|     Mini-SIEM Agent      | --------------------------> |       FastAPI Backend        |
|          (Go)            |    POST /api/v1/events      |                              |
|                          |                             |  - Ingestion Engine          |
|  - Real-time Log Tailer  |                             |  - YAML Rule Engine          |
|  - Regex Extraction      |                             |  - In-Memory Time Windows    |
+--------------------------+                             +---------------+--------------+
                                                                         |
                                                 +-----------------------+-----------------------+
                                                 |                                               |
                                                 v                                               v
                                       +-------------------+                           +-------------------+
                                       |     SQLite DB     |                           |   Web Dashboard   |
                                       |   (minisiem.db)   | <------------------------ |   (HTML/CSS/JS)   |
                                       +-------------------+      GET /api/v1/alerts   +-------------------+

```

---

## 📂 Repository Structure

```text
Mini_SIEM/
├── agent/                  # Endpoint log-monitoring agent (Go)
│   ├── config.yaml         # Agent configuration (target URL, interval, file path)
│   ├── main.go             # Log tailer, regex parser, and HTTP dispatch client
│   └── go.mod              # Go dependencies
├── dashboard/              # Web user interface
│   ├── index.html          # Operational dashboard view
│   ├── styles.css          # Shared theme variables, metrics, and severity styling
│   └── app.js              # Periodic alert polling and live DOM updates
├── deployments/            # Container orchestration & infrastructure
│   ├── Dockerfile          # Multi-stage image build based on python:3.11-slim
│   └── docker-compose.yml  # Container setup with hot-reloading and volume mounts
├── rules/                  # Declarative detection rules (YAML)
│   ├── linux/              # Authentication events (e.g., SSH brute-force)
│   └── network/            # Network telemetry events (e.g., port scan detection)
├── server/                 # Central backend engine (Python)
│   ├── api/                # FastAPI routers (log ingestion & alert querying)
│   ├── engine/             # Correlation engine (time windows & unique cardinality)
│   ├── models/             # Schema definitions and validation via Pydantic v2
│   └── database.py         # SQLAlchemy ORM models and database initialization
├── tests/                  # Automated test suite (pytest)
├── pytest.ini              # Python path resolution for pytest
└── requirements.txt        # Python backend dependencies

```

---

## 🚀 Quick Start

### Option 1: Docker Compose Deployment (Recommended)

No local Python runtime or virtual environment setup is required on your host machine.

```bash
# 1. Navigate to the deployment directory
cd deployments

# 2. Build and launch the container in the background
docker compose up --build -d

# 3. View live execution logs
docker compose logs -f

```

* **Web Console:** Open [http://localhost:8000/](http://localhost:8000/) in your browser.
* **Interactive API Docs (Swagger UI):** Accessible at [http://localhost:8000/docs](http://localhost:8000/docs).
* **Stop Services:** Run `docker compose down` inside `deployments/`.

---

### Option 2: Local Python Execution

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate    # Linux / macOS
# .venv\Scripts\activate     # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
python3 -m server.main

```

---

## 🧪 Automated Testing

The correlation engine includes automated tests covering multi-event thresholds, sliding expiration windows, and false-positive prevention:

```bash
python3 -m pytest -v

```

All test cases are isolated under `tests/test_engine.py` using `SecurityEvent.model_validate` fixtures.

---

## 🔍 Detection Rules

### 1. SSH Brute-Force (`linux-ssh-bruteforce`)

* **Source Type:** `linux_auth`
* **Filter Condition:** Failed authentication (`auth.success = false`)
* **Correlation:** Triggers when **3 consecutive failed attempts** originate from the same IP address within a **60-second window**.
* **Severity:** `HIGH`

### 2. Network Port Scan (`network-port-scan`)

* **Source Type:** `network_flow`
* **Filter Condition:** Inbound network connections
* **Correlation:** Monitors distinct destination ports (`distinct: "network.dst_port"`). Triggers when an IP contacts **5 unique ports** within a **30-second window**.
* **Severity:** `MEDIUM`

---

## 💻 Go Agent Setup

The agent runs as a standalone daemon on endpoints to monitor logs and forward structured events.

1. **Configure `agent/config.yaml`:**
```yaml
server_url: "http://localhost:8000/api/v1/events"
hostname: "srv-ubuntu-prod"
log_file: "./test_auth.log"
poll_interval_ms: 500

```


2. **Run or compile the agent:**
```bash
cd agent

# Run directly
go run main.go

# Or compile into a standalone binary
go build -o siem-agent main.go
./siem-agent

```


3. **Simulate malicious activity (in another terminal):**
```bash
echo "Failed password for root from 192.168.1.99 port 22 ssh2" >> agent/test_auth.log
echo "Failed password for admin from 192.168.1.99 port 22 ssh2" >> agent/test_auth.log
echo "Failed password for test from 192.168.1.99 port 22 ssh2" >> agent/test_auth.log

```


Within seconds, the alert will register in the database and appear highlighted on the web dashboard.

---

## 💾 Database Management

* **Storage Location:** SQLite database stored at `minisiem.db` in the repository root.


* **Persistence:** Mounted via Docker volumes (`../minisiem.db:/app/minisiem.db`), keeping records safe across container restarts.


* **Reset Database:** Stop the server (`docker compose down` or `Ctrl + C`), delete `minisiem.db` (`rm minisiem.db`), and restart the server. The application will automatically regenerate clean schema tables upon startup.



