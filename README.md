# 🛡️ Sentri

**Real-time Host Security Auditing, Privilege Escalation Detection & LLM-Powered Threat Analysis Platform**

---

## 📌 Overview

**Sentri** is an enterprise-grade host security monitoring and automated defense system designed for modern Linux environments. It couples low-overhead, kernel- and log-level host inspection with a high-performance asynchronous backend and generative AI risk classification.

Sentri continuously inspects system activities—including SSH authentications, brute-force incursions, privilege elevations (`sudo`/`su`), and arbitrary command executions (`auditd`/`execve`). When anomalous or high-risk behavior occurs, Sentri can automatically enforce defensive countermeasures (temporary account lockouts, IP blacklisting) while streaming structured telemetry to security engineers via REST APIs and real-time Telegram alerts.

```
                           +------------------------+
                           |  Linux Host Activity   |
                           | (/var/log/auth.log,    |
                           |  /var/log/audit/*.log) |
                           +-----------+------------+
                                       |
                                       v
                           +------------------------+
                           |      Sentri Agent      |
                           |  (Watchdog + Parsers)  |
                           +-----------+------------+
                                       |
              +------------------------+------------------------+
              | (Local Defense)                                 | (HTTP / aiohttp)
              v                                                 v
  +-----------------------+                         +-----------------------+
  |  Auto-Lockout & IP    |                         |     Sentri Backend    |
  |  Blocking (iptables)  |                         |        (FastAPI)      |
  +-----------------------+                         +-----------+-----------+
                                                                |
                                       +------------------------+------------------------+
                                       |                        |                        |
                                       v                        v                        v
                            +--------------------+   +--------------------+   +--------------------+
                            |   PostgreSQL 15    |   |     OpenAI API     |   |   Telegram Alert   |
                            | (Async Telemetry)  |   |   (Risk Engine)    |   |     Dispatcher     |
                            +--------------------+   +--------------------+   +--------------------+
```

---

## ✨ Key Features

- **Real-Time SSH Authentication Monitoring**: Watches system authentication logs (`auth.log` / `secure`) to identify successful logins, credential failures, and invalid usernames.
- **Automated SSH Brute-Force Mitigation**: Sliding-window tracking of repeated authentication failures by IP address, triggering automated temporary host firewall blocks (`iptables`).
- **Privilege Escalation Tracking & Account Lockout**: Intercepts `sudo` invocations, `su` elevations, and suspicious failed privilege attempts. Automatically locks offending user accounts when failure thresholds are exceeded.
- **Kernel Command Auditing via `auditd`**: Parses Linux audit framework records (`execve` syscalls) to capture commands, execution arguments, working directories, process IDs, and originating users.
- **LLM-Powered Risk Assessment**: Real-time integration with OpenAI models to assess semantic risk (`critical`, `high`, `medium`, `low`, `minimal`) of arbitrary shell commands.
- **Interactive CLI Threat Explainer (`sentri.sh`)**: Terminal utility that allows administrators to query Sentri's AI engine directly for detailed explanations, permission impacts, and risk scores of complex shell commands with local cache optimization.
- **Instant Telegram Alerting**: Immediate webhook notifications sent to security operations channels with structured metadata whenever high-risk commands or brute-force attacks are detected.
- **Local Resilience & JSON Spooling**: The agent buffers security telemetry locally in JSON storage with thread-safe flushing to protect against temporary network or backend outages.

---

## 🏗️ Repository Architecture

Sentri is organized into two primary subsystems:

```
sentri/
├── agent/                         # Lightweight host monitoring agent daemon
│   ├── api/
│   │   ├── client.py              # Asynchronous HTTP client (aiohttp) with retry & failover
│   │   └── __init__.py
│   ├── core/
│   │   ├── agent.py               # SentriAgent event dispatcher & lifecycle coordinator
│   │   └── __init__.py
│   ├── parsers/
│   │   ├── base.py                # Abstract base class for log parsers
│   │   ├── command_parser.py      # auditd / execve command stream parser & de-duplicator
│   │   ├── privilege_escalation_parser.py # Sudo/su parser & AccountLockoutManager
│   │   ├── ssh_brute_force_parser.py      # IP failure aggregator & iptables blocker
│   │   └── ssh_parser.py          # SSH auth state parser
│   ├── storage/
│   │   ├── base.py                # Abstract storage interface
│   │   ├── json_storage.py        # Thread-safe persistent file buffer with flush intervals
│   │   └── __init__.py
│   ├── watchers/
│   │   ├── base.py                # Watcher base class
│   │   └── file_watcher.py        # Event-driven file system watcher (watchdog)
│   ├── main.py                    # Agent CLI entry point, signal handlers & query engine
│   └── requirements.txt           # Agent Python dependencies
│
├── backend/                       # Central FastAPI analytics & telemetry platform
│   ├── app/
│   │   ├── api/                   # REST API routes & dependencies
│   │   │   ├── api_v1/
│   │   │   │   ├── endpoints/     # Events, commands, brute-force, privilege, health
│   │   │   │   └── router.py      # v1 master router
│   │   │   └── deps.py            # Database session injection
│   │   ├── core/
│   │   │   └── config.py          # Pydantic BaseSettings environment configuration
│   │   ├── db/
│   │   │   ├── base_class.py      # SQLAlchemy DeclarativeBase
│   │   │   ├── session.py         # Async engine & sessionmaker (asyncpg)
│   │   │   └── crud/              # CRUD data access layers
│   │   ├── models/                # SQLAlchemy database models (events, brute_force, etc.)
│   │   ├── schemas/               # Pydantic request/response validation models
│   │   ├── services/
│   │   │   ├── openai_service.py  # LLM command risk evaluator & explainer
│   │   │   └── telegram_service.py# Telegram Bot API notification engine
│   │   ├── main.py                # FastAPI ASGI application initialization
│   │   └── test_api_smoke.py      # Automated smoke test suite
│   ├── scripts/
│   │   └── start-prod.sh          # Production deployment script
│   ├── .dockerignore
│   ├── .env.example               # Environment variables template
│   ├── Dockerfile                 # Backend container definition
│   ├── docker-compose.yml         # Development compose configuration
│   ├── docker-compose.prod.yml    # Production compose configuration
│   ├── pyproject.toml             # Poetry project configuration & dependencies
│   └── sentri.sh                  # Interactive command explanation CLI script
│
├── .gitignore
└── README.md
```

---

## ⚙️ Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+) recommended for host monitoring; macOS and Windows supported for backend development.
- **Python**: Version `3.9` or higher.
- **Docker & Docker Compose**: For running containerized backend services and PostgreSQL.
- **Audit Subsystem (Optional, for command monitoring)**: `auditd` and `auditctl`.

---

## 🚀 Quick Start Guide

### 1. Set Up the Sentri Backend

Navigate to the `backend/` directory and configure environment variables:

```bash
cd backend
cp .env.example .env
```

Configure `.env` as required (see [Configuration](#-configuration) below).

Start the backend and PostgreSQL database using Docker Compose:

```bash
docker-compose up --build -d
```

Verify service health:

```bash
curl http://localhost:8000/health
# Response: {"status":"ok"}
```

API documentation (Swagger UI) is available at: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 2. Set Up the Sentri Agent

On the target monitored host (or locally):

```bash
cd ../agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Verify connectivity to the backend API:

```bash
python3 main.py --api-url http://localhost:8000/api/v1 --test-api
```

Run the agent daemon in active monitoring mode (requires read access to `/var/log`):

```bash
sudo python3 main.py --api-url http://localhost:8000/api/v1 --debug
```

#### Command-Line Options for `agent/main.py`:

| Flag | Description | Default |
|------|-------------|---------|
| `--api-url` | Base URL of the Sentri Backend API | `None` |
| `--test-api` | Tests backend API connectivity and exits | `False` |
| `--ssh-log` | Path to system authentication log | Auto-detected |
| `--auditd-log`| Path to auditd log file | `/var/log/audit/audit.log` |
| `--storage-dir` | Local path for buffering event logs | `./logs` |
| `--query` | Display stored events from local buffer | `False` |
| `--user` | Filter queried events by username | `None` |
| `--ip` | Filter queried events by IP address | `None` |
| `--event-type` | Filter queried events by type | `None` |
| `--stats` | Print summary statistics of recorded events | `False` |
| `--from-beginning` | Process entire log from start instead of tailing | `False` |
| `--debug` | Enable verbose diagnostic logging | `False` |

---

### 3. Using the Interactive Command Explainer (`sentri.sh`)

Sentri includes a companion CLI utility located in `backend/sentri.sh` that leverages the backend's AI engine to analyze potentially dangerous shell commands:

```bash
chmod +x backend/sentri.sh
./backend/sentri.sh rm -rf /var/log/audit
```

Output:
```
🛡️ SENTRI COMMAND EXPLANATION
Command: rm -rf /var/log/audit

Summary: Recursively deletes the audit log directory and all of its contents without prompting for confirmation.
Risk Level: CRITICAL

Impact Analysis:
- Eliminates security audit trails on the system.
- Impairs incident response and forensic investigations.
```

---

## 🔧 Configuration

### Backend Configuration (`backend/.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_SERVER` | PostgreSQL server hostname / container | `db` (or `localhost`) |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `POSTGRES_USER` | PostgreSQL user | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `postgres` |
| `POSTGRES_DB` | Database name | `sentri` |
| `SECRET_KEY` | Secret key for cryptographic signing | `development_secret_key` |
| `OPENAI_API_KEY` | OpenAI API key for LLM risk assessment | `""` |
| `TELEGRAM_BOT_TOKEN`| Telegram Bot token for dispatching alerts | `""` |
| `TELEGRAM_CHAT_IDS` | Array of recipient chat IDs (e.g. `[12345678]`) | `[]` |
| `TELEGRAM_ENABLED` | Toggle Telegram notifications | `True` |
| `LOG_LEVEL` | Application logging verbosity (`DEBUG`, `INFO`) | `INFO` |

---

## 🔒 Automated Mitigation Controls

### Account Lockout
Configured inside `agent/main.py` via `PrivilegeEscalationParser`:
- **Default Failure Threshold**: `3` failures within a 30-minute window.
- **Action**: Issues an automated user lockout (`passwd -l <user>`) and schedules an unlock countdown (`passwd -u <user>`).

### SSH Brute-Force IP Blocking
Configured inside `agent/main.py` via `SSHBruteForceParser`:
- **Default Threshold**: `5` failed attempts within `5` minutes.
- **Action**: Dynamically inserts an `iptables` drop rule for the offending IP address for `30` minutes.
- **Whitelist Protection**: Internal subnets (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are permanently whitelisted against accidental lockout.

---

## 🧪 Testing

Run smoke tests against the FastAPI application:

```bash
cd backend
pytest app/test_api_smoke.py -v
```

---

## 📄 License

This project is licensed under the MIT License.