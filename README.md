<div align="center">
  <h1>🔍 Anisakys</h1>
  <p><em>Advanced Automated Phishing Detection & ICANN Compliance Engine</em></p>

![Security](https://img.shields.io/badge/Security-BlueTeam-4B0082)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Version](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)
![Status](https://img.shields.io/badge/Status-Production-success.svg)
![License](https://img.shields.io/badge/License-GPLv3-red.svg)
![ICANN](https://img.shields.io/badge/ICANN-Compliant-orange)
![Threat Intel](https://img.shields.io/badge/Threat%20Intel-Multi--API-yellow)
![Automation](https://img.shields.io/badge/Automation-Ready-purple)

  <br/>

![Architecture](https://img.shields.io/badge/Architecture-Multi--Threaded-lightblue)
![Database](https://img.shields.io/badge/Database-PostgreSQL-336791?logo=postgresql&logoColor=white)
![API](https://img.shields.io/badge/API-REST-FF6C37)
![Reports](https://img.shields.io/badge/Reports-Auto--Generated-green)

</div>

---

## 🎯 Overview

<div align="center">

```mermaid
graph TB
    A[🌐 Domain Generation] --> B[🔍 Multi-API Scanning]
    B --> C[🤖 ML Threat Assessment]
    C --> D[📊 Confidence Scoring]
    D --> E{🎯 Auto-Report?}
    E -->|Yes| F[📧 ICANN Compliance Report]
    E -->|No| G[👤 Manual Review Queue]
    F --> H[📋 Follow-up Tracking]
    G --> I[🔄 Analyst Decision]
    I --> F

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff8e1
    style E fill:#ffebee
    style F fill:#e0f2f1
    style G fill:#fce4ec
    style H fill:#f1f8e9
    style I fill:#e3f2fd
```

</div>

**Anisakys** is an enterprise-grade automated phishing detection and reporting engine specifically designed for **blue teams**, **SOC analysts**, and **cybersecurity professionals** who require comprehensive threat hunting capabilities with full **ICANN compliance**.

This sophisticated platform combines **real-time domain monitoring**, **multi-API threat intelligence**, **machine learning-based assessment**, and **automated abuse reporting** to provide organizations with a complete defense against sophisticated phishing campaigns.

### 🏛️ **ICANN Compliance Features**

- ✅ **2-Day SLA Tracking** - Automatic follow-up system for non-responsive registrars
- ✅ **Escalation Management** - Multi-level CC escalation for overdue reports
- ✅ **Audit Trail** - Complete reporting history with timestamps
- ✅ **Professional Templates** - ICANN-compliant abuse report formatting

---

## 📚 Table of Contents

<div align="center">

|          🎯 **Core Sections**           |         🛠️ **Technical Docs**          |                🚀 **Advanced Usage**                 |
| :-------------------------------------: | :------------------------------------: | :--------------------------------------------------: |
|        [🌟 Features](#-features)        |  [⚙️ Configuration](#-configuration)   |      [🤖 Auto-Analysis](#-auto-analysis-system)      |
| [🚀 Getting Started](#-getting-started) |          [🛠️ Usage](#-usage)           |           [🔌 REST API](#-rest-api-server)           |
|   [📋 Prerequisites](#-prerequisites)   | [🔍 Multi-API](#-multi-api-validation) | [📧 ICANN Reports](#-manual-phishing-site-reporting) |
|    [🔨 Installation](#-installation)    |   [📊 Monitoring](#-basic-scanning)    |       [🔄 Advanced Ops](#-advanced-operations)       |

</div>

**Quick Navigation:**

- 🎯 [**Overview**](#-overview) • 🌟 [**Features**](#-features) • 🚀 [**Quick Start**](#-getting-started)
- ⚙️ [**Configuration**](#-configuration) • 🛠️ [**Usage Guide**](#-usage) • 🤝 [**Contributing**](#-contributing)

---

## 🌟 Features

<div align="center">

```mermaid
graph LR
    A[🔍 Detection Engine] --> B[🛡️ Threat Intel APIs]
    B --> C[📧 ICANN Reporting]
    C --> D[📊 Management Dashboard]
    B --> N[🔗 Grinder Integration]

    A --> E[🌀 Domain Generation<br/>180 Threads]
    A --> F[🤖 ML Pattern Detection<br/>Content Analysis]

    B --> G[🦠 VirusTotal<br/>70+ Engines]
    B --> H[🔍 URLVoid<br/>30+ Sources]
    B --> I[🎣 PhishTank<br/>Community DB]

    N --> O[📤 IP Reporting<br/>Malicious Infrastructure]

    C --> J[📋 Follow-up System<br/>2-Day SLA]
    C --> K[🔄 Escalation Mgmt<br/>Multi-Level CC]

    D --> L[🚀 REST API<br/>Bearer Auth]
    D --> M[📈 Real-time Stats<br/>Health Monitoring]

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff8e1
    style N fill:#ffebee
```

</div>

---

### 🔍 **Core Detection Engine**

<table>
<tr>
<td width="50%">

#### 🌀 **Dynamic Domain Generation**

- **Keyword Permutation Engine** - Advanced combinatorial generation
- **Smart Pattern Recognition** - ML-enhanced content analysis
- **Multi-Threading Support** - Up to **180 concurrent workers**
- **Noise Reduction Logic** - DNS failure filtering & retry intelligence

</td>
<td width="50%">

#### ⚡ **High-Performance Architecture**

- **Continuous Monitoring** - Configurable intervals & daemon mode
- **Smart Logging System** - Duplicate prevention & log rotation
- **Memory Optimization** - Efficient resource management
- **Graceful Shutdown** - Clean exit handling with KeyboardInterrupt

</td>
</tr>
</table>

### 🛡️ **Multi-API Threat Intelligence**

Anisakys integrates multiple threat intelligence services to provide comprehensive assessment of each detected domain. The system simultaneously queries different APIs and aggregates results to generate a **consolidated confidence score** and **aggregated threat level**.

#### 🔄 **Multi-API Validation Flow**

1. **🔍 Initial Detection** - Detection engine identifies suspicious domain
2. **📡 Parallel Query** - Simultaneous requests sent to all configured APIs
3. **⚖️ Result Aggregation** - Results combined using specific weights
4. **📊 Final Scoring** - 0-100% score calculated based on all sources
5. **🎯 Automatic Decision** - If threshold exceeded, proceeds to automatic reporting

#### 🔌 **Integrated APIs**

- **🦠 VirusTotal** - Queries 70+ antivirus engines for malware detection and URL reputation
- **🔍 URLVoid** - Verifies against 30+ reputation sources and blacklist services
- **🎣 PhishTank** - Community database of verified phishing sites
- **🛡️ Google Safe Browsing** - Real-time malware and social engineering detection (API v4)
- **🔗 Grinder** - Optional malicious IP reporting to threat intelligence system (configurable)

#### 📈 **Confidence System**

The system automatically calculates:

- **Confidence Score** (0-100%) - Based on API consensus
- **Threat Level** - Aggregated classification (low/medium/high/critical)
- **Detection Keywords** - Specific terms that triggered detection
- **API Response Consensus** - Percentage of APIs confirming the threat

#### 🎯 **Threat Level Rules**

| Level      | Triggers                                                   |
| ---------- | ---------------------------------------------------------- |
| `critical` | Homoglyphs, PhishTank verified, GSB malware                |
| `high`     | Typosquatting, combo-squatting, GSB social engineering     |
| `medium`   | Suspicious TLD (forced minimum), keywords, domain <30 days |
| `low`      | Low risk indicators                                        |
| `clean`    | No threats detected                                        |

> **Note:** Suspicious TLDs (.shop, .top, .buzz, etc.) force a minimum threat level of `medium`

### Enhanced Abuse Reporting

- 📧 **Enhanced Abuse Email Detection**: Multi-source abuse contact discovery
- 🏢 **Hosting Provider Intelligence**: ASN-based abuse contact mapping
- ☁️ **Cloudflare Detection**: Smart handling of CDN-protected sites
- 📎 **Multi-Attachment Support**: Folder-based attachment management
- 🎯 **Auto-Reporting System**: Confidence-based automatic abuse reports
- 📈 **Escalation Management**: Multi-level CC escalation for critical threats

### Database & Management

- 🗄️ **PostgreSQL Integration**: Robust data persistence and analytics
- 📊 **Site Status Monitoring**: Real-time takedown detection and tracking
- 🔄 **Auto-Analysis Queue**: Background processing of detected threats
- 📋 **Manual Review System**: Human oversight for edge cases
- 📈 **Threat Intelligence Storage**: Historical data for pattern analysis

### REST API & Automation

- 🚀 **REST API Server**: External integration with Bearer token authentication
- 🔐 **API Key Authentication**: Secure endpoint access control
- 📤 **External Reporting**: Programmatic phishing site submissions
- 📊 **Status Monitoring**: Real-time system and threat statistics
- 🔧 **Health Monitoring**: System status and integration connectivity checks

### Advanced Features

- 🎯 **Priority-Based Processing**: High/Medium/Low priority threat handling
- 🔍 **Real-Time Analysis**: Immediate processing for critical keywords
- 📊 **Confidence Scoring**: ML-based threat assessment (0-100%)
- 🤖 **Intelligent Auto-Reporting**: Configurable confidence thresholds
- 📈 **Comprehensive Logging**: Detailed audit trails and monitoring
- ⚙️ **Flexible Configuration**: Environment-based settings management

## 🚀 Getting Started

### 📋 Prerequisites

<div align="center">

|                       🐍 **Python Environment**                       |                           🗄️ **Database Requirements**                            |                        🔑 **API Keys (Optional)**                         |
| :-------------------------------------------------------------------: | :-------------------------------------------------------------------------------: | :-----------------------------------------------------------------------: |
| ![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python) | ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-336791?logo=postgresql) | ![VirusTotal](https://img.shields.io/badge/VirusTotal-Recommended-4285f4) |
| ![OS](https://img.shields.io/badge/OS-Linux%2FmacOS-green?logo=linux) |   ![SQLite](https://img.shields.io/badge/SQLite-Development-003B57?logo=sqlite)   |    ![URLVoid](https://img.shields.io/badge/URLVoid-Recommended-orange)    |

</div>

<table>
<tr>
<td width="50%">

#### 🎯 **System Requirements**

- **Python 3.10+** - Core runtime environment
- **PostgreSQL 12+** - Production database (recommended)
- **SQLite** - Development/testing database
- **Linux/macOS** - Preferred operating systems
- **4GB RAM** - Minimum for multi-threading
- **SSD Storage** - Recommended for database performance

</td>
<td width="50%">

#### 🔑 **API Keys (Optional but Recommended)**

- **VirusTotal API** - 70+ antivirus engines
- **URLVoid API** - 30+ reputation sources
- **PhishTank API** - Community phishing database
- **Grinder API** - Enterprise threat intelligence
- **SMTP Credentials** - Abuse report delivery
- **Screenshots Directory** - Visual evidence storage

</td>
</tr>
</table>

---

### 🔨 Installation

<div align="center">

```mermaid
graph TD
    A[📥 Clone Repository] --> B[🐍 Create Virtual Environment]
    B --> C[⚡ Activate Environment]
    C --> D[📦 Install Dependencies]
    D --> E[⚙️ Configure Environment]
    E --> F[🗄️ Setup Database]
    F --> G[🚀 Launch System]

    style A fill:#e3f2fd
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff8e1
    style E fill:#ffebee
    style F fill:#f1f8e9
    style G fill:#e0f2f1
```

</div>

#### **Step 1: 📥 Clone the Repository**

```bash
git clone https://github.com/JuanVilla424/anisakys.git
cd anisakys
```

#### **Step 2: 🐍 Setup Python Environment**

<table>
<tr>
<td width="50%">

**🔹 Using pip (Recommended)**

```bash
# Create virtual environment
python -m venv venv

# Activate environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

</td>
<td width="50%">

**🔹 Using Poetry (Alternative)**

```bash
# Install Poetry (>= 2.2)
pipx install poetry

# Install the locked dependencies (incl. dev tools)
poetry install --with dev

# Activate environment
eval $(poetry env activate)
```

> 📦 `pyproject.toml` is the single source of truth for dependencies and
> `poetry.lock` pins them. `requirements*.txt` are generated from the lock:
> after changing dependencies run `poetry lock` and `tools/sync-requirements.sh`.

</td>
</tr>
</table>

#### **Step 3: ⚙️ Environment Configuration**

```bash
# Copy example configuration
cp .env.example .env

# Edit configuration (use your preferred editor)
nano .env
```

> 💡 **Pro Tip:** The system will work with minimal configuration, but API keys significantly enhance detection capabilities.

#### **Step 4: 🗃️ Apply Database Migrations**

```bash
# Creates or upgrades the schema in DATABASE_URL (run again after every update)
alembic upgrade head
```

> ⚠️ The application never creates tables by itself: every process checks at startup that the
> database is at the latest Alembic revision and refuses to start otherwise.

## ⚙️ Configuration

### Essential Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/anisakys

# Core Settings
KEYWORDS=bank,login,verify,secure,account
DOMAINS=.com,.net,.org,.info
TIMEOUT=30
LOG_LEVEL=INFO
DEFAULT_ATTACHMENT=attachments/file.pdf
ATTACHMENTS_FOLDER=attachments/

# Email Configuration (for abuse reporting)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
ABUSE_EMAIL_SENDER=reports@yourorg.com

# API Keys (Optional but Recommended)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLVOID_API_KEY=your_urlvoid_api_key
PHISHTANK_API_KEY=your_phishtank_api_key

# Grinder Integration (Optional)
GRINDER0X_API_URL=https://your-grinder-instance.com
GRINDER0X_API_KEY=your_grinder_api_key

# Auto-Analysis Configuration
AUTO_MULTI_API_SCAN=true
AUTO_REPORT_THRESHOLD_CONFIDENCE=85
MANUAL_REVIEW_THRESHOLD_CONFIDENCE=70
```

## 🛠️ Usage

### 🪃 **Basic Scanning**

Run continuous phishing detection with enhanced multi-API validation:

```bash
cd anisakys
python anisakys.py --timeout 30 --log-level INFO
```

### 🔍 **Multi-API Validation**

Perform comprehensive threat assessment on a specific URL:

```bash
cd anisakys
python anisakys.py --multi-api-scan --url https://suspicious-site.com
```

### 🤖 **Auto-Analysis System**

Run background threads for auto-analysis and reporting without active scanning:

```bash
cd anisakys
python anisakys.py --threads-only
```

Check auto-analysis system status:

```bash
cd anisakys
python anisakys.py --show-auto-status
```

### 🚀 **REST API Server**

Development server (binds `API_BIND_HOST`, `127.0.0.1` by default; the Werkzeug
debugger is never enabled):

```bash
cd anisakys
python anisakys.py --start-api --api-port 8080 --api-key your_secure_api_key
```

Production: serve the WSGI app with gunicorn (as `entrypoint-backend.sh` does). This
process only serves HTTP; background jobs run in the scheduler role.

```bash
gunicorn --bind 127.0.0.1:8091 --worker-class gthread --threads 4 'src.api.wsgi:create_app()'
```

Behind a reverse proxy set `TRUSTED_PROXY_HOPS`; with several workers set
`RATELIMIT_STORAGE_URL=redis://...` so rate limits are shared.

**API keys and scopes** (`python -m src.cli.api_keys create --help` lists them):
`read`, `scan`, `report` (submissions wait for analyst approval), `report_send`
(submissions are reported without approval), `write`, `email_admin` (e-mail monitor
threads, limited to `EMAIL_MONITOR_ALLOWED_MAILBOXES`), `metrics` and `admin`.

**API Endpoints:**

- `POST /api/v1/report` - Submit phishing reports (202 pending approval without `report_send`)
- `POST /api/v1/multi-scan` - Perform multi-API validation
- `GET /api/v1/status/<url>` - Check report status
- `GET /api/v1/stats` - System statistics, incl. `reports_by_status` and `outbox_by_status`
- `GET /api/v1/session` - The calling key: `key_type`, `key_name`, `key_prefix` (8 chars),
  usable `scopes` and `rate_limit_storage` (`shared`/`per-process`); never the secret
- `GET /api/v1/sites/sources` - `[{"source": str|null, "count": int}]`
- `GET /api/v1/reports/tasks` - Open analyst tasks (web-form providers, sites without a contact)
- `POST /api/v1/reports/tasks/<id>/complete` - Close one: `{"outcome": "submitted"|"not_applicable", "note"?}`
- `POST /api/v2/stix/bundle` - Build a STIX 2.1 indicator bundle (TLP 2.0, AMBER by default)
- `GET /api/v1/health` - Health check with a database ping (503 when unhealthy)
- `GET /metrics` - Prometheus metrics (`METRICS_TOKEN` or a `metrics`/`read` API key)

**Response conventions** (console endpoints):

- Unknown is `null`, never a default: no invented severities, confidences, statuses,
  sources, priorities, `gsb_safe`/`is_cloudflare` flags or "now" timestamps.
- Timestamps are ISO-8601 with an explicit offset (`2026-01-02T03:04:05+00:00`).
  Database columns without time zone are read as UTC (the images and CI run the
  database and the application in UTC); see `src/api/serializers.py`.
- Every response carries `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Reset` and `Retry-After`; a 429 is
  `{"error": "...", "retry_after": <seconds>}` with the same `Retry-After`.
  `/threads/<id>/results` is limited per API key _and_ thread (30/min, 120/min per key).
- Lists report the real `total` across pages (`/sites`, `/intelligence/iocs`,
  `/campaigns`, `/reports/tasks`); `/graph` reports `meta.total_rows`, `meta.limit`
  and `meta.limited`.

**Compatibility notes** (fields that were lying now say so; names are unchanged):

- `/graph`: node `severity` is null except for domains (severest stored threat level);
  edge `confidence` is null except `detected_as` (stored kit confidence / 100);
  `meta` counts count the returned nodes.
- `/intelligence/iocs`: new `search` and `threat` filters; IP `threat` is the severest
  level of its sites; IP `tags` is empty when the Cloudflare flag is unknown.
- `/sites`: new `takedown_date`; `source`, `priority`, `is_cloudflare` and `gsb_safe`
  (until GSB checked the site) can be null.
- `/threads`: `results_count` = results shown (same as `/threads/<id>/results` total),
  `total_results` = all recorded results incl. discarded, new `last_execution_results`.
- `/integrations`: `status` is `unknown` without breaker data; `circuit_breaker` and
  `error_rate` can be null; `last_success` is null (not recorded), new `state_changed_at`.
- `/campaigns`: `confidence` can be null; new `limit`/`offset` (default 100, max 500).
- `/activity`: `timestamp` and `severity` can be null; undated events sort last.
- `/reports`: `status` can be null; `?status=` accepts `queued`, `failed`, `pending_manual`.
- `/report`: `processing` can be `scheduled` (the scheduler role reports the site).

### 🕸️ **Manual Phishing Site Reporting**

Report a confirmed phishing site:

```bash
cd anisakys
python anisakys.py --report "https://sub.domain.com" --abuse-email abuse@provider.com
```

- You can specify abuse mail or not.

**Make Sure the Site is 100% a Phishing Site**

### 👾 **Process Reported Sites**

Send abuse reports for manually flagged sites with multi-API evidence:

```bash
cd anisakys
python anisakys.py --process-reports --attachment attachments/evidence.pdf --cc="soc@company.com,analyst@company.com"
```

- You can specify attachment or the system will get these from env.
- You can specify CC Mails or the system will get these from env.

Use multiple attachments from a folder:

```bash
cd anisakys
python anisakys.py --process-reports --attachments-folder ./evidence_folder --cc="team@company.com"
```

- You can specify attachments folder or the system will get these from env.
- You can specify CC Mails or the system will get these from env.

### 📧 **Test Abuse Reporting**

Send a test report with multi-API validation results:

```bash
cd anisakys
python anisakys.py --test-report --abuse-email test@yourorg.com
```

### 🔗 **Grinder Integration**

Test threat intelligence integration:

```bash
cd anisakys
python anisakys.py --test-grinder-integration
```

### 🔄 **Advanced Operations**

Force immediate auto-analysis of pending sites:

```bash
cd anisakys
python anisakys.py --force-auto-analysis
```

Process auto-report eligible sites immediately:

```bash
cd anisakys
python anisakys.py --auto-report-now
```

Reset scanning position to beginning:

```bash
cd anisakys
python anisakys.py --reset-offset
```

### 📏 **Measuring Detection Quality**

Analyst labels (`POST /api/v1/sites/<id>/labels`: `confirm`, `dismiss`, `report`) are the
ground truth. The evaluation harness builds a versioned dataset and measures the detector:

```bash
# Dataset: analyst labels + live-verified OpenPhish feed + hard negatives
# (official brand logins, homonyms, benign SaaS pages, Tranco top sites)
python -m src.eval build --name baseline --version 2026-10-04
python -m src.eval verify eval/datasets/baseline/2026-10-04

# Precision, recall, PR-AUC, TPR@FPR, precision@k, per-brand confusion,
# calibration and latency/cost per stage -> eval/runs/<run>/report.{json,html}
python -m src.eval run eval/datasets/baseline/2026-10-04 --predictor live
python -m src.eval run eval/datasets/baseline/2026-10-04 --predictor heuristic

# Time to detect / report / take down, queues and outcomes from the database
python -m src.eval ops --days 30
```

Dataset manifests (with the samples' SHA-256) and the seed lists in `eval/seeds/` are
versioned; samples built from third-party feeds and the run reports stay local. The same
operational metrics are served at `GET /api/v1/metrics/operational` and on `/metrics`.

## 🤝 Contributing

**Contributions are welcome! To contribute to this repository, please follow these steps**:

1. **Fork the Repository**

2. **Create a Feature Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Commit Your Changes**

   ```bash
   git commit -m "feat(<scope>): your feature commit message - lower case"
   ```

4. **Push to the Branch**

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request into** `dev` **branch**

Please ensure your contributions adhere to the Code of Conduct and Contribution Guidelines.

# _Disclaimer_

The contents of this repository are provided "as is" for informational purposes only. The authors and contributors make no warranties—express or implied—regarding the accuracy, completeness, or suitability of the information herein. Use of this repository is at your own risk, and no liability is assumed for any errors or omissions.

This tool is designed for legitimate cybersecurity research and blue team operations. Users are responsible for ensuring compliance with applicable laws and regulations when using this software.

## 📫 Contact

For any inquiries or support, please open an issue or contact [r6ty5r296it6tl4eg5m.constant214@passinbox.com](mailto:r6ty5r296it6tl4eg5m.constant214@passinbox.com).

---

## 📜 License

<div align="center">

2026 — This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html). You are free to use, modify, and distribute this software under the terms of the GPL-3.0 license. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.

</div>
