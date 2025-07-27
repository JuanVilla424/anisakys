# 🔍 Anisakys

![Security](https://img.shields.io/badge/Security-BlueTeam-blue)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Python3](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Overview

Anisakys is an advanced automated phishing detection engine designed for blue teams and cybersecurity analysts who need comprehensive threat hunting capabilities. This powerful tool performs real-time monitoring of suspicious domains through combinatorial analysis, multi-API validation, and machine learning-based threat assessment, making it essential for organizations protecting against sophisticated phishing campaigns.

## 📚 Table of Contents

- [Features](#-features)
- [Getting Started](#-getting-started)
  - [Prerequisites](#-prerequisites)
  - [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
  - [Basic Scanning](#-basic-scanning)
  - [Multi-API Validation](#-multi-api-validation)
  - [Auto-Analysis System](#-auto-analysis-system)
  - [REST API Server](#-rest-api-server)
  - [Manual Phishing Site Reporting](#-manual-phishing-site-reporting)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

## 🌟 Features

### Core Detection Engine

- 🌀 Dynamic domain permutation generation from keyword lists
- 🔍 Content-based phishing pattern detection with ML enhancement
- ⚡ Multi-threaded scanning architecture (up to 180 concurrent workers)
- 📊 Smart logging with duplicate prevention and noise reduction
- 🛡️ DNS failure noise reduction and intelligent retry logic
- 🔄 Continuous monitoring with configurable intervals and daemon mode

### Multi-API Threat Intelligence

- 🛡️ **VirusTotal Integration**: 70+ antivirus engines for comprehensive URL scanning
- 🔍 **URLVoid Integration**: 30+ reputation engines and blocklist services
- 🎣 **PhishTank Integration**: Community-driven verified phishing database
- 🔗 **Grinder Integration**: Bidirectional threat intelligence sharing and IP reporting
- 🤖 **Auto-Analysis Pipeline**: Intelligent threat assessment with confidence scoring
- 📊 **Multi-API Validation**: Aggregated threat level calculation across all services

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

**Before you begin, ensure you have met the following requirements**:

- Python 3.10+
- PostgreSQL 12+ (for production) or SQLite (for development)
- Linux/macOS (Windows not recommended)
- **Optional API Keys for Enhanced Detection**:
  - VirusTotal API Key (recommended)
  - URLVoid API Key (recommended)
  - PhishTank API Key (optional)
  - Grinder API credentials (optional)

### 🔨 Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/JuanVilla424/anisakys.git
   cd anisakys
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   ```

3. **Activate the Virtual Environment**

   On Unix or MacOS:

   ```bash
   source venv/bin/activate
   ```

4. **Upgrade pip**

   ```bash
   python -m ensurepip
   pip install --upgrade pip
   ```

5. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   - or if u prefer use poetry:

     ```bash
     pip install poetry
     poetry lock
     poetry install
     ```

     - **When you're done**, deactivate the environment:

       ```bash
       deactivate
       ```

6. **Set Up Environment Variables**

   - Rename the `.env.example` file to `.env`:
     ```bash
     cp .env.example .env
     ```
   - Open the `.env` file and configure the environment variables as needed.

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

Start the REST API server with authentication:

```bash
cd anisakys
python anisakys.py --start-api --api-port 8080 --api-key your_secure_api_key
```

**API Endpoints:**

- `POST /api/v1/report` - Submit phishing reports
- `POST /api/v1/multi-scan` - Perform multi-API validation
- `GET /api/v1/status/<url>` - Check report status
- `GET /api/v1/stats` - System statistics
- `GET /api/v1/health` - Health check

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

2025 — This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html). You are free to use, modify, and distribute this software under the terms of the GPL-3.0 license. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
