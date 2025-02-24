# Anisakys 🔍

![Security](https://img.shields.io/badge/Security-RedTeam-blueviolet)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Python3](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Overview

Anisakys is an automated phishing detection engine that identifies suspicious domains through combinatorial analysis and content pattern matching. Designed for red teams and security analysts, it generates domain permutations from keyword lists and scans for phishing indicators.

## 📚 Table of Contents

- [Features](#-features)
- [Getting Started](#-getting-started)
  - [Prerequisites](#-prerequisites)
  - [Installation](#-installation)
- [Usage](#-usage)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

## 🌟 Features

- 🌀 Dynamic domain permutation generation
- 🔍 Content-based phishing pattern detection
- ⚡ Multi-threaded scanning (20 concurrent workers)
- 📊 Smart logging with duplicate prevention
- 🛡️ DNS failure noise reduction
- 🔄 Continuous scanning mode with configurable intervals

## 🚀 Getting Started

### 📋 Prerequisites

**Before you begin, ensure you have met the following requirements**:

- Python 3.10+
- Linux/macOS (Windows not recommended)

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

## 🛠️ Usage

### 🪃 **Running App**

- Run the container with the necessary environment variables:

  ```bash
  cd anisakys
  python anisakys.py --timeput 20 --log-level INFO
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

## 📫 Contact

For any inquiries or support, please open an issue or contact [r6ty5r296it6tl4eg5m.constant214@passinbox.com](mailto:r6ty5r296it6tl4eg5m.constant214@passinbox.com).

---

## 📜 License

2025 - This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html). You are free to use, modify, and distribute this software under the terms of the GPL-3.0 license. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
