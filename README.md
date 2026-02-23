# HeaderGuard — Security Header Scanner

A lightweight Python CLI tool that analyzes websites for critical HTTP security headers. Perfect for security audits, penetration testing, and web development best practices.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Blueprint](#blueprint)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Security Headers Explained](#security-headers-explained)
- [Example Output](#example-output)

---

## Overview

HeaderGuard scans any URL and evaluates whether the server sends proper security headers. These headers protect against common web vulnerabilities like **XSS**, **clickjacking**, **MIME sniffing**, and **man-in-the-middle attacks**. The scanner outputs a score (0–100), a letter grade, and actionable recommendations.

---

## Blueprint

### This flowchart shows the full workflow from setup to output:

<img src= "https://imgur.com/xL1tuPz.png" width="90%" alt="Terminal view">

| Phase | Steps |
|-------|-------|
| **SETUP** | Install Python → Create project folder → Install dependencies (`pip install requests`) |
| **RUN** | Execute `python scanner.py <URL>` |
| **TROUBLESHOOTING** | Check internet connection → Verify URL is accessible → Retry scan |
| **OUTPUT** | Security Header Report with score, grade, and per-header pass/fail status |

---

## Features

- ✅ Scans 7 critical security headers
- ✅ HTTPS enforcement check
- ✅ Security score (0–100) and letter grade (A–F)
- ✅ Clear recommendations for missing headers
- ✅ Verbose mode to inspect all response headers
- ✅ No configuration needed — runs with a single command

---

## Installation

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/header-guard.git
   cd header-guard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the scanner**
   ```bash
   python scanner.py https://example.com
   ```

---

## Usage

### Basic scan

```bash
python scanner.py https://github.com
```

### Scan without protocol (auto-uses HTTPS)

```bash
python scanner.py google.com
```

### Verbose mode (show all response headers)

```bash
python scanner.py https://example.com -v
```

### Custom timeout (default: 10 seconds)

```bash
python scanner.py https://slow-site.com -t 30
```

### Command-line help

```bash
python scanner.py --help
```

---

## Security Headers Explained

| Header | Purpose | Severity |
|--------|---------|----------|
| **Strict-Transport-Security** | Forces HTTPS; prevents downgrade attacks | Critical |
| **Content-Security-Policy** | Mitigates XSS and data injection | Critical |
| **X-Content-Type-Options** | Stops MIME type sniffing | High |
| **X-Frame-Options** | Reduces clickjacking risk | High |
| **X-XSS-Protection** | Legacy XSS filter support | Medium |
| **Referrer-Policy** | Limits referrer leakage | Medium |
| **Permissions-Policy** | Restricts browser features (camera, mic, etc.) | Medium |

---

## Example Output

```
============================================================
🛡️  HEADERGUARD - Security Header Report
============================================================

📎 URL: https://github.com
🔒 HTTPS: Yes ✓

📊 SECURITY SCORE: 85/100 (Grade: B)
------------------------------------------------------------

✓ Strict-Transport-Security: [PASS]
   Value: max-age=31536000; includeSubDomains; preload

✓ X-Content-Type-Options: [PASS]
   Value: nosniff

✓ X-Frame-Options: [PASS]
   Value: deny

✗ Content-Security-Policy: [MISSING]
   Recommendation: default-src 'self'
   Why: Prevents XSS and data injection attacks

...
============================================================
```

---

## Project Structure

```
header-guard/
├── scanner.py          # Main scanner script
├── requirements.txt    # Python dependencies
├── blueprint.png       # Workflow flowchart
└── README.md           # This file
```

---
