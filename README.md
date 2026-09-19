```markdown
# 🎣 Check Phish - Enterprise Phishing Triage Engine

![Version](https://img.shields.io/badge/Version-4.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-success.svg)
![Execution](https://img.shields.io/badge/Execution-100%25_Static_%26_Safe-brightgreen.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

```text
             O  o
        _\_   o
     \\/  ('>
     ( \__|
     \___/

Check Phish By Ali Burhan
Version 4.0 - Enterprise Triage & Threat Engine

```

## 🛡️ Overview

Check Phish is an advanced, automated threat-hunting engine designed for Cybersecurity Analysts and SOC teams. Phishing exploits the space between a technical control and a human reaction. This tool bridges that gap by providing a 100% safe, static execution environment to dissect raw `.eml` files and text blocks. It identifies highly evasive social engineering tactics, Business Email Compromise (BEC) routing anomalies, and hidden malicious payloads without ever executing active malware or rendering dangerous HTML.

## ✨ Enterprise Features

* **Deep Header & Authentication Analysis:** Validates SPF, DKIM, and DMARC integrity while mapping asymmetric `Reply-To` routing used in BEC attacks.


* **Quishing (QR Code) Detection:** Automatically extracts and decodes QR codes embedded in attachments to uncover hidden malicious URLs bypassing text filters.


* **Advanced Heuristics & Evasion Detection:** Identifies Domain Generation Algorithms (DGA) via Shannon Entropy, catches typosquatting through sequence matching, and flags zero-width Unicode characters and CSS obfuscation.
* **Psychological Threat Scoring:** Maps cognitive triggers like urgency, fear, authority, and financial reward lures directly to standardized threat taxonomies.


* **Safe Infrastructure Tracing:** Uses strictly restricted HTTP `HEAD` requests to safely unmask redirect chains and traces domain age via WHOIS lookups without triggering web-based exploits.
* **Automated Triage Reporting:** Generates timestamped incident reports mapped to the "Pause, Verify, Report" human firewall protocol.



## ⚙️ Prerequisites & Installation

This tool requires Python 3.8 or higher. While it runs natively with local heuristics, installing the advanced threat intelligence libraries unlocks full infrastructure tracing and payload parsing.

**1. Clone the repository:**

```bash
git clone [https://github.com/aliburhan/check-phish.git](https://github.com/aliburhan/check-phish.git)
cd check-phish

```

**2. Install advanced threat libraries:**

```bash
pip install requests python-whois Pillow pyzbar PyPDF2

```

## 🚀 Usage Guide

Check Phish features an interactive, CLI-based menu tailored for rapid incident response.

**Run the engine:**

```bash
python check_phish.py

```

**Execution Options:**

1. **Load from File:** Enter the path to any raw `.eml` or `.txt` file.
2. **Direct Paste:** Paste raw email headers and body directly into the terminal buffer (ideal for isolated VM environments).
3. **Exit:** Safely terminate the engine.

## 📊 Sample Incident Report

When a malicious payload is detected, the engine categorizes the threat and assigns actionable mitigation steps.

```text
Check Phish By Ali Burhan - Threat Analysis Report
=================================================================
Date: 2026-09-19 12:00:00
Source: Direct Terminal Paste
Risk Score: 100/100
Assessment: Malicious
Recommended Action: Block Domain & Escalate
=================================================================
Key Indicators Found:
 - Brand impersonation: Display name claims 'microsoft', but routes from 'm1crosoft-security-alert.xyz'.
 - Severe BEC Risk: Email sent from 'm1crosoft-security-alert.xyz' but replies are diverted to 'gmail.com'.
 - Sender policy framework (SPF) authentication failed.
 - Secrecy tactic detected: Sender insists on confidentiality to bypass peer verification.
 - Cognitive urgency trigger detected: 'immediate action / within 24 hours'.
 - Advanced Evasion: Hidden HTML elements detected, often used to poison AI filters.
 - Direct IP link detected: '198.51.100.42'.
 - Privacy Threat: A hidden 1x1 tracking pixel was detected. The attacker is tracking email opens.

Human Firewall Guidance:
 - Pause: Do not proceed or make any financial commitments.
 - Verify: Validate the request using a trusted phone number or in person.
 - Report: Forward this message immediately to your security operations center.

```

## 🔒 Security & Execution Disclaimer

**Zero-Execution Guarantee:** This script is designed for deployment in secure environments. It processes MIME payloads statically. Link tracing is restricted to HTTP `HEAD` operations to fetch server headers only. It does not download response bodies, render DOM environments, or execute JavaScript.

## 👨‍💻 Author

**Ali Burhan**
Cybersecurity Analyst

```

```
