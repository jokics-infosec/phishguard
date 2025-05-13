> 📘 **Internal Developer Instructions** — This guide outlines how the code is structured, secured, and maintained. Intended for future contributors or hiring managers reviewing the architecture.

# 📘 Internal Developer Instructions — PhishGuard

PhishGuard is a modular SOAR-style tool designed to automate phishing detection, enrichment, alerting, and triage. This guide explains the internal architecture, naming conventions, and dev workflows.

---

## 🔧 Secure Coding Standards

- Follow best practices from **OWASP**, **NIST**, and **CERT**
- All input/output must be sanitized
- No secrets should be hardcoded
- Logging must not expose sensitive data
- Use `.env` + `.gitignore` to manage secrets

---

## 📁 Project Structure Overview

```
phishguard/
├── phishguard.py            # Entry point script
├── .env / .env.example      # API secrets (never commit .env)
├── requirements.txt         # All Python dependencies
│
├── gmail_reader.py          # Gmail API OAuth + message fetch
├── ioc_extractor.py         # Extracts URLs/IPs/Domains from body
├── osint_lookup.py          # VirusTotal + AbuseIPDB enrichment
├── risk_score.py            # Scoring system for phishing detection
├── label_manager.py         # Gmail label creation & application
├── alert.py                 # Sends Slack alerts
│
├── utils/
│   └── logger.py            # Logging via rotating log files
│
└── docs/
    ├── README.md            # Public-facing GitHub overview
    └── instructions.md      # This file (internal dev guide)
```

---

## 🔠 Naming Conventions

| Type        | Format            | Example                         |
|-------------|-------------------|----------------------------------|
| Python files | `snake_case.py`   | `ioc_extractor.py`              |
| Configs     | `credentials-*.json`, `.env` | `credentials-gmail.json` |
| Functions   | snake_case        | `extract_iocs_from_email()`     |
| Classes     | PascalCase        | `EmailScanner`, if added later  |
| Logs        | `/logs/phishguard.log` | Rotating logs, auto-created   |

---

## ⚙️ Environment Variables (`.env`)

Used for local secret management. DO NOT COMMIT `.env`.

```
VT_API_KEY=
ABUSEIPDB_KEY=
SLACK_WEBHOOK_URL=
```

See `.env.example` for required keys.

---

## 🔄 Development Workflow

1. Clone project / pull latest changes
2. Create `.env` file using `.env.example`
3. Install dependencies: `pip install -r requirements.txt`
4. Run via: `python3 phishguard.py`
5. Check output in console and logs
6. Review Slack channel for alerts

---

## ✅ Code Responsibilities

| Module         | Purpose |
|----------------|---------|
| `phishguard.py` | Orchestrates the full pipeline |
| `gmail_reader.py` | Auth + unread email retrieval |
| `ioc_extractor.py` | Regex-based IOC detection |
| `osint_lookup.py` | Uses APIs to verify threats |
| `risk_score.py` | Assigns severity |
| `label_manager.py` | Tags dangerous messages |
| `alert.py` | Sends Slack messages |
| `logger.py` | Tracks logs in `/logs` |

---

## 🧠 Future Notes

- Consider adding a `phishguard_setup.py` for interactive `.env` creation
- Future versions may include attachments, sandbox analysis, or integration with TheHive

---

## 📄 License

This is a private SOC portfolio project. For licensing and reuse, please contact the original author.
