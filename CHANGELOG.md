# 📜 Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.0.0] - 2024-04-19

🎉 Initial public release of **PhishGuard**

### 🚀 Features
- Gmail API OAuth2 integration for reading unread messages
- Modular IOC extraction from email body (`urls`, `ips`, `domains`)
- VirusTotal and AbuseIPDB integration for IOC enrichment
- Risk scoring system based on enrichment metadata
- Automated Gmail label tagging (`⚠️ PHISHING ALERT`)
- Slack alert integration via webhook
- Rotating file logger (`logs/phishguard.log`) with timestamps and severity levels
- Secure `.env` configuration handling
- GitHub-ready documentation:
  - `README.md` for usage
  - `instructions.md` for internal dev standards
  - `LICENSE` with MIT license
  - `.env.example` for safe sharing
- Git-tracked `.gitignore` to protect credentials and tokens

### 📁 Structure
- Modular codebase in Python
- Supports developer onboarding and future version upgrades
- Cleanly separated logging, alerting, scoring, and enrichment logic

---

## [Unreleased]

### ✨ Planned for `v1.1.0`
- CLI flags for dry-run or phishing-only mode
- Export results as CSV or HTML reports
- Add simple unit tests for key modules
- Add support for attachments or base64 parsing
- Integrate with TheHive or Jira for SOC ticketing

