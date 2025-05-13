# 🛡️ PhishGuard

**PhishGuard** is a modular, automated phishing detection and alerting tool designed for SOC analysts, blue teamers, and cybersecurity professionals. It integrates with Gmail, enriches IOCs using VirusTotal and AbuseIPDB, scores threat levels, applies Gmail labels, and sends real-time alerts to Slack.

---

## 🚀 Features

- ✅ Gmail API integration with OAuth2
- ✅ IOC extraction (URLs, IPs, Domains) from emails
- ✅ VirusTotal and AbuseIPDB enrichment
- ✅ Risk scoring engine (low, suspicious, phishing)
- ✅ Gmail labeling for flagged messages
- ✅ Slack alert integration via webhook
- 🪵 Rotating log files via `logger.py` (stored in `/logs`)
- 🔐 `.env`-based API key management
- 📦 Modular architecture for easy expansion

---

## 📁 Folder Structure

```
phishguard/
├── phishguard.py            # Entry point script
├── credentials-gmail.json   # OAuth credentials (NOT committed)
├── .env                     # API keys and secrets (NOT committed)
├── .env.example             # Template for required env variables
├── requirements.txt         # Dependencies
│
├── gmail_reader.py          # Gmail API integration
├── ioc_extractor.py         # IOC parsing from email bodies
├── osint_lookup.py          # Threat enrichment via VirusTotal/AbuseIPDB
├── risk_score.py            # Risk level calculation logic
├── alert.py                 # Sends alerts to Slack
├── label_manager.py         # Applies Gmail label to phishing messages
│
├── utils/
│   └── logger.py            # Logging via rotating log files
│
└── docs/
    ├── README.md            # This file
    └── instructions.md      # Internal developer guide
```

---

## ⚙️ Requirements

- Python 3.11+
- Gmail API credentials
- VirusTotal API Key
- AbuseIPDB API Key (optional but recommended)
- Slack Webhook URL

---

## 🔐 Environment Variables (`.env`)

Create a `.env` file in the root folder:

```
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

A safe public template is included as `.env.example`.

---

## 🧪 Usage

```bash
python3 phishguard.py
```

The tool will:
1. Fetch unread emails
2. Extract IOCs
3. Enrich and score threats
4. Apply Gmail label to phishing messages
5. Send Slack alert if phishing is confirmed

---

## 🪵 Logging

PhishGuard uses a rotating file logger to persist detections, errors, and risk assessments to disk.

- Logs are stored in: `logs/phishguard.log`
- Each log entry includes a timestamp, log level, and message
- Automatically rotates logs every 1MB (up to 3 backups)

This makes the tool production-ready for SOC use cases and long-term triage or investigations.

---

## 📷 Example Output (Console)

```
📨 From: alerts@paypal-login-check.com
Subject: Urgent Action Required

🔍 Extracted IOCs:
  urls: ['http://paypal-update-login.com/verify']
  ips: ['185.220.101.45']
  domains: ['paypal-update-login.com']

🧠 Enriched Results:
...
📊 Risk Assessment:
  Score: 9
  Level: PHISHING
  Reason: High malicious URL; AbuseIPDB confidence 97

🏷️  Gmail label applied: ⚠️ PHISHING ALERT
📣 Slack alert sent.
```

---

## 🧱 Architecture

Each component is separated by role and fully modular:
- Easy to extend with new enrichment providers
- Supports CLI or automation workflows (e.g. cron)
- Designed for real-world SOC environments

---

## 🛡️ Security Notes

- All secrets and keys are environment-based
- No secrets are ever committed to the repo
- `.gitignore` prevents leaking sensitive info
- Token-based Gmail access is stored locally in `token.json`

---

## 📌 Roadmap

- [ ] HTML report export
- [ ] CLI options for dry run / phishing-only
- [ ] Version 2 setup wizard for `.env` + config
- [ ] Optional VirusTotal upload for attachments
- [ ] Jira/SOAR ticketing support

---

## 🤝 Contributing

Pull requests are welcome!

If you'd like to contribute:
- Fork the repo
- Create a feature branch
- Submit a clean pull request
- Please follow the modular structure and secure coding practices outlined in `docs/instructions.md`

---

## 🧠 Credits

Created by a security automation enthusiast building a SOC analyst portfolio.

---

## 📄 License

MIT License (feel free to use/extend responsibly)
