import os
import requests
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(subject, sender, score, risk_level, iocs):
    """
    Sends a phishing alert message to a Slack channel using webhook.
    """
    if not SLACK_WEBHOOK_URL:
        print("[!] Slack webhook not configured.")
        return

    color = "#ff0000" if risk_level == "phishing" else "#ffa500"

    message = {
        "attachments": [
            {
                "fallback": f"[PhishGuard] {risk_level.upper()} alert",
                "color": color,
                "title": "⚠️ Suspected Phishing Email Detected",
                "fields": [
                    {"title": "From", "value": sender, "short": True},
                    {"title": "Subject", "value": subject, "short": True},
                    {"title": "Risk Level", "value": risk_level.upper(), "short": True},
                    {"title": "Threat Score", "value": str(score), "short": True},
                    {"title": "URLs", "value": "\n".join(iocs.get("urls", [])[:3]) or "None", "short": False},
                    {"title": "IPs", "value": "\n".join(iocs.get("ips", [])[:3]) or "None", "short": False},
                    {"title": "Domains", "value": "\n".join(iocs.get("domains", [])[:3]) or "None", "short": False},
                ],
                "footer": "PhishGuard SOAR Bot",
            }
        ]
    }

    try:
        res = requests.post(SLACK_WEBHOOK_URL, json=message)
        if res.status_code != 200:
            print(f"[!] Failed to send Slack alert: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[!] Error sending Slack alert: {e}")
