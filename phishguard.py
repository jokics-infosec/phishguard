from gmail_reader import get_gmail_service, fetch_unread_emails
from ioc_extractor import extract_iocs_from_email
from osint_lookup import enrich_iocs
from risk_score import calculate_risk_score
from label_manager import get_or_create_label, apply_label
from alert import send_slack_alert
from utils.logger import setup_logger

log = setup_logger()

def main():
    # Initialize Gmail API client
    service = get_gmail_service()

    # Fetch unread emails from the inbox
    emails = fetch_unread_emails(service)

    if not emails:
        log.info("No new unread emails found.")
        return

    for email in emails:
        print("=" * 80)
        print(f"📨 From: {email['from']}")
        print(f"Subject: {email['subject']}")

        # Step 1: Extract Indicators of Compromise (IOCs)
        iocs = extract_iocs_from_email(email["body"])
        print("\n🔍 Extracted IOCs:")
        for ioc_type, values in iocs.items():
            print(f"  {ioc_type}: {values}")

        # Step 2: Enrich IOCs using VirusTotal and AbuseIPDB
        enrichment = enrich_iocs(iocs)
        print("\n🧠 Enriched Results:")
        for ioc_type, entries in enrichment.items():
            if not entries:
                continue
            print(f"\n== {ioc_type.upper()} ==")
            for indicator, data in entries.items():
                print(f"→ {indicator}")
                for key, value in data.items():
                    print(f"    {key}: {value}")

        # Step 3: Analyze risk score based on enrichment results
        risk = calculate_risk_score(enrichment)
        print("\n📊 Risk Assessment:")
        print(f"  Score: {risk['score']}")
        print(f"  Level: {risk['level'].upper()}")
        print(f"  Reason: {risk['details']['reason']}")

        # Log summary to file
        log.info(
            f"Sender: {email['from']} | Subject: {email['subject']} | "
            f"Risk Level: {risk['level'].upper()} | Score: {risk['score']}"
        )

        # Step 4: Apply Gmail label and send Slack alert if phishing
        if risk["level"] == "phishing":
            label_id = get_or_create_label(service)
            apply_label(service, email["id"], label_id)
            print("🏷️  Gmail label applied: ⚠️ PHISHING ALERT")
            log.info("Gmail label applied to message ID: " + email["id"])

            send_slack_alert(
                subject=email["subject"],
                sender=email["from"],
                score=risk["score"],
                risk_level=risk["level"],
                iocs=iocs
            )
            print("📣 Slack alert sent.")
            log.info("Slack alert sent for phishing email.")

        print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
