import os
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

VT_HEADERS = {"x-apikey": VT_API_KEY}
ABUSE_HEADERS = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}


def enrich_iocs(iocs: dict) -> dict:
    """
    Enriches URLs, domains, and IPs using VirusTotal and AbuseIPDB.

    Args:
        iocs (dict): Contains keys 'urls', 'domains', 'ips' with lists of values.

    Returns:
        dict: Enrichment results.
    """
    results = {"urls": {}, "domains": {}, "ips": {}}

    # --- Enrich URLs ---
    for url in iocs.get("urls", []):
        encoded_url = requests.utils.quote(url, safe="")
        url_id = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        try:
            res = requests.get(url_id, headers=VT_HEADERS)
            if res.ok:
                data = res.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                results["urls"][url] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "scan_date": data["data"]["attributes"].get("last_analysis_date"),
                }
        except Exception as e:
            results["urls"][url] = {"error": str(e)}

    # --- Enrich Domains ---
    for domain in iocs.get("domains", []):
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        try:
            res = requests.get(vt_url, headers=VT_HEADERS)
            if res.ok:
                data = res.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                results["domains"][domain] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "categories": data["data"]["attributes"].get("categories", {}),
                }
        except Exception as e:
            results["domains"][domain] = {"error": str(e)}

    # --- Enrich IPs ---
    for ip in iocs.get("ips", []):
        ip_data = {}

        # VirusTotal IP check
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        try:
            res = requests.get(vt_url, headers=VT_HEADERS)
            if res.ok:
                data = res.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                ip_data["vt_malicious"] = stats.get("malicious", 0)
                ip_data["country"] = data["data"]["attributes"].get("country")
                ip_data["network"] = data["data"]["attributes"].get("network")
        except Exception as e:
            ip_data["vt_error"] = str(e)

        # AbuseIPDB IP check
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        try:
            res = requests.get(abuse_url, headers=ABUSE_HEADERS)
            if res.ok:
                data = res.json()
                abuse_data = data.get("data", {})
                ip_data["abuse_confidence_score"] = abuse_data.get("abuseConfidenceScore")
                ip_data["abuse_country"] = abuse_data.get("countryCode")
                ip_data["abuse_usage_type"] = abuse_data.get("usageType")
                ip_data["abuse_total_reports"] = abuse_data.get("totalReports")
        except Exception as e:
            ip_data["abuse_error"] = str(e)

        results["ips"][ip] = ip_data

    return results
