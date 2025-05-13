def calculate_risk_score(enriched_data: dict) -> dict:
    """
    Calculates a threat score and label based on enriched IOC data.

    Args:
        enriched_data (dict): Results from osint_lookup.enrich_iocs()

    Returns:
        dict: Includes score, severity level, and justification
    """
    score = 0
    malicious_urls = []
    malicious_domains = []
    malicious_ips = []
    reasons = []

    # URLs
    for url, data in enriched_data.get("urls", {}).items():
        if data.get("malicious", 0) >= 5:
            score += 3
            malicious_urls.append(url)
            reasons.append(f"High malicious URL: {url}")
        elif data.get("malicious", 0) >= 1 or data.get("suspicious", 0) >= 2:
            score += 2
            malicious_urls.append(url)

    # Domains
    for domain, data in enriched_data.get("domains", {}).items():
        if data.get("malicious", 0) >= 5:
            score += 3
            malicious_domains.append(domain)
            reasons.append(f"High malicious domain: {domain}")
        elif data.get("malicious", 0) >= 1:
            score += 2
            malicious_domains.append(domain)

    # IPs
    for ip, data in enriched_data.get("ips", {}).items():
        if data.get("vt_malicious", 0) >= 5:
            score += 3
            malicious_ips.append(ip)
            reasons.append(f"VT flagged IP: {ip}")
        elif data.get("vt_malicious", 0) >= 1:
            score += 2
            malicious_ips.append(ip)

        if data.get("abuse_confidence_score", 0) >= 90:
            score += 3
            reasons.append(f"AbuseIPDB flagged IP: {ip}")
        elif data.get("abuse_confidence_score", 0) >= 70:
            score += 2

    # Assign level
    if score >= 7:
        level = "phishing"
    elif score >= 3:
        level = "suspicious"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "details": {
            "malicious_urls": malicious_urls,
            "malicious_domains": malicious_domains,
            "malicious_ips": malicious_ips,
            "reason": "; ".join(reasons)
        }
    }
