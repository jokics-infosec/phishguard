import re
from email.message import Message

def extract_iocs_from_email(email_body: Message) -> dict:
    """
    Extracts URLs, IPs, and domains from an email MIME body.

    Args:
        email_body (email.message.Message): Full MIME email object

    Returns:
        dict: {
            'urls': [...],
            'ips': [...],
            'domains': [...]
        }
    """
    text = extract_text_body(email_body)

    # Regex patterns
    url_pattern = r'https?://[^\s<>"\'\]\)]+'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

    urls = re.findall(url_pattern, text)
    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)

    return {
        "urls": list(set(urls)),
        "ips": list(set(ips)),
        "domains": list(set(domains))
    }

def extract_text_body(msg: Message) -> str:
    """
    Extracts plain text from email body, falling back to HTML if needed.

    Args:
        msg (email.message.Message): MIME message

    Returns:
        str: plain text string
    """
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                continue
            if content_type == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
            elif content_type == "text/html":
                return strip_html(part.get_payload(decode=True).decode(errors="ignore"))
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")

    return ""

def strip_html(html: str) -> str:
    """
    Strips HTML tags for simple fallback parsing.

    Args:
        html (str): Raw HTML

    Returns:
        str: Plain text
    """
    return re.sub('<[^<]+?>', '', html)

