"""
Phishing Email Forensics — Analysis Engine
Cryptography and Network Security / SOC Project

Parses raw .eml files and extracts indicators of compromise (IOCs):
headers, authentication results (SPF/DKIM/DMARC), URLs, IPs, domains,
lookalike-domain matches, attachment risk, and urgency-language cues.
Produces a risk score and a structured report — entirely offline,
using only Python's standard library.
"""

import re
import difflib
from email import message_from_bytes, policy
from email.utils import parseaddr, getaddresses

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

KNOWN_BRAND_DOMAINS = {
    'paypal.com', 'microsoft.com', 'apple.com', 'google.com', 'amazon.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'netflix.com',
    'dhl.com', 'fedex.com', 'ups.com', 'irs.gov', 'linkedin.com',
    'facebook.com', 'instagram.com', 'outlook.com', 'office365.com',
    'dropbox.com', 'docusign.com',
}

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'verify your account', 'suspended', 'act now',
    'final notice', 'click here', 'confirm your identity', 'unauthorized access',
    'limited time', 'failure to', 'will be closed', 'security alert',
    'unusual activity', 'restricted', 'reactivate', 'expire', 'locked',
]

RISKY_ATTACHMENT_EXTENSIONS = {
    '.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.jar',
    '.hta', '.lnk', '.docm', '.xlsm', '.zip', '.iso', '.img',
    '.html', '.htm',
}

URL_REGEX = re.compile(r'https?://[^\s\'"<>\)\]]+', re.IGNORECASE)
IP_URL_REGEX = re.compile(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def load_email(filepath):
    with open(filepath, 'rb') as f:
        return message_from_bytes(f.read(), policy=policy.default)


def get_domain(email_address):
    if '@' in email_address:
        return email_address.split('@')[-1].lower().strip('>')
    return ''


def extract_headers(msg):
    return {
        'from': msg.get('From', ''),
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'to': msg.get('To', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'message_id': msg.get('Message-ID', ''),
        'received': msg.get_all('Received', []),
    }


def parse_auth_results(msg):
    """Look for an Authentication-Results header and pull out SPF/DKIM/DMARC
    verdicts if present."""
    auth_header = msg.get('Authentication-Results', '')
    result = {'spf': 'not found', 'dkim': 'not found', 'dmarc': 'not found', 'raw': auth_header}

    for mechanism in ('spf', 'dkim', 'dmarc'):
        match = re.search(rf'{mechanism}=(\w+)', auth_header, re.IGNORECASE)
        if match:
            result[mechanism] = match.group(1).lower()
    return result


def get_body_text(msg):
    """Walk the MIME tree and concatenate all text/plain and text/html parts."""
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ('text/plain', 'text/html'):
                try:
                    chunks.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            chunks.append(msg.get_content())
        except Exception:
            pass
    return '\n'.join(chunks)


def extract_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                attachments.append({
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'risky': ext in RISKY_ATTACHMENT_EXTENSIONS,
                })
    return attachments


def extract_urls(body_text):
    urls = list(dict.fromkeys(URL_REGEX.findall(body_text)))  # de-dupe, keep order
    return urls


def extract_domains(urls):
    domains = set()
    for url in urls:
        cleaned = url.replace('https://', '').replace('http://', '')
        domain = cleaned.split('/')[0].split('?')[0].lower()
        domain = domain.split(':')[0]  # strip port
        domains.add(domain)
    return sorted(domains)


def extract_ip_urls(urls):
    return [url for url in urls if IP_URL_REGEX.match(url)]


def check_lookalike_domains(domains, threshold=0.75):
    flagged = []
    for domain in domains:
        if domain in KNOWN_BRAND_DOMAINS:
            continue
        for brand in KNOWN_BRAND_DOMAINS:
            ratio = difflib.SequenceMatcher(None, domain, brand).ratio()
            if ratio >= threshold:
                flagged.append({'domain': domain, 'resembles': brand, 'similarity': round(ratio, 2)})
                break
    return flagged


def check_display_name_mismatch(msg):
    """Flag cases where the visible display name implies one organization
    but the actual email address belongs to a different domain."""
    raw_from = msg.get('From', '')
    display_name, addr = parseaddr(raw_from)
    domain = get_domain(addr)

    flagged_brand = None
    if display_name:
        name_lower = display_name.lower()
        for brand in KNOWN_BRAND_DOMAINS:
            brand_name = brand.split('.')[0]
            if brand_name in name_lower and domain != brand:
                flagged_brand = brand
                break

    return {
        'display_name': display_name,
        'address': addr,
        'domain': domain,
        'mismatch': flagged_brand is not None,
        'implied_brand': flagged_brand,
    }


def check_reply_to_mismatch(msg):
    from_addr = parseaddr(msg.get('From', ''))[1]
    reply_addr = parseaddr(msg.get('Reply-To', ''))[1]
    from_domain = get_domain(from_addr)
    reply_domain = get_domain(reply_addr)

    return {
        'from_domain': from_domain,
        'reply_domain': reply_domain,
        'mismatch': bool(reply_domain) and reply_domain != from_domain,
    }


def detect_urgency_language(body_text):
    text_lower = body_text.lower()
    return [kw for kw in URGENCY_KEYWORDS if kw in text_lower]


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def compute_risk_score(findings):
    score = 0
    reasons = []

    auth = findings['auth_results']
    if auth['spf'] in ('fail', 'softfail'):
        score += 20
        reasons.append(f"SPF check: {auth['spf']}")
    if auth['dkim'] == 'fail':
        score += 15
        reasons.append("DKIM check: fail")
    if auth['dmarc'] == 'fail':
        score += 15
        reasons.append("DMARC check: fail")

    if findings['display_name_check']['mismatch']:
        score += 20
        reasons.append(
            f"Display name impersonates {findings['display_name_check']['implied_brand']} "
            f"but sends from {findings['display_name_check']['domain']}"
        )

    if findings['reply_to_check']['mismatch']:
        score += 10
        reasons.append("Reply-To domain differs from From domain")

    if findings['lookalike_domains']:
        score += 15
        reasons.append(f"{len(findings['lookalike_domains'])} lookalike domain(s) found in body")

    if findings['ip_urls']:
        score += 15
        reasons.append("URL uses a raw IP address instead of a domain")

    if findings['urgency_keywords']:
        score += min(10, 2 * len(findings['urgency_keywords']))
        reasons.append(f"{len(findings['urgency_keywords'])} urgency-language cue(s) detected")

    risky_attachments = [a for a in findings['attachments'] if a['risky']]
    if risky_attachments:
        score += 25
        reasons.append(f"{len(risky_attachments)} high-risk attachment(s)")

    score = min(score, 100)

    if score >= 70:
        verdict = 'MALICIOUS — High confidence phishing'
    elif score >= 40:
        verdict = 'SUSPICIOUS — Treat as phishing pending review'
    elif score >= 15:
        verdict = 'LOW RISK — Minor anomalies, monitor'
    else:
        verdict = 'CLEAN — No significant indicators found'

    return {'score': score, 'verdict': verdict, 'reasons': reasons}


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def analyze_eml(filepath):
    msg = load_email(filepath)
    body_text = get_body_text(msg)
    urls = extract_urls(body_text)
    domains = extract_domains(urls)

    findings = {
        'headers': extract_headers(msg),
        'auth_results': parse_auth_results(msg),
        'urls': urls,
        'domains': domains,
        'ip_urls': extract_ip_urls(urls),
        'lookalike_domains': check_lookalike_domains(domains),
        'display_name_check': check_display_name_mismatch(msg),
        'reply_to_check': check_reply_to_mismatch(msg),
        'urgency_keywords': detect_urgency_language(body_text),
        'attachments': extract_attachments(msg),
    }
    findings['risk'] = compute_risk_score(findings)
    return findings
