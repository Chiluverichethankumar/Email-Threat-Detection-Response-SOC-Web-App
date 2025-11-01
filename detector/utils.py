import os, email, re, dns.resolver, dkim, requests
from bs4 import BeautifulSoup
from email import policy
import difflib

VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'   # ← CHANGE THIS!
KNOWN_DOMAINS = ['google.com', 'microsoft.com', 'apple.com']
PHISHING_KEYWORDS = ['urgent', 'verify your account', 'click here', 'password reset', 'bank account', 'login now']
SCORE_THRESHOLD_MALICIOUS = 7
SCORE_THRESHOLD_SUSPICIOUS = 4

def extract_urls(body):
    soup = BeautifulSoup(body, 'lxml')
    return [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith(('http://', 'https://'))]

def check_domain_impersonation(domain):
    for known in KNOWN_DOMAINS:
        if difflib.SequenceMatcher(None, domain.lower(), known.lower()).ratio() > 0.8:
            if domain.lower() != known.lower():
                return True
    return False

def check_spf(sender_domain, received_ip):
    try:
        records = dns.resolver.resolve(sender_domain, 'TXT')
        for r in records:
            txt = str(r).strip('"')
            if txt.startswith('v=spf1') and received_ip in txt:
                return True
        return False
    except:
        return False

def check_dkim(raw_email):
    try:
        return dkim.verify(raw_email)
    except:
        return False

def scan_url_vt(url):
    try:
        resp = requests.get(
            'https://www.virustotal.com/vtapi/v2/url/report',
            params={'apikey': VIRUSTOTAL_API_KEY, 'resource': url},
            timeout=10
        )
        data = resp.json()
        return data.get('positives', 0) > 0
    except:
        return False

def analyze_email_file(file_path):
    with open(file_path, 'rb') as f:
        raw = f.read()
        msg = email.message_from_bytes(raw, policy=policy.default)

    from_addr = msg['From'] or ''
    subject = msg['Subject'] or ''
    received = msg.get('Received', '')
    sender_domain = from_addr.split('@')[-1] if '@' in from_addr else ''
    ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
    received_ip = ip_match.group(1) if ip_match else ''

    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode(errors='ignore')
                break
            elif part.get_content_type() == 'text/html' and not body:
                body = part.get_payload(decode=True).decode(errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')

    score = 0
    issues = []

    if sender_domain and check_domain_impersonation(sender_domain):
        score += 3
        issues.append("Domain impersonation")
    if sender_domain and received_ip and not check_spf(sender_domain, received_ip):
        score += 2
        issues.append("SPF failed")
    if not check_dkim(raw):
        score += 2
        issues.append("DKIM failed")

    kw_count = sum(1 for kw in PHISHING_KEYWORDS if kw.lower() in body.lower())
    if kw_count > 2:
        score += 2
        issues.append(f"{kw_count} phishing keywords")

    urls = extract_urls(body)
    for url in urls:
        if not url.startswith('https://'):
            score += 1
            issues.append("Non-HTTPS link")
        if scan_url_vt(url):
            score += 3
            issues.append("Malicious URL (VT)")

    if score >= SCORE_THRESHOLD_MALICIOUS:
        classification = "Malicious"
        quarantine_path = os.path.join('quarantine', os.path.basename(file_path))
        os.makedirs('quarantine', exist_ok=True)
        os.replace(file_path, quarantine_path)
    elif score >= SCORE_THRESHOLD_SUSPICIOUS:
        classification = "Suspicious"
    else:
        classification = "Legitimate"

    return {
        'classification': classification,
        'score': score,
        'issues': ', '.join(issues) if issues else 'None',
        'raw_email': raw.decode(errors='ignore'),
        'subject': subject,
        'from_addr': from_addr
    }