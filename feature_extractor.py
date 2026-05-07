"""
PhishGuard — URL Feature Extractor (No API key required)
Extracts 20 security-grounded features from a URL.
"""

import re
import math
from urllib.parse import urlparse

# Common legitimate TLDs vs suspicious ones
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan', '.work'}
BRAND_KEYWORDS = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
                  'instagram', 'netflix', 'bank', 'secure', 'account', 'login', 'verify']

def entropy(s: str) -> float:
    """Shannon entropy of a string — high entropy = random/obfuscated."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def extract_features(url: str) -> dict:
    """Returns a dict of 20 features for a given URL."""
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    except Exception:
        parsed = urlparse('http://invalid')

    domain    = parsed.netloc or ''
    path      = parsed.path or ''
    query     = parsed.query or ''
    full_url  = url

    # Strip port from domain for TLD check
    domain_clean = domain.split(':')[0]
    parts = domain_clean.split('.')
    tld = '.' + parts[-1] if len(parts) > 1 else ''

    # Subdomain count
    subdomain_count = max(0, len(parts) - 2)

    # IP address as domain
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    has_ip = int(bool(ip_pattern.match(domain_clean)))

    # URL length features
    url_length   = len(full_url)
    domain_length = len(domain_clean)

    # Special character counts
    dot_count    = full_url.count('.')
    hyphen_count = full_url.count('-')
    at_count     = full_url.count('@')
    eq_count     = full_url.count('=')
    amp_count    = full_url.count('&')
    slash_count  = full_url.count('/')

    # HTTPS
    has_https = int(parsed.scheme == 'https')

    # Suspicious TLD
    suspicious_tld = int(tld.lower() in SUSPICIOUS_TLDS)

    # Brand keyword in domain (typosquatting signal)
    brand_in_domain = int(any(kw in domain_clean.lower() for kw in BRAND_KEYWORDS))

    # Entropy of domain (high = likely random/DGA)
    domain_entropy = round(entropy(domain_clean), 4)

    # Path depth
    path_depth = len([p for p in path.split('/') if p])

    # Query string length
    query_length = len(query)

    # Double slash in path (except after scheme)
    double_slash = int('//' in path)

    # Hex encoding in URL
    has_hex = int('%' in full_url)

    # Digit ratio in domain
    digits_in_domain = sum(c.isdigit() for c in domain_clean)
    digit_ratio = round(digits_in_domain / max(len(domain_clean), 1), 4)

    features = {
        'url_length':       url_length,
        'domain_length':    domain_length,
        'has_https':        has_https,
        'has_ip':           has_ip,
        'dot_count':        dot_count,
        'hyphen_count':     hyphen_count,
        'at_count':         at_count,
        'eq_count':         eq_count,
        'amp_count':        amp_count,
        'slash_count':      slash_count,
        'subdomain_count':  subdomain_count,
        'suspicious_tld':   suspicious_tld,
        'brand_in_domain':  brand_in_domain,
        'domain_entropy':   domain_entropy,
        'path_depth':       path_depth,
        'query_length':     query_length,
        'double_slash':     double_slash,
        'has_hex':          has_hex,
        'digit_ratio':      digit_ratio,
        'url_entropy':      round(entropy(full_url), 4),
    }
    return features

FEATURE_NAMES = list(extract_features('http://example.com').keys())
