"""
PhishGuard — Real-Time Scanner (Zero API Keys Required)
Runs 5 parallel checks: DNS · WHOIS · SSL · Redirects · Blacklist
"""

import socket
import ssl
import datetime
import urllib.request
import urllib.error
import concurrent.futures
import re
from urllib.parse import urlparse

# ── Free community phishing feed (no key needed) ─────────────────────────────
OPENPHISH_FEED = "https://openphish.com/feed.txt"

_cached_blacklist: set = set()
_blacklist_loaded = False

def _load_blacklist():
    global _cached_blacklist, _blacklist_loaded
    if _blacklist_loaded:
        return
    try:
        req = urllib.request.Request(OPENPHISH_FEED,
              headers={'User-Agent': 'PhishGuard/2.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = r.read().decode('utf-8', errors='ignore')
        _cached_blacklist = set(line.strip() for line in data.splitlines() if line.strip())
        _blacklist_loaded = True
    except Exception:
        _blacklist_loaded = True  # don't retry on error


# ── Individual checks ─────────────────────────────────────────────────────────

def check_dns(domain: str) -> dict:
    result = {'status': 'unknown', 'ip': None, 'resolves': False, 'risk': 0}
    try:
        ip = socket.gethostbyname(domain)
        result.update({'status': 'ok', 'ip': ip, 'resolves': True, 'risk': 0})
        # IP-literal domain = high risk
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            result['risk'] = 40
            result['status'] = 'ip_literal'
    except socket.gaierror:
        result.update({'status': 'no_resolve', 'resolves': False, 'risk': 50})
    except Exception as e:
        result.update({'status': f'error: {e}', 'risk': 20})
    return result


def check_ssl(domain: str, port: int = 443) -> dict:
    result = {'valid': False, 'issuer': None, 'expires': None,
              'days_left': None, 'risk': 0, 'status': 'unknown'}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, port), timeout=5),
                             server_hostname=domain) as s:
            cert = s.getpeercert()

        # Parse expiry
        exp_str = cert.get('notAfter', '')
        exp = datetime.datetime.strptime(exp_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (exp - datetime.datetime.utcnow()).days

        # Parse issuer
        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        issuer = issuer_dict.get('organizationName', 'Unknown')

        risk = 0
        if days_left < 0:
            risk = 50; status = 'expired'
        elif days_left < 30:
            risk = 25; status = 'expiring_soon'
        else:
            status = 'valid'

        result.update({'valid': True, 'issuer': issuer, 'expires': exp_str,
                       'days_left': days_left, 'risk': risk, 'status': status})
    except ssl.SSLCertVerificationError:
        result.update({'valid': False, 'risk': 60, 'status': 'invalid_cert'})
    except (ConnectionRefusedError, socket.timeout, OSError):
        result.update({'valid': False, 'risk': 15, 'status': 'no_ssl'})
    except Exception as e:
        result.update({'valid': False, 'risk': 10, 'status': f'error: {e}'})
    return result


def check_redirects(url: str) -> dict:
    result = {'hops': [], 'final_url': url, 'hop_count': 0, 'risk': 0,
              'cross_domain': False, 'status': 'ok'}
    try:
        if not url.startswith('http'):
            url = 'https://' + url
        original_domain = urlparse(url).netloc

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        hops = [url]
        current = url

        for _ in range(10):
            req = urllib.request.Request(current,
                  headers={'User-Agent': 'Mozilla/5.0 PhishGuard'})
            try:
                with opener.open(req, timeout=4) as r:
                    final = r.url
                    hops.append(final)
                    current = final
                    break
            except urllib.error.HTTPError as e:
                loc = e.headers.get('Location', '')
                if loc:
                    hops.append(loc)
                    current = loc
                else:
                    break

        final_domain = urlparse(current).netloc
        cross = original_domain != final_domain and final_domain != ''

        risk = min(len(hops) * 5, 30)
        if cross:
            risk += 20

        result.update({'hops': hops, 'final_url': current,
                       'hop_count': len(hops) - 1,
                       'cross_domain': cross, 'risk': risk})
    except Exception as e:
        result.update({'status': f'error: {e}', 'risk': 0})
    return result


def check_blacklist(url: str) -> dict:
    _load_blacklist()
    hit = url.strip() in _cached_blacklist
    # Also check domain-level
    try:
        domain = urlparse(url).netloc
        domain_hit = any(domain in entry for entry in _cached_blacklist)
    except Exception:
        domain_hit = False

    flagged = hit or domain_hit
    return {
        'blacklisted': flagged,
        'source': 'OpenPhish' if flagged else 'none',
        'risk': 100 if flagged else 0,
        'status': 'BLACKLISTED' if flagged else 'clean'
    }


def check_whois_age(domain: str) -> dict:
    """
    Lightweight WHOIS via python-whois library.
    Falls back gracefully if not installed.
    """
    result = {'age_days': None, 'created': None, 'risk': 0, 'status': 'unknown'}
    try:
        import whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.datetime.utcnow() - created).days
            risk = 0
            if age < 30:
                risk = 50
            elif age < 90:
                risk = 20
            result.update({
                'age_days': age,
                'created': str(created)[:10],
                'risk': risk,
                'status': 'new_domain' if age < 30 else 'ok'
            })
    except ImportError:
        result['status'] = 'whois_not_installed'
    except Exception as e:
        result['status'] = f'error: {str(e)[:60]}'
    return result


# ── Master scanner ─────────────────────────────────────────────────────────────

def run_all_checks(url: str) -> dict:
    """Run all 5 checks in parallel, return combined report."""
    if not url.startswith('http'):
        url = 'https://' + url
    domain = urlparse(url).netloc.split(':')[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            'dns':       ex.submit(check_dns, domain),
            'ssl':       ex.submit(check_ssl, domain),
            'redirects': ex.submit(check_redirects, url),
            'blacklist': ex.submit(check_blacklist, url),
            'whois':     ex.submit(check_whois_age, domain),
        }
        results = {k: f.result() for k, f in futures.items()}

    return results
