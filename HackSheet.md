# Professional Pentest & AppSec Cheatsheet (Ethical & Report-Ready)

> **Use only with explicit written authorization.** This guide is designed for **legal** security testing, labs, and CTFs. Every command or technique should be executed **within scope** and with appropriate approvals.

---

## Table of Contents
1. [Legal & Ethics Checklist](#legal--ethics-checklist)
2. [Engagement & Scoping](#engagement--scoping)
3. [Evidence Collection Standards](#evidence-collection-standards)
4. [High-Level Workflow](#high-level-workflow)
5. [Discovery & Recon](#discovery--recon)
6. [Network Scanning](#network-scanning)
7. [Service Enumeration](#service-enumeration)
8. [Web App Recon & Testing](#web-app-recon--testing)
9. [Credential & Access Hygiene](#credential--access-hygiene)
10. [Vulnerability Validation (Safe PoCs)](#vulnerability-validation-safe-pocs)
11. [Blue-Team: Detections & Mitigations](#blue-team-detections--mitigations)
12. [Reporting Templates](#reporting-templates)
13. [Appendix: Useful Tools](#appendix-useful-tools)

---

## Legal & Ethics Checklist
- ✅ **Authorization:** Signed SOW / Rules of Engagement (RoE) with explicit **scope** and **testing windows**.
- ✅ **Data Handling:** NDA signed; plan for sensitive data (PII/PHI) and retention schedule.
- ✅ **Impact Controls:** No production data tampering, DOS/Stress tests only when approved.
- ✅ **Communication:** Stakeholder contacts, escalation paths, change-control window.
- ✅ **Evidence Plan:** Screenshots, logs, timestamps, hashes, reproducible steps.

---

## Engagement & Scoping
- **Scope IDs**: IP ranges, domains, apps, APIs, cloud accounts, identities.
- **Out-of-scope**: Third-party apps, production databases, email spam tests (unless approved).
- **Success criteria**: What constitutes a valid finding? Which risks matter most?
- **Constraints**: Time windows, credentials provided, test accounts.

---

## Evidence Collection Standards
- **Timestamp** all activities (UTC).  
- **Hash** files you exfiltrate in *lab environments only* (e.g., SHA-256).  
- **Screenshots** + exact request/response pairs for web issues.  
- **Versioning**: Record tool versions, parameters, and environment (OS, VM).

---

## High-Level Workflow
1. **Discovery** → OSINT, DNS, certificate transparency, cloud asset discovery.  
2. **Scanning** → Safe port scan + service/version detection.  
3. **Enumeration** → Protocol-specific checks (SMB, NFS, LDAP, HTTP).  
4. **Validation** → Reproducible PoCs that **avoid impact** (read-only, controlled).  
5. **Risk Analysis** → Likelihood × Impact; affected assets; blast radius.  
6. **Reporting** → Executive summary + technical details + fixes.  
7. **Retest** → Verify remediations.

---

## Discovery & Recon
### DNS & CT (safe lookups)
```bash
whois example.com
dig A example.com +short
dig -x 203.0.113.10 +short
curl -s "https://crt.sh/?q=%25example.com&output=json" | jq length
```
**Capture:** domain, NS/MX, registrant privacy, cert SANs, subdomains.

### Tech Fingerprinting (non-invasive)
```bash
whatweb https://example.com
```

### Search Dorks (read-only)
- `site:example.com "index of"`  
- `site:example.com inurl:debug`

**Risk Note:** Keep queries read-only and non-invasive.

---

## Network Scanning
> Use **rate limits** and coordinate with defenders.

```bash
nmap -T3 -p- -sV -O --version-light -oA scans/base example.com
```
- **Capture:** open ports, services, versions; attach scan artifacts.

---

## Service Enumeration
### SMB (read-only listing when credentials provided)
```bash
smbclient -L //192.0.2.10 -U "user%Password!"   # List shares
```
### NFS
```bash
showmount -e 192.0.2.20
```
### SSH banner (non-auth)
```bash
nc -v example.com 22
```

**Do not** brute-force credentials unless explicitly allowed and rate-limited.

---

## Web App Recon & Testing
### Directory & File Discovery (throttled)
```bash
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 20 -rate 50 -o ffuf.json -of json
```
### robots.txt & Security Headers
```bash
curl -sI https://example.com | grep -Ei 'content-security-policy|x-frame-options|x-xss-protection|strict-transport-security'
```

### Client-side Checks
- Hidden inputs, comments, source maps (`.map`) leakage.
- JS endpoints and hardcoded API keys.

---

## Credential & Access Hygiene
- Use **provided** test accounts with least privilege.
- **Password spraying** only with **written approval**, small sets, long intervals.
- Never store plaintext credentials in reports—mask sensitive parts.

---

## Vulnerability Validation (Safe PoCs)
> Prefer **non-destructive** tests. Avoid data changes in production.

### Reflected XSS (benign proof)
```html
<script>console.log('xss-test-123')</script>
```
- Validate via console log **only**; do not exfiltrate cookies or data.

### SQL Injection (boolean-based, harmless)
```text
' OR '1'='1' -- 
```
- Confirm **authentication bypass risk** in a **non-prod** account if possible.
- **Capture:** parameter name, DBMS fingerprint (if any), and **no sensitive rows**.

### IDOR (access control)
- Use **two test users** and verify cross-access to a harmless resource (e.g., avatar).  
- **Capture:** exact URL/ID pattern; do **not** pull sensitive data.

### File Upload
- Upload benign text/image and test for extension/Content-Type enforcement.  
- **Do not** upload executables or shells to production.

---

## Blue-Team: Detections & Mitigations

### Network
- **Detect:** Nmap scan bursts; unusual source IPs; new TLS clients.  
- **Mitigate:** Rate limits; port-knocking; segmentation; IDS rules (Zeek/Suricata).

### Web
- **Detect:** Repeated 404s across many paths; abnormal user-agents.  
- **Mitigate:** WAF with virtual patches; strong CSP; strict cookies; input validation.

### Auth
- **Detect:** Spray/burst login attempts; geo impossible travel.  
- **Mitigate:** MFA; lockout policies; password hygiene; device posture checks.

### Data Exposure
- **Detect:** Access to `/backup`, `/old`, `.git`, `.env`, map files.  
- **Mitigate:** Remove debug artifacts; block sensitive paths; S3 bucket policies.

---

## Reporting Templates

### Executive Summary (1–2 pages)
- Scope, timeline, assets, methodology, overall risk rating.
- Top 5 findings + business impact + high-level fixes.

### Finding Entry Template
- **Title:** SQL Injection in `GET /items?q=`
- **Severity:** High (CVSS v3.1 vector: …)
- **Affected Assets:** `app.example.com`
- **Description:** What & why it matters.
- **Evidence:** Request/response, screenshots, timestamps.
- **Replication Steps:** Minimal safe steps.
- **Remediation:** Parameterized queries; input validation; WAF rule.
- **References:** OWASP Cheat Sheets, vendor advisories.
- **Status:** New / Remediated / Not Applicable / Risk Accepted.

### Appendix
- Tool versions, hashes of artifacts, change log.

---

## Appendix: Useful Tools

### Install (examples)
```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y nmap whatweb gobuster jq
# Go-based
go install github.com/ffuf/ffuf@latest
```

### Reference Links
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- NIST 800-115 Technical Guide to Information Security Testing
- MITRE ATT&CK: https://attack.mitre.org/
- Bug Bounty Legal Safe Harbor (check program policies)

---

### Notes
This document intentionally **avoids** destructive payloads and post-exploitation persistence examples. If you need red-team content for a **closed lab**, create a separate lab-only addendum and keep it off public repos.
