# DomainLens - Domain Recon Toolkit

```text

$$$$$$$\                                    $$\           $$\                                    
$$  __$$\                                   \__|          $$ |                                   
$$ |  $$ | $$$$$$\  $$$$$$\$$$$\   $$$$$$\  $$\ $$$$$$$\  $$ |      $$$$$$\  $$$$$$$\   $$$$$$$\ 
$$ |  $$ |$$  __$$\ $$  _$$  _$$\  \____$$\ $$ |$$  __$$\ $$ |     $$  __$$\ $$  __$$\ $$  _____|
$$ |  $$ |$$ /  $$ |$$ / $$ / $$ | $$$$$$$ |$$ |$$ |  $$ |$$ |     $$$$$$$$ |$$ |  $$ |\$$$$$$\  
$$ |  $$ |$$ |  $$ |$$ | $$ | $$ |$$  __$$ |$$ |$$ |  $$ |$$ |     $$   ____|$$ |  $$ | \____$$\ 
$$$$$$$  |\$$$$$$  |$$ | $$ | $$ |\$$$$$$$ |$$ |$$ |  $$ |$$$$$$$$\\$$$$$$$\ $$ |  $$ |$$$$$$$  |
\_______/  \______/ \__| \__| \__| \_______|\__|\__|  \__|\________|\_______|\__|  \__|\_______/

```
Generate a full domain recon report: DNS, TLS certificate, security headers, redirects and subdomains.

DomainLens is a lightweight **passive reconnaissance** CLI tool designed for defenders, students and authorized security testing.  
It collects key information about a domain and exports it into clean, readable reports.

---

## ✨ Features
- **DNS recon** (A/AAAA/CNAME/MX/TXT/NS)
- **HTTP/HTTPS checks**
  - status code + redirect chain
  - response time
  - robots.txt & sitemap.xml detection
- **Security headers audit**
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS certificate info**
  - issuer, expiry date, SANs
- **Passive subdomain discovery**
  - crt.sh (certificate transparency logs)
- **Report output**
  - Markdown (`report.md`)
  - JSON (`report.json`)

---

## 📦 Installation

### Option 1: Install from source
```bash
git clone https://github.com/shelvy1337/domainlens.git
cd domainlens
pip install -r requirements.txt
```

### Option 2: Run directly
```bash
python -m domainlens example.com
```

---

## 🚀 Usage

Basic scan:
```bash
domainlens example.com
```

Save reports to a folder:
```bash
domainlens example.com --out reports/
```

Generate both Markdown and JSON:
```bash
domainlens example.com --md --json
```

Enable subdomain discovery:
```bash
domainlens example.com --subdomains
```

---

## 📝 Example Output

DomainLens generates:
- `reports/example.com/report.md`
- `reports/example.com/report.json`

---

## ⚠️ Disclaimer
This tool is intended for **educational purposes** and **authorized security testing only**.

Use DomainLens only on:
- domains you own, or
- systems you have explicit permission to test.

DomainLens performs **passive reconnaissance** and does not include exploitation, brute force or phishing functionality.
