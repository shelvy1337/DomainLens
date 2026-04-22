# DomainLens Report - example.com

Generated: **####**

---

## Summary
- Domain: `example.com`
- Security posture: **50/100 (Fair)**
- HTTPS reachable: **Yes**
- HTTP reachable: **Yes**
- TLS cert: **OK**
- Subdomains found: **N/A**

### Score Breakdown
- HTTPS: **25/25**
- TLS: **25/25**
- Headers: **0/50**

---

## Findings


### [MEDIUM] HTTP does not clearly redirect to HTTPS
- Description: The HTTP endpoint is reachable but no redirect to HTTPS was detected.
- Recommendation: Redirect all HTTP traffic to HTTPS.


### [MEDIUM] Missing Content-Security-Policy
- Description: No CSP header was detected.
- Recommendation: Deploy a Content-Security-Policy to reduce XSS and injection risk.


### [MEDIUM] Missing HSTS header
- Description: Strict-Transport-Security is not present.
- Recommendation: Add Strict-Transport-Security to enforce HTTPS in browsers.


### [MEDIUM] Missing X-Frame-Options
- Description: The site does not explicitly restrict framing.
- Recommendation: Add X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors.


### [LOW] Missing Permissions-Policy
- Description: No Permissions-Policy header was detected.
- Recommendation: Add a Permissions-Policy header to disable unused browser features.


### [LOW] Missing Referrer-Policy
- Description: No Referrer-Policy header was detected.
- Recommendation: Add a Referrer-Policy header appropriate for your app.


### [LOW] Missing X-Content-Type-Options
- Description: The site does not explicitly disable MIME sniffing.
- Recommendation: Add X-Content-Type-Options: nosniff.




---

## DNS Records

### A


- 104.20.23.154

- 172.66.147.243




### AAAA


- 2606:4700:10::ac42:93f3

- 2606:4700:10::6814:179a




### CNAME

- (none)



### MX


- 0 .




### TXT


- "v=spf1 -all"

- "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"




### NS


- hera.ns.cloudflare.com.

- elliott.ns.cloudflare.com.





---

## HTTP / HTTPS

### HTTPS

- Status: **200**
- Final URL: https://example.com/
- Response time: 49 ms

- Server: cloudflare


Redirect chain:

- 200 → https://example.com/



### HTTP

- Status: **200**
- Final URL: http://example.com/
- Response time: 21 ms

- Server: cloudflare


Redirect chain:

- 200 → http://example.com/



---

## robots.txt / sitemap.xml

- robots.txt: **NOT FOUND** (404)


- sitemap.xml: **NOT FOUND** (404)


---

## Security Headers Audit

Score: **0 / 60**

- **strict-transport-security**: missing

- **content-security-policy**: missing

- **x-frame-options**: missing

- **x-content-type-options**: missing

- **referrer-policy**: missing

- **permissions-policy**: missing



---

## TLS Certificate

- Issuer: countryName=US, organizationName=CLOUDFLARE, INC., commonName=Cloudflare TLS Issuing ECC CA 1
- Expires at: 2026-07-01T21:24:46+00:00
- Days left: 70

### SANs


- *.example.com

- example.com




---

## Passive Subdomains (crt.sh)

- Not enabled.


---

## Disclaimer
DomainLens is intended for educational purposes and authorized security testing only.

Use DomainLens only on:
- domains you own, or
- systems you have explicit permission to test.

This tool performs passive reconnaissance and does not include exploitation, brute force or phishing functionality.