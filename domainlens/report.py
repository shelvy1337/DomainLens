import json
from pathlib import Path
from jinja2 import Template


REPORT_TEMPLATE = r"""
# DomainLens Report — {{ domain }}

Generated: **{{ generated_at }}**

---

## Summary
- Domain: `{{ domain }}`
- HTTPS reachable: **{{ "Yes" if http.https.ok else "No" }}**
- HTTP reachable: **{{ "Yes" if http.http.ok else "No" }}**
- TLS cert: **{{ "OK" if tls.ok else "Unavailable" }}**
- Subdomains found: **{{ subdomains.count if subdomains else "N/A" }}**

---

## DNS Records

{% for rtype, values in dns.items() %}
### {{ rtype }}
{% if values and values|length > 0 %}
{% for v in values %}
- {{ v }}
{% endfor %}
{% else %}
- (none)
{% endif %}
{% endfor %}

---

## HTTP / HTTPS

### HTTPS
{% if http.https.ok %}
- Status: **{{ http.https.status_code }}**
- Final URL: {{ http.https.final_url }}
- Response time: {{ http.https.response_time_ms }} ms
{% if http.https.server %}- Server: {{ http.https.server }}{% endif %}

Redirect chain:
{% for hop in http.https.redirect_chain %}
- {{ hop.status }} → {{ hop.url }}
{% endfor %}
{% else %}
- Error: {{ http.https.error }}
{% endif %}

### HTTP
{% if http.http.ok %}
- Status: **{{ http.http.status_code }}**
- Final URL: {{ http.http.final_url }}
- Response time: {{ http.http.response_time_ms }} ms

Redirect chain:
{% for hop in http.http.redirect_chain %}
- {{ hop.status }} → {{ hop.url }}
{% endfor %}
{% else %}
- Error: {{ http.http.error }}
{% endif %}

---

## robots.txt / sitemap.xml
{% if http.robots_txt %}
- robots.txt: **{{ "FOUND" if http.robots_txt.exists else "NOT FOUND" }}** ({{ http.robots_txt.status if http.robots_txt.status else "?" }})
{% else %}
- robots.txt: N/A
{% endif %}

{% if http.sitemap_xml %}
- sitemap.xml: **{{ "FOUND" if http.sitemap_xml.exists else "NOT FOUND" }}** ({{ http.sitemap_xml.status if http.sitemap_xml.status else "?" }})
{% else %}
- sitemap.xml: N/A
{% endif %}

---

## Security Headers Audit
{% if headers_audit %}
Score: **{{ headers_audit.score }} / {{ headers_audit.max_score }}**

{% for h, info in headers_audit.details.items() %}
- **{{ h }}**: {{ info.status }}
{% endfor %}
{% else %}
- N/A
{% endif %}

---

## TLS Certificate
{% if tls.ok %}
- Issuer: {{ tls.issuer }}
- Expires at: {{ tls.expires_at }}
- Days left: {{ tls.days_left }}

### SANs
{% if tls.sans and tls.sans|length > 0 %}
{% for s in tls.sans %}
- {{ s }}
{% endfor %}
{% else %}
- (none)
{% endif %}
{% else %}
- TLS info unavailable: {{ tls.error }}
{% endif %}

---

## Passive Subdomains (crt.sh)
{% if subdomains %}
{% if subdomains.ok %}
Found: **{{ subdomains.count }}**

{% for s in subdomains.subdomains[:200] %}
- {{ s }}
{% endfor %}

{% if subdomains.count > 200 %}
> Showing first 200 results.
{% endif %}
{% else %}
- Error: {{ subdomains.error }}
{% endif %}
{% else %}
- Not enabled.
{% endif %}

---

## Disclaimer
DomainLens is intended for educational purposes and authorized security testing only.

Use DomainLens only on:
- domains you own, or
- systems you have explicit permission to test.

This tool performs passive reconnaissance and does not include exploitation, brute force or phishing functionality.
""".strip()


def write_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_md(path: Path, data: dict):
    tpl = Template(REPORT_TEMPLATE)
    md = tpl.render(**data)
    path.write_text(md, encoding="utf-8")