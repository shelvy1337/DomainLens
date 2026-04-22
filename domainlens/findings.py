def build_findings(report: dict) -> list[dict]:
    findings = []

    http = report.get("http", {})
    tls = report.get("tls", {})
    headers_audit = report.get("headers_audit", {})
    header_details = headers_audit.get("details", {})

    https_ok = bool(http.get("https", {}).get("ok"))
    http_ok = bool(http.get("http", {}).get("ok"))

    http_chain = http.get("http", {}).get("redirect_chain", [])
    redirects_to_https = any(
        isinstance(hop, dict) and str(hop.get("url", "")).startswith("https://")
        for hop in http_chain
    )

    robots = http.get("robots_txt")
    sitemap = http.get("sitemap_xml")

    # HTTPS / redirect
    if not https_ok:
        findings.append({
            "severity": "high",
            "title": "HTTPS is not reachable",
            "description": "The target does not appear to serve content over HTTPS.",
            "recommendation": "Enable HTTPS and serve the site over TLS.",
        })

    if http_ok and not redirects_to_https:
        findings.append({
            "severity": "medium",
            "title": "HTTP does not clearly redirect to HTTPS",
            "description": "The HTTP endpoint is reachable but no redirect to HTTPS was detected.",
            "recommendation": "Redirect all HTTP traffic to HTTPS.",
        })

    # TLS
    if https_ok and not tls.get("ok"):
        findings.append({
            "severity": "high",
            "title": "TLS certificate information could not be retrieved",
            "description": "HTTPS is reachable but TLS certificate inspection failed.",
            "recommendation": "Verify certificate validity and TLS configuration.",
        })

    if tls.get("ok") and isinstance(tls.get("days_left"), int):
        days_left = tls["days_left"]
        if days_left < 0:
            findings.append({
                "severity": "high",
                "title": "TLS certificate is expired",
                "description": f"The certificate appears expired ({days_left} days left).",
                "recommendation": "Renew and deploy a valid TLS certificate immediately.",
            })
        elif days_left <= 14:
            findings.append({
                "severity": "medium",
                "title": "TLS certificate expires soon",
                "description": f"The certificate expires in {days_left} days.",
                "recommendation": "Renew the certificate soon to avoid downtime.",
            })

    # Headers
    def missing(name: str) -> bool:
        return header_details.get(name, {}).get("status") == "missing"

    if https_ok and missing("strict-transport-security"):
        findings.append({
            "severity": "medium",
            "title": "Missing HSTS header",
            "description": "Strict-Transport-Security is not present.",
            "recommendation": "Add Strict-Transport-Security to enforce HTTPS in browsers.",
        })

    if missing("content-security-policy"):
        findings.append({
            "severity": "medium",
            "title": "Missing Content-Security-Policy",
            "description": "No CSP header was detected.",
            "recommendation": "Deploy a Content-Security-Policy to reduce XSS and injection risk.",
        })

    if missing("x-frame-options"):
        findings.append({
            "severity": "medium",
            "title": "Missing X-Frame-Options",
            "description": "The site does not explicitly restrict framing.",
            "recommendation": "Add X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors.",
        })

    if missing("permissions-policy"):
        findings.append({
            "severity": "low",
            "title": "Missing Permissions-Policy",
            "description": "No Permissions-Policy header was detected.",
            "recommendation": "Add a Permissions-Policy header to disable unused browser features.",
        })

    if missing("x-content-type-options"):
        findings.append({
            "severity": "low",
            "title": "Missing X-Content-Type-Options",
            "description": "The site does not explicitly disable MIME sniffing.",
            "recommendation": "Add X-Content-Type-Options: nosniff.",
        })

    if missing("referrer-policy"):
        findings.append({
            "severity": "low",
            "title": "Missing Referrer-Policy",
            "description": "No Referrer-Policy header was detected.",
            "recommendation": "Add a Referrer-Policy header appropriate for your app.",
        })

    # Informational
    if robots and robots.get("exists"):
        findings.append({
            "severity": "info",
            "title": "robots.txt is present",
            "description": "robots.txt was found and returned successfully.",
            "recommendation": "Review its contents to ensure it does not disclose unnecessary paths.",
        })

    if sitemap and sitemap.get("exists"):
        findings.append({
            "severity": "info",
            "title": "sitemap.xml is present",
            "description": "sitemap.xml was found and returned successfully.",
            "recommendation": "Ensure only intended public URLs are exposed.",
        })

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 99), f["title"]))
    return findings