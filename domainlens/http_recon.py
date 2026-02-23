import time
import requests


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _check_url(url: str, timeout: int = 8) -> dict:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "DomainLens/0.1 (Passive Recon Tool)",
            "Accept": "*/*",
        }
    )

    start = time.perf_counter()
    try:
        r = s.get(url, allow_redirects=True, timeout=timeout)
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        chain = []
        for h in r.history:
            chain.append(
                {
                    "url": h.url,
                    "status": h.status_code,
                }
            )
        chain.append({"url": r.url, "status": r.status_code})

        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        security = {}
        for h in SECURITY_HEADERS:
            security[h] = headers_lower.get(h)

        return {
            "ok": True,
            "final_url": r.url,
            "status_code": r.status_code,
            "redirect_chain": chain,
            "response_time_ms": elapsed_ms,
            "server": headers_lower.get("server"),
            "security_headers": security,
        }
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return {
            "ok": False,
            "error": str(e),
            "response_time_ms": elapsed_ms,
        }


def _exists(url: str, timeout: int = 8) -> dict:
    """
    Fast existence check.
    We try HEAD first, fallback to GET if blocked.
    """
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "DomainLens/0.1 (Passive Recon Tool)",
            "Accept": "*/*",
        }
    )

    try:
        r = s.head(url, allow_redirects=True, timeout=timeout)
        return {"exists": r.status_code < 400, "status": r.status_code, "final_url": r.url}
    except Exception:
        try:
            r = s.get(url, allow_redirects=True, timeout=timeout)
            return {"exists": r.status_code < 400, "status": r.status_code, "final_url": r.url}
        except Exception as e:
            return {"exists": False, "error": str(e)}


def http_recon(domain: str, timeout: int = 8) -> dict:
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    https = _check_url(https_url, timeout=timeout)
    http = _check_url(http_url, timeout=timeout)

    # robots/sitemap (prefer final https if possible)
    base = None
    if https.get("ok"):
        base = https.get("final_url")
    elif http.get("ok"):
        base = http.get("final_url")

    robots = None
    sitemap = None
    if base:
        robots = _exists(base.rstrip("/") + "/robots.txt", timeout=timeout)
        sitemap = _exists(base.rstrip("/") + "/sitemap.xml", timeout=timeout)

    return {
        "http": http,
        "https": https,
        "robots_txt": robots,
        "sitemap_xml": sitemap,
    }


def headers_audit(security_headers: dict) -> dict:
    """
    Very lightweight scoring.
    """
    score = 0
    details = {}

    for k, v in security_headers.items():
        if v:
            details[k] = {"status": "present", "value": v}
            score += 10
        else:
            details[k] = {"status": "missing", "value": None}

    return {
        "score": score,
        "max_score": len(security_headers) * 10,
        "details": details,
    }