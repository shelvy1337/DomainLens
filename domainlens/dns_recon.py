import dns.resolver


def _resolve(domain: str, record_type: str):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=4)
        return [str(a).strip() for a in answers]
    except Exception:
        return []


def dns_recon(domain: str) -> dict:
    return {
        "A": _resolve(domain, "A"),
        "AAAA": _resolve(domain, "AAAA"),
        "CNAME": _resolve(domain, "CNAME"),
        "MX": _resolve(domain, "MX"),
        "TXT": _resolve(domain, "TXT"),
        "NS": _resolve(domain, "NS"),
    }