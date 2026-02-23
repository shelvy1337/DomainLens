import requests


def crtsh_subdomains(domain: str, timeout: int = 10) -> dict:
    """
    Passive subdomain discovery via crt.sh
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "DomainLens/0.1 (Passive Recon Tool)"},
        )
        r.raise_for_status()

        data = r.json()

        subs = set()
        for row in data:
            name = row.get("name_value", "")
            if not name:
                continue

            # crt.sh can return multiple names separated by newlines
            for part in name.splitlines():
                part = part.strip().lower()
                if part.endswith(domain):
                    part = part.lstrip("*.")  # remove wildcard
                    subs.add(part)

        subs = sorted(subs)

        return {"ok": True, "count": len(subs), "subdomains": subs}

    except Exception as e:
        return {"ok": False, "error": str(e), "count": 0, "subdomains": []}