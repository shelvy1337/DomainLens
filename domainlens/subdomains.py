import time
import requests


def crtsh_subdomains(domain: str, timeout: int = 10, retries: int = 2, retry_delay: float = 1.5) -> dict:
    """
    Passive subdomain discovery via crt.sh with simple retry handling.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "DomainLens/0.1 (Passive Recon Tool)"}

    last_error = None

    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=timeout, headers=headers)
            r.raise_for_status()

            data = r.json()

            subs = set()
            for row in data:
                name = row.get("name_value", "")
                if not name:
                    continue

                for part in name.splitlines():
                    part = part.strip().lower()
                    if part.endswith(domain):
                        part = part.lstrip("*.")
                        subs.add(part)

            subs = sorted(subs)

            return {
                "ok": True,
                "count": len(subs),
                "subdomains": subs,
                "source": "crt.sh",
            }

        except Exception as e:
            last_error = str(e)
            if attempt < retries:
                time.sleep(retry_delay)

    return {
        "ok": False,
        "error": last_error,
        "count": 0,
        "subdomains": [],
        "source": "crt.sh",
    }