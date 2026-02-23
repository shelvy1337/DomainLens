import socket
import ssl
from datetime import datetime, timezone


def tls_recon(domain: str, timeout: int = 6) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False

    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # issuer
        issuer = []
        for part in cert.get("issuer", []):
            for k, v in part:
                issuer.append(f"{k}={v}")
        issuer = ", ".join(issuer) if issuer else None

        # SANs
        sans = []
        for typ, name in cert.get("subjectAltName", []):
            if typ == "DNS":
                sans.append(name)

        # expiry
        not_after = cert.get("notAfter")
        expires = None
        days_left = None

        if not_after:
            # example: 'Jun 10 12:00:00 2026 GMT'
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            dt = dt.replace(tzinfo=timezone.utc)
            expires = dt.isoformat()
            days_left = (dt - datetime.now(timezone.utc)).days

        return {
            "ok": True,
            "issuer": issuer,
            "expires_at": expires,
            "days_left": days_left,
            "sans": sorted(set(sans)),
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}