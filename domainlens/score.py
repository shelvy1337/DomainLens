def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def compute_security_score(http_data: dict, tls_data: dict, headers_data: dict | None) -> dict:
    """
    Global score 0-100:
    - HTTPS reachable: 25
    - TLS available/ok: 25
    - Security headers: 50 (normalized from headers_audit score/max_score)
    """
    points = 0
    breakdown = {}

    https_ok = bool(http_data.get("https", {}).get("ok"))
    tls_ok = bool(tls_data.get("ok"))

    breakdown["https"] = {"max": 25, "got": 25 if https_ok else 0}
    points += breakdown["https"]["got"]

    breakdown["tls"] = {"max": 25, "got": 25 if tls_ok else 0}
    points += breakdown["tls"]["got"]

    headers_max = 50
    if headers_data and headers_data.get("max_score"):
        ratio = headers_data["score"] / headers_data["max_score"]
        got = int(round(ratio * headers_max))
    else:
        got = 0

    got = clamp(got, 0, headers_max)
    breakdown["headers"] = {"max": headers_max, "got": got}
    points += got

    points = clamp(points, 0, 100)

    if points >= 85:
        posture = "Excellent"
    elif points >= 70:
        posture = "Good"
    elif points >= 50:
        posture = "Fair"
    else:
        posture = "Poor"

    return {
        "score": points,
        "posture": posture,
        "breakdown": breakdown,
    }