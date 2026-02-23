import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalize_domain(value: str) -> str:
    value = value.strip()

    # allow user to paste full URL
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        value = parsed.hostname or value

    value = value.lower().strip(".")

    if not DOMAIN_RE.match(value):
        raise ValueError(f"Invalid domain: {value}")

    return value


def safe_filename(domain: str) -> str:
    return domain.replace("/", "_").replace("\\", "_")


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()