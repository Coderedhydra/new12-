from urllib.parse import urlparse


def normalize_base_domain(base_url: str) -> str:
    parsed = urlparse(base_url)
    return parsed.netloc.lower()


def in_scope(candidate_url: str, base_url: str) -> bool:
    base_host = normalize_base_domain(base_url)
    c = urlparse(candidate_url)
    if c.scheme not in {"http", "https"}:
        return False
    host = c.netloc.lower()
    return host == base_host or host.endswith(f".{base_host}")
