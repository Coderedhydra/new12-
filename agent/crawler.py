from collections import deque
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .config import AgentConfig
from .db import FindingsDB
from .rate_limiter import AsyncRateLimiter
from .scope import in_scope


async def recursive_crawl(
    base_url: str,
    config: AgentConfig,
    limiter: AsyncRateLimiter,
    db: FindingsDB,
) -> dict:
    timeout = httpx.Timeout(config.timeout_read, connect=config.timeout_connect)
    headers = {"User-Agent": config.user_agent}
    visited: set[str] = set()
    queue = deque([(base_url, 0)])
    urls: list[str] = []
    forms: list[dict] = []
    js_files: list[str] = []
    parameters: dict[str, list[str]] = {}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        while queue and len(visited) < config.max_urls:
            url, depth = queue.popleft()
            if url in visited or depth > config.max_depth:
                continue
            if not in_scope(url, base_url):
                continue
            visited.add(url)

            await limiter.wait()
            try:
                r = await client.get(url)
            except httpx.HTTPError:
                continue

            db.log_crawl(url=url, status_code=r.status_code, response_bytes=len(r.text))
            urls.append(url)

            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for key in qs:
                parameters.setdefault(parsed.path, [])
                if key not in parameters[parsed.path]:
                    parameters[parsed.path].append(key)

            ctype = r.headers.get("content-type", "")
            if "text/html" not in ctype:
                continue

            soup = BeautifulSoup(r.text, "lxml")
            for tag in soup.find_all("a", href=True):
                nxt = urljoin(url, tag["href"])
                if in_scope(nxt, base_url) and nxt not in visited:
                    queue.append((nxt, depth + 1))

            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                if in_scope(js_url, base_url) and js_url not in js_files:
                    js_files.append(js_url)

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "get").upper()
                inputs = [inp.get("name", "") for inp in form.find_all("input") if inp.get("name")]
                forms.append({"url": url, "action": action, "method": method, "inputs": inputs})

    return {
        "urls": urls,
        "forms": forms,
        "js_files": js_files,
        "parameters": parameters,
    }
