import json
from urllib.parse import urljoin

import httpx

from .config import AgentConfig
from .rate_limiter import AsyncRateLimiter
from .scope import in_scope


COMMON_DISCOVERY_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.env",
    "/.git/HEAD",
    "/.DS_Store",
]


async def run_recon(base_url: str, config: AgentConfig, limiter: AsyncRateLimiter) -> dict:
    timeout = httpx.Timeout(config.timeout_read, connect=config.timeout_connect)
    headers = {"User-Agent": config.user_agent}
    discovered = {"base": base_url, "paths": [], "headers": {}, "tech_hints": []}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        await limiter.wait()
        r = await client.get(base_url)
        discovered["headers"] = dict(r.headers)

        server = r.headers.get("server")
        powered = r.headers.get("x-powered-by")
        if server:
            discovered["tech_hints"].append(f"server:{server}")
        if powered:
            discovered["tech_hints"].append(f"powered:{powered}")

        for path in COMMON_DISCOVERY_PATHS:
            candidate = urljoin(base_url, path)
            if not in_scope(candidate, base_url):
                continue
            await limiter.wait()
            resp = await client.get(candidate)
            if resp.status_code < 400:
                discovered["paths"].append(
                    {"url": candidate, "status": resp.status_code, "bytes": len(resp.text)}
                )

    return discovered


def summarize_recon(recon_result: dict) -> str:
    return json.dumps(recon_result, indent=2)[:4000]
