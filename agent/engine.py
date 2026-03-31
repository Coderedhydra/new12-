import asyncio
import json

import httpx

from .config import AgentConfig
from .crawler import recursive_crawl
from .db import FindingsDB
from .ollama_client import OllamaClient
from .plugin_manager import build_plugins
from .rate_limiter import AsyncRateLimiter
from .recon import run_recon, summarize_recon
from .scope import in_scope

SAFE_POLICY = (
    "You are a defensive security analysis assistant. "
    "Never produce exploit instructions, weaponized payloads, malware, or unauthorized actions. "
    "Use only non-destructive authorized testing and remediation-focused analysis. "
    "Never invent credentials, secrets, or findings. If evidence is missing, say 'not verified'. "
    "Do not suggest password guessing, credential stuffing, or brute-force behavior."
)


class SafeBountyEngine:
    def __init__(self, config: AgentConfig, base_url: str) -> None:
        self.config = config
        self.base_url = base_url
        self.db = FindingsDB(config.db_path)
        self.ollama = OllamaClient(config.ollama_host, config.ollama_model)
        self.limiter = AsyncRateLimiter(config.requests_per_second)
        self.plugins = build_plugins()
        self.messages: list[dict[str, str]] = [
            {"role": "system", "content": SAFE_POLICY},
            {"role": "system", "content": f"Authorized scope: {base_url}"},
        ]
        self.bootstrap_cache: dict | None = None

    async def execute_scan(self, progress_cb=None) -> dict:
        if progress_cb:
            progress_cb("recon", "Running reconnaissance")
        recon = await run_recon(self.base_url, self.config, self.limiter)

        if progress_cb:
            progress_cb("crawl", "Crawling in-scope application")
        crawl = await recursive_crawl(self.base_url, self.config, self.limiter, self.db)

        if progress_cb:
            progress_cb("test", "Running safe plugins")
        timeout = httpx.Timeout(self.config.timeout_read, connect=self.config.timeout_connect)
        headers = {"User-Agent": self.config.user_agent}

        pages = []
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
            await self.limiter.wait()
            base_response = await client.get(self.base_url)

            for url in crawl["urls"][:80]:
                if not in_scope(url, self.base_url):
                    continue
                await self.limiter.wait()
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue
                pages.append({"url": url, "body": resp.text, "response": resp})

            context = {
                "base_url": self.base_url,
                "recon": recon,
                "crawl": crawl,
                "base_response": base_response,
                "pages": pages,
                "http_client": client,
                "limiter": self.limiter,
            }

            all_findings = []
            for plugin in self.plugins:
                plugin_findings = await plugin.run(context)
                for finding in plugin_findings:
                    if self.db.save_finding(finding):
                        all_findings.append(finding)
                        if progress_cb:
                            progress_cb("finding", f"[{finding.severity}] {finding.title} @ {finding.endpoint}")

        plan_prompt = (
            "Given recon and crawl output, provide a defensive next-step plan with prioritized checks."
            f" Recon: {summarize_recon(recon)}"
            f" Crawl: {json.dumps(crawl)[:2500]}"
        )
        self.messages.append({"role": "user", "content": plan_prompt})
        plan = self.ollama.chat(self.messages)
        self.messages.append({"role": "assistant", "content": plan})

        if progress_cb:
            progress_cb("report", "Scan complete")

        return {
            "recon": recon,
            "crawl": crawl,
            "findings_count": len(all_findings),
            "llm_plan": plan,
        }

    def chat(self, user_message: str) -> str:
        grounded_message = (
            "Answer only using observed scan evidence from this run. "
            "If not present in evidence, respond 'not verified'. "
            f"User request: {user_message}"
        )
        self.messages.append({"role": "user", "content": grounded_message})
        answer = self.ollama.chat(self.messages)
        self.messages.append({"role": "assistant", "content": answer})
        return answer

    async def run_recon_only(self) -> dict:
        return await run_recon(self.base_url, self.config, self.limiter)

    async def bootstrap_target_context(self, progress_cb=None) -> dict:
        if self.bootstrap_cache is not None:
            return self.bootstrap_cache

        if progress_cb:
            progress_cb("bootstrap", "Collecting initial recon and crawl context")
        recon = await run_recon(self.base_url, self.config, self.limiter)
        crawl = await recursive_crawl(self.base_url, self.config, self.limiter, self.db)

        bootstrap_summary = {
            "base_url": self.base_url,
            "internal_urls": crawl.get("urls", []),
            "forms": crawl.get("forms", []),
            "js_files": crawl.get("js_files", []),
            "parameters": crawl.get("parameters", {}),
            "recon_paths": recon.get("paths", []),
            "tech_hints": recon.get("tech_hints", []),
        }
        self.messages.append(
            {
                "role": "system",
                "content": (
                    "Initial target context collected from live scan. "
                    "Use this context for user questions and planning: "
                    + json.dumps(bootstrap_summary)[:12000]
                ),
            }
        )
        self.bootstrap_cache = {"recon": recon, "crawl": crawl}
        return self.bootstrap_cache
