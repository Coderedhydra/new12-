import json
import re
import subprocess
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"
USER_AGENT = "SafeResearchAgent/1.0"
TIMEOUT = 12


@dataclass
class AgentContext:
    base_url: str
    model: str
    history: list[dict[str, Any]]


class LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict[str, str]] = []
        self._current_form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {k: v for k, v in attrs}
        if tag == "a" and attrs_dict.get("href"):
            self.links.add(attrs_dict["href"] or "")
        elif tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action") or "",
                "method": (attrs_dict.get("method") or "get").lower(),
            }
            self.forms.append(self._current_form)


def get_ollama_models() -> list[str]:
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
    except Exception:
        return []

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) <= 1:
        return []

    models = []
    for line in lines[1:]:
        parts = re.split(r"\s+", line)
        if parts:
            models.append(parts[0])
    return models


def normalized_in_scope(url: str, base: str) -> bool:
    b = urlparse(base)
    t = urlparse(url)
    return (t.netloc == "" or t.netloc == b.netloc) and (t.scheme in ("", "http", "https"))


def fetch_url(url: str) -> dict[str, Any]:
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    return {
        "url": url,
        "status": r.status_code,
        "content_type": r.headers.get("Content-Type", ""),
        "headers": dict(r.headers),
        "body_preview": r.text[:3000],
        "body_length": len(r.text),
    }


def enumerate_links(url: str, max_links: int = 100) -> dict[str, Any]:
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    parser = LinkFormParser()
    parser.feed(r.text)

    abs_links = []
    for link in parser.links:
        absolute = urljoin(url, link)
        if normalized_in_scope(absolute, url):
            abs_links.append(absolute)

    unique_links = sorted(set(abs_links))[:max_links]
    normalized_forms = []
    for form in parser.forms:
        normalized_forms.append(
            {
                "action": urljoin(url, form["action"]),
                "method": form["method"],
            }
        )

    return {
        "url": url,
        "status": r.status_code,
        "internal_links": unique_links,
        "forms": normalized_forms,
    }


def check_security_headers(url: str) -> dict[str, Any]:
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    hdr = {k.lower(): v for k, v in r.headers.items()}

    required = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    ]
    missing = [h for h in required if h not in hdr]

    return {
        "url": url,
        "status": r.status_code,
        "missing_headers": missing,
        "present_headers": {k: hdr[k] for k in required if k in hdr},
    }


def reflection_probe(url: str, marker: str = "SAFE_REFLECT_PROBE") -> dict[str, Any]:
    p = urlparse(url)
    qs = parse_qs(p.query)
    if not qs:
        return {"url": url, "reflections": [], "note": "No query params to probe."}

    probe_qs = {k: [marker] for k in qs.keys()}
    encoded = urlencode({k: v[0] for k, v in probe_qs.items()})
    probe_url = urlunparse((p.scheme, p.netloc, p.path, p.params, encoded, p.fragment))

    r = requests.get(probe_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    reflections = [k for k in probe_qs if marker in r.text]

    return {
        "original_url": url,
        "probe_url": probe_url,
        "status": r.status_code,
        "reflections": reflections,
        "reflection_count": len(reflections),
    }


def analyze_source_patterns(url: str) -> dict[str, Any]:
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    body = r.text.lower()
    patterns = {
        "inline_script": "<script" in body,
        "potential_debug_keyword": any(k in body for k in ["debug", "traceback", "stack trace"]),
        "exposed_api_key_pattern": bool(re.search(r"(api[_-]?key|token)\s*[:=]\s*['\"][a-z0-9_\-]{12,}", body)),
    }
    return {
        "url": url,
        "status": r.status_code,
        "patterns": patterns,
    }


def load_knowledge_base() -> dict[str, Any]:
    with open("knowledge_base.json", "r", encoding="utf-8") as f:
        return json.load(f)


def tool_registry() -> dict[str, Any]:
    return {
        "fetch_url": fetch_url,
        "enumerate_links": enumerate_links,
        "check_security_headers": check_security_headers,
        "reflection_probe": reflection_probe,
        "analyze_source_patterns": analyze_source_patterns,
    }


def call_ollama(model: str, messages: list[dict[str, Any]]) -> dict[str, Any]:
    r = requests.post(
        OLLAMA_CHAT_URL,
        json={"model": model, "messages": messages, "stream": False},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def run_tool_message(tool_call: str, args: dict[str, Any], ctx: AgentContext) -> dict[str, Any]:
    tools = tool_registry()
    if tool_call not in tools:
        return {"error": f"Unknown tool: {tool_call}"}

    if "url" in args and not normalized_in_scope(args["url"], ctx.base_url):
        return {"error": "Out-of-scope URL blocked by safety policy."}

    try:
        return tools[tool_call](**args)
    except Exception as exc:
        return {"error": str(exc)}


def system_prompt(base_url: str, kb: dict[str, Any]) -> str:
    return (
        "You are a defensive web security research assistant. "
        "Never provide exploit instructions, malware, or unauthorized attack guidance. "
        "Use only non-destructive, authorized testing patterns and prioritize remediation. "
        f"Current authorized scope: {base_url}. "
        f"Knowledge base summary: {json.dumps(kb)[:1500]}"
    )


def agent_loop(ctx: AgentContext) -> None:
    kb = load_knowledge_base()
    ctx.history.append({"role": "system", "content": system_prompt(ctx.base_url, kb)})

    print("\nSafe agent ready. Type 'exit' to quit.")
    print("You can ask it to fetch pages, enumerate forms/links, and review findings defensively.\n")

    while True:
        user_msg = input("you> ").strip()
        if user_msg.lower() in {"exit", "quit"}:
            print("bye")
            break

        ctx.history.append({"role": "user", "content": user_msg})
        response = call_ollama(ctx.model, ctx.history)
        msg = response.get("message", {})

        content = msg.get("content", "")
        print(f"\nagent> {content}\n")
        ctx.history.append({"role": "assistant", "content": content})

        if content.startswith("TOOL:"):
            # Expected format: TOOL:tool_name {"url":"https://..."}
            try:
                _, tool_name, args_raw = content.split(" ", 2)
                args = json.loads(args_raw)
                tool_out = run_tool_message(tool_name.replace("TOOL:", ""), args, ctx)
                tool_text = json.dumps(tool_out, indent=2)
                print(f"tool[{tool_name}]> {tool_text}\n")
                ctx.history.append(
                    {
                        "role": "tool",
                        "content": tool_text,
                    }
                )
                followup = call_ollama(ctx.model, ctx.history)
                followup_text = followup.get("message", {}).get("content", "")
                print(f"agent> {followup_text}\n")
                ctx.history.append({"role": "assistant", "content": followup_text})
            except Exception as exc:
                err = f"Tool parse/exec error: {exc}"
                print(err)
                ctx.history.append({"role": "assistant", "content": err})


def choose_model() -> str:
    models = get_ollama_models()
    if not models:
        return input("No models discovered via `ollama list`. Enter model name: ").strip()

    print("Available Ollama models:")
    for idx, m in enumerate(models, start=1):
        print(f"  {idx}. {m}")

    while True:
        raw = input("Select model number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(models):
            return models[int(raw) - 1]
        print("Invalid selection.")


def main() -> None:
    print("=== Safe Research Agent (Ollama) ===")
    model = choose_model()
    base_url = input("Authorized base URL (e.g., https://example.com): ").strip()
    ctx = AgentContext(base_url=base_url, model=model, history=[])
    agent_loop(ctx)


if __name__ == "__main__":
    main()
