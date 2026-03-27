import subprocess
from typing import Any

import ollama


class OllamaClient:
    def __init__(self, host: str, model: str) -> None:
        self.host = host
        self.model = model
        self.client = ollama.Client(host=host)

    @staticmethod
    def list_models() -> list[str]:
        try:
            out = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        except Exception:
            return []
        lines = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        if len(lines) < 2:
            return []
        return [line.split()[0] for line in lines[1:]]

    def chat(self, messages: list[dict[str, str]]) -> str:
        resp: dict[str, Any] = self.client.chat(model=self.model, messages=messages)
        msg = resp.get("message", {})
        return str(msg.get("content", "")).strip()
