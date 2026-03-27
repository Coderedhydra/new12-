from dataclasses import dataclass


@dataclass(slots=True)
class AgentConfig:
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"
    db_path: str = "findings.db"
    user_agent: str = "SafeBountyAgent/2.0"
    max_depth: int = 2
    max_urls: int = 250
    requests_per_second: float = 2.0
    timeout_connect: float = 8.0
    timeout_read: float = 20.0
