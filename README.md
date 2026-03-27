# Safe Autonomous Security Assistant (Ollama, Local)

A local **defensive** security assessment assistant with:

- Conversational CLI (`rich`) with command shortcuts
- Ollama-backed reasoning (`llama3.1`, `deepseek-coder-v2`, `mixtral` preferred)
- Phase-based pipeline: **recon → crawl → test → report**
- Modular vulnerability plugins (safe, non-destructive checks)
- SQLite evidence + finding storage
- Real-time stage/finding output

> This tool is intentionally designed for authorized, non-destructive security testing and remediation workflows.

## Safety constraints

- Requires explicit authorization confirmation before testing.
- Scope enforcement to avoid out-of-scope domains.
- Request rate limiting (configurable).
- No exploit automation, weaponized payloads, or destructive behavior.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Make sure Ollama is running:

```bash
ollama serve
```

## Run

```bash
python cli.py
```

Commands:

- `/recon` - run recon only
- `/scan` - run full safe phase pipeline
- `/findings` - list findings from SQLite
- `/report` - export Markdown + JSON + HTML reports
- `/focus <area>` - ask the LLM to focus on a specific area

## File structure

```text
agent/
  config.py
  crawler.py
  db.py
  engine.py
  models.py
  ollama_client.py
  plugin_manager.py
  rate_limiter.py
  recon.py
  reporter.py
  scope.py
  plugins/
    base.py
    info_disclosure.py
    reflection_probe.py
    security_headers.py
cli.py
requirements.txt
```
