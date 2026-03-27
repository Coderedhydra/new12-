# Safe Research Assistant Agent (Ollama)

This project provides a **defensive security research assistant** that:

- Lists local Ollama models and lets you choose one.
- Accepts a target URL.
- Runs in chat mode with tool-calling support.
- Performs **authorized, non-destructive** reconnaissance checks.
- Collects links/forms/internal endpoints and basic HTTP evidence.
- Uses findings to help with secure code review and remediation guidance.

## Important safety scope

This agent intentionally avoids exploit automation, destructive payloads, credential abuse, or unauthorized testing. Use only on systems you own or are explicitly authorized to test.

## Features

- `ollama list` model discovery.
- Interactive model selection.
- Chat loop backed by Ollama `/api/chat`.
- Tool functions:
  - `fetch_url` – fetch and summarize a URL.
  - `enumerate_links` – collect in-scope links and forms.
  - `check_security_headers` – inspect common missing security headers.
  - `reflection_probe` – benign marker reflection test for query parameters.
  - `analyze_source_patterns` – detect risky code patterns in fetched source.
- Local knowledge base from OWASP-style guidance (`knowledge_base.json`).

## Requirements

- Python 3.10+
- Running Ollama daemon (`ollama serve`)
- At least one pulled model (e.g. `ollama pull llama3.1`)

## Usage

```bash
python safe_agent.py
```

Then:
1. Pick a model from the list.
2. Enter target URL.
3. Chat with the agent.

Type `exit` to quit.

## Timeout troubleshooting (Ollama)

Large models can take longer than default HTTP read timeout.  
If you see timeout errors, increase Ollama read timeout:

```bash
OLLAMA_READ_TIMEOUT=300 python safe_agent.py
```

Optional environment variables:

- `OLLAMA_CONNECT_TIMEOUT` (default `10`)
- `OLLAMA_READ_TIMEOUT` (default `180`)

## Notes

If `ollama list` is unavailable, the app will ask for a model name manually.
