import asyncio
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent.config import AgentConfig
from agent.engine import SafeBountyEngine
from agent.ollama_client import OllamaClient
from agent.reporter import export_reports

console = Console()
SUPPORTED_MODELS = {"llama3.1", "deepseek-coder-v2", "mixtral"}


def choose_model() -> str:
    models = OllamaClient.list_models()
    if not models:
        return console.input("[yellow]No models discovered. Enter model name:[/yellow] ").strip()

    table = Table(title="Available Ollama Models")
    table.add_column("#", style="cyan")
    table.add_column("Model", style="green")
    for idx, model in enumerate(models, start=1):
        table.add_row(str(idx), model)
    console.print(table)

    while True:
        raw = console.input("Select model number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(models):
            selected = models[int(raw) - 1]
            if selected.split(":")[0] not in SUPPORTED_MODELS:
                console.print(
                    "[yellow]Model is not in preferred set (llama3.1/deepseek-coder-v2/mixtral), continuing anyway.[/yellow]"
                )
            return selected
        console.print("[red]Invalid selection.[/red]")


def progress_callback(stage: str, message: str) -> None:
    console.print(f"[bold cyan]{stage:>7}[/bold cyan] :: {message}")


def print_findings(engine: SafeBountyEngine) -> None:
    rows = engine.db.list_findings()
    table = Table(title="Findings")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("Verification")
    table.add_column("Endpoint")
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["severity"],
            row["vuln_type"],
            row["title"],
            row["verification"],
            row["endpoint"],
        )
    console.print(table)


async def run() -> None:
    console.print(Panel.fit("Safe Autonomous Security Assistant (Defensive)", style="bold green"))

    model = choose_model()
    base_url = console.input("Target base URL (authorized only): ").strip()
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("Invalid URL")

    confirm = console.input(
        "Type [bold]I_HAVE_AUTHORIZATION[/bold] to confirm legal scope: "
    ).strip()
    if confirm != "I_HAVE_AUTHORIZATION":
        raise SystemExit("Authorization confirmation was not provided.")

    config = AgentConfig(ollama_model=model)
    engine = SafeBountyEngine(config=config, base_url=base_url)
    bootstrap = await engine.bootstrap_target_context(progress_cb=progress_callback)
    bootstrap_crawl = bootstrap.get("crawl", {})
    console.print(
        f"[green]Bootstrapped context:[/green] urls={len(bootstrap_crawl.get('urls', []))}, "
        f"forms={len(bootstrap_crawl.get('forms', []))}, js={len(bootstrap_crawl.get('js_files', []))}"
    )

    console.print(
        "\nCommands: [bold]/recon[/bold], [bold]/scan[/bold], [bold]/findings[/bold], "
        "[bold]/report[/bold], [bold]/report confirmed[/bold], [bold]/focus <area>[/bold], [bold]exit[/bold]\n"
    )

    while True:
        cmd = console.input("[bold blue]you>[/bold blue] ").strip()
        if cmd in {"exit", "quit"}:
            console.print("Bye")
            break

        if cmd == "/recon":
            result = await engine.run_recon_only()
            console.print_json(data=result)
            continue

        if cmd == "/scan":
            result = await engine.execute_scan(progress_cb=progress_callback)
            console.print_json(data=result)
            continue

        if cmd == "/findings":
            print_findings(engine)
            continue

        if cmd == "/report":
            output = export_reports(engine.db, min_verification="LIKELY")
            console.print(f"Reports generated: {output}")
            continue

        if cmd == "/report confirmed":
            output = export_reports(engine.db, min_verification="CONFIRMED")
            console.print(f"Confirmed-only reports generated: {output}")
            continue

        if cmd.startswith("/focus "):
            area = cmd.replace("/focus ", "", 1).strip()
            prompt = f"Focus on defensive analysis for this area: {area}. Suggest safe next steps only."
            ans = engine.chat(prompt)
            console.print(Panel(ans, title="assistant"))
            continue

        answer = engine.chat(cmd)
        console.print(Panel(answer, title="assistant"))


if __name__ == "__main__":
    asyncio.run(run())
