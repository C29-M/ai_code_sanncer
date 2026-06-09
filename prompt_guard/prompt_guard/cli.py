"""Command-line interface for prompt_guard."""
import sys
import json
import logging
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box

from prompt_guard.scanner import scan_prompt
from prompt_guard import __version__

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}

LEVEL_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


@click.group()
@click.version_option(version=__version__, prog_name="prompt-guard")
def main():
    """prompt-guard - AI Security Middleware for System Prompt Scanning."""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=False), required=False)
@click.option("--deep", is_flag=True, default=False, help="Enable deep scan mode.")
@click.option("--garak", is_flag=True, default=False, help="Enable Garak integration.")
@click.option("--guardrails", is_flag=True, default=False, help="Enable Guardrails AI.")
@click.option("--nemo", is_flag=True, default=False, help="Enable NeMo Guardrails.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output raw JSON.")
@click.option("--text", "inline_text", default=None, help="Scan inline text instead of file.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose logging.")
def scan(file, deep, garak, guardrails, nemo, output_json, inline_text, verbose):
    """Scan a system prompt file or inline text for security issues."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    if inline_text:
        prompt_text = inline_text
    elif file:
        try:
            with open(file, "r", encoding="utf-8") as f:
                prompt_text = f.read()
        except FileNotFoundError:
            console.print(f"[red]Error: File not found: {file}[/red]")
            sys.exit(2)
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            sys.exit(2)
    else:
        console.print("[red]Error: Provide a FILE argument or use --text.[/red]")
        sys.exit(2)

    if not output_json:
        console.print(Rule("[bold cyan]PROMPT GUARD - Security Analysis[/bold cyan]"))

    result = scan_prompt(
        prompt_text,
        deep_scan=deep,
        enable_garak=garak,
        enable_guardrails=guardrails,
        enable_nemo=nemo,
    )

    if output_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        sys.exit(0 if result.safe else 1)

    _print_result(result)
    sys.exit(0 if result.safe else 1)


@main.command()
@click.argument("text")
@click.option("--json", "output_json", is_flag=True, default=False)
def check(text, output_json):
    """Scan inline prompt text directly from the command line."""
    result = scan_prompt(text)
    if output_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        console.print(Rule("[bold cyan]PROMPT GUARD - Quick Check[/bold cyan]"))
        _print_result(result)
    sys.exit(0 if result.safe else 1)


def _print_result(result):
    level_color = LEVEL_COLORS.get(result.risk_level, "white")
    safe_text = "[bold green]SAFE[/bold green]" if result.safe else "[bold red]UNSAFE[/bold red]"

    console.print()
    console.print(f"  Status:     {safe_text}")
    console.print(f"  Risk Score: [bold]{result.risk_score}/10[/bold]")
    console.print(f"  Risk Level: [{level_color}]{result.risk_level.upper()}[/{level_color}]")
    console.print(f"  Scan Time:  {result.metadata.get('scan_time_seconds', 0):.3f}s")
    console.print()

    console.print(Panel(result.summary, title="[bold]Summary[/bold]", border_style="cyan"))

    if result.findings:
        console.print()
        table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Message")
        table.add_column("Matched Text", style="dim", max_width=40)

        for finding in result.findings:
            sev_color = SEVERITY_COLORS.get(finding.severity, "white")
            table.add_row(
                finding.type.replace("_", " ").title(),
                Text(finding.severity.upper(), style=sev_color),
                finding.message,
                finding.matched_text,
            )
        console.print(table)

    if result.recommendations:
        console.print()
        rec_text = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(result.recommendations))
        console.print(Panel(rec_text, title="[bold]Recommendations[/bold]", border_style="yellow"))

    console.print()
