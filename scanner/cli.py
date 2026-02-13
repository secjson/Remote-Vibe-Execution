"""CLI entrypoint for the code scanner."""

from __future__ import annotations
import sys
import click
from rich.console import Console

from scanner.config import ScanConfig, AIProvider
from scanner.orchestrator import run_scan

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def main():
    """🔒 Remote Vibe Execution - AI-powered security analysis for GitHub repositories."""
    pass


@main.command()
@click.argument("target")
@click.option("--github-token", envvar="GITHUB_TOKEN", default="", help="GitHub personal access token")
@click.option("--ai-provider", type=click.Choice(["openai", "anthropic", "none"]), default="none", help="AI provider for triage")
@click.option("--ai-key", envvar="AI_API_KEY", default="", help="AI API key")
@click.option("--ai-model", default="", help="AI model name")
@click.option("--output", "-o", default="./output", help="Output directory")
@click.option("--format", "-f", "output_format", multiple=True, default=["json", "markdown"], help="Output format(s)")
@click.option("--no-secrets", is_flag=True, help="Disable secret scanning")
@click.option("--no-static", is_flag=True, help="Disable static analysis")
@click.option("--no-deps", is_flag=True, help="Disable dependency scanning")
@click.option("--no-ai", is_flag=True, help="Disable AI triage")
@click.option("--min-severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="low")
@click.option("--ai-min-severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="info",
              help="Minimum severity for findings sent to AI triage (saves API costs)")
@click.option("--config", "config_file", default="", help="YAML config file path")
@click.option("--semgrep-rules", multiple=True, default=[], help="Additional Semgrep rule packs")
def scan(
    target, github_token, ai_provider, ai_key, ai_model,
    output, output_format, no_secrets, no_static, no_deps, no_ai,
    min_severity, ai_min_severity, config_file, semgrep_rules,
):
    """Scan a repository for security vulnerabilities.

    TARGET can be a GitHub URL (https://github.com/owner/repo) or a local path.
    """
    console.print("[bold green]🔒 Remote Vibe Execution v1.0.0[/bold green]")
    console.print()

    # Build config
    if config_file:
        config = ScanConfig.from_yaml(config_file)
    else:
        config = ScanConfig.from_env()

    # Apply CLI overrides
    if target.startswith(("http://", "https://", "git@")):
        config.repo_url = target
    else:
        config.repo_path = target

    if github_token:
        config.github_token = github_token
    if ai_key:
        config.ai_api_key = ai_key
    if ai_model:
        config.ai_model = ai_model

    config.ai_provider = AIProvider(ai_provider)
    config.output_dir = output
    config.output_format = list(output_format)
    config.enable_secret_scan = not no_secrets
    config.enable_static_analysis = not no_static
    config.enable_dependency_scan = not no_deps
    config.enable_ai_triage = not no_ai

    from scanner.config import SeverityLevel
    config.min_severity = SeverityLevel(min_severity)
    config.ai_min_severity = SeverityLevel(ai_min_severity)

    if semgrep_rules:
        config.semgrep_rules.extend(semgrep_rules)

    # Run
    try:
        report = run_scan(config)
        sys.exit(0 if report.summary["total_findings"] == 0 else 1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(2)


@main.command()
@click.argument("query")
@click.option("--github-token", envvar="GITHUB_TOKEN", default="", help="GitHub token")
@click.option("--max-results", default=10, help="Max results")
def search(query, github_token, max_results):
    """Search GitHub for repositories to scan."""
    from scanner.github_client import GitHubClient

    config = ScanConfig()
    config.github_token = github_token
    client = GitHubClient(config)

    try:
        results = client.search_repos(query, max_results=max_results)
        for r in results:
            stars = r.get("stargazers_count", 0)
            lang = r.get("language", "N/A")
            desc = (r.get("description") or "")[:60]
            console.print(
                f"  ⭐ {stars:>6}  [{lang}]  "
                f"[bold]{r['full_name']}[/bold]  {desc}"
            )
    except Exception as e:
        console.print(f"[red]Search failed: {e}[/red]")


if __name__ == "__main__":
    main()
