"""Main scan orchestrator - ties all pipeline layers together."""

from __future__ import annotations
import time
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from scanner.config import ScanConfig
from scanner.models import ScanReport, RepoMetadata
from scanner.github_client import ingest_repo
from scanner.preprocessor import preprocess
from scanner.ai_agent import AITriageAgent
from scanner.risk_engine import RiskEngine
from scanner.reporters import generate_reports
from scanners.secret_scanner import SecretScanner
from scanners.static_analyzer import StaticAnalyzer
from scanners.dependency_scanner import DependencyScanner

console = Console()


def run_scan(config: ScanConfig) -> ScanReport:
    """Execute the full scan pipeline."""
    report = ScanReport()
    report.scan_started = datetime.utcnow().isoformat()
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # ── Stage 1: Repo Ingestion ──
        task = progress.add_task("📥 Ingesting repository...", total=None)
        try:
            repo_path, metadata = ingest_repo(config)
            report.repo = metadata
            progress.update(task, description=f"📥 Ingested: {metadata.name} ({metadata.file_count} files)")
        except Exception as e:
            report.errors.append(f"Ingestion failed: {e}")
            console.print(f"[red]❌ Ingestion failed: {e}[/red]")
            return report
        progress.remove_task(task)

        # ── Stage 2: Pre-processing ──
        task = progress.add_task("⚙️  Pre-processing...", total=None)
        files, chunks, deps = preprocess(config, repo_path)
        metadata.dependencies = deps
        progress.update(task, description=f"⚙️  Processed: {len(files)} files, {len(chunks)} chunks, {len(deps)} deps")
        progress.remove_task(task)

        # ── Stage 3: Scanners ──
        all_findings = []

        if config.enable_secret_scan:
            task = progress.add_task("🔑 Scanning secrets...", total=None)
            try:
                scanner = SecretScanner(config)
                findings = scanner.scan(repo_path)
                all_findings.extend(findings)
                report.scanners_used.append("secret_scanner")
                progress.update(task, description=f"🔑 Secrets: {len(findings)} findings")
            except Exception as e:
                report.errors.append(f"Secret scan error: {e}")
            progress.remove_task(task)

        if config.enable_static_analysis:
            task = progress.add_task("🔍 Static analysis...", total=None)
            try:
                scanner = StaticAnalyzer(config)
                findings = scanner.scan(repo_path)
                all_findings.extend(findings)
                report.scanners_used.append("static_analyzer")
                progress.update(task, description=f"🔍 Static: {len(findings)} findings")
            except Exception as e:
                report.errors.append(f"Static analysis error: {e}")
            progress.remove_task(task)

        if config.enable_dependency_scan:
            task = progress.add_task("📦 Dependency scan...", total=None)
            try:
                scanner = DependencyScanner(config)
                findings = scanner.scan(repo_path, dependencies=deps)
                all_findings.extend(findings)
                report.scanners_used.append("dependency_scanner")
                progress.update(task, description=f"📦 Dependencies: {len(findings)} findings")
            except Exception as e:
                report.errors.append(f"Dependency scan error: {e}")
            progress.remove_task(task)

        # ── Stage 4: AI Triage ──
        if config.enable_ai_triage and config.ai_provider.value != "none":
            task = progress.add_task(f"🤖 AI triage ({len(all_findings)} findings)...", total=None)
            try:
                agent = AITriageAgent(config)
                all_findings = agent.triage_findings(all_findings, repo_path)
                progress.update(task, description="🤖 AI triage complete")
            except Exception as e:
                report.errors.append(f"AI triage error: {e}")
            progress.remove_task(task)

        # ── Stage 5: Risk Engine ──
        task = progress.add_task("📊 Risk analysis...", total=None)
        engine = RiskEngine(config)
        all_findings = engine.process(all_findings)
        report.findings = all_findings
        progress.remove_task(task)

    # Finalize
    report.scan_completed = datetime.utcnow().isoformat()
    report.scan_duration_seconds = time.time() - start_time

    # ── Stage 6: Reporting ──
    console.print()
    output_paths = generate_reports(report, config)

    # Print summary
    _print_summary(report, output_paths)

    return report


def _print_summary(report: ScanReport, output_paths: list[str]):
    """Print a rich summary to the console."""
    s = report.summary

    table = Table(title=f"Scan Results: {report.repo.name}", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = s["by_severity"].get(sev, 0)
        if count > 0:
            table.add_row(sev.upper(), str(count), style=colors.get(sev, ""))

    console.print(table)
    console.print()

    summary_text = (
        f"Total: {s['total_findings']} | "
        f"Actionable: {s['actionable_findings']} | "
        f"False Positives: {s['false_positives']} | "
        f"Duration: {report.scan_duration_seconds:.1f}s"
    )
    console.print(Panel(summary_text, title="Summary", border_style="green"))

    if output_paths:
        console.print("\n[bold]Reports saved:[/bold]")
        for p in output_paths:
            console.print(f"  📄 {p}")

    if report.errors:
        console.print(f"\n[yellow]⚠️  {len(report.errors)} error(s) during scan[/yellow]")
