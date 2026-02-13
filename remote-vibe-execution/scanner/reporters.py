"""Report generation: JSON, Markdown, and database storage."""

from __future__ import annotations
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from scanner.models import ScanReport, Finding


class JSONReporter:
    """Generate JSON scan reports."""

    def generate(self, report: ScanReport, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{report.repo.name}_{timestamp}.json"
        path = os.path.join(output_dir, filename)
        with open(path, "w") as f:
            f.write(report.to_json())
        return path


class MarkdownReporter:
    """Generate Markdown scan reports."""

    def generate(self, report: ScanReport, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{report.repo.name}_{timestamp}.md"
        path = os.path.join(output_dir, filename)
        md = self._build_markdown(report)
        with open(path, "w") as f:
            f.write(md)
        return path

    def _build_markdown(self, report: ScanReport) -> str:
        s = report.summary
        lines = [
            f"# Security Scan Report: {report.repo.name}",
            "",
            f"**Repository**: {report.repo.url}  ",
            f"**Scan Date**: {report.scan_started}  ",
            f"**Duration**: {report.scan_duration_seconds:.1f}s  ",
            f"**Scanners**: {', '.join(report.scanners_used)}  ",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total Findings | {s['total_findings']} |",
            f"| Actionable | {s['actionable_findings']} |",
            f"| False Positives | {s['false_positives']} |",
            "",
            "### Severity Breakdown",
            "",
        ]

        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = s["by_severity"].get(sev, 0)
            if count:
                lines.append(f"- {emoji.get(sev,'')} **{sev.upper()}**: {count}")
        lines += ["", "### By Type", ""]
        for ft, count in s["by_type"].items():
            lines.append(f"- **{ft}**: {count}")
        lines += ["", "## Findings", ""]

        for sev_level in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in report.findings if f.effective_severity == sev_level and f.is_actionable]
            if not sev_findings:
                continue
            lines.append(f"### {emoji.get(sev_level,'')} {sev_level.upper()} ({len(sev_findings)})")
            lines.append("")
            for i, f in enumerate(sev_findings, 1):
                lines.append(f"#### {i}. {f.title}")
                lines.append("")
                lines.append(f"- **Scanner**: {f.scanner} | **Rule**: `{f.rule_id}` | **Confidence**: {f.confidence:.0%}")
                if f.location:
                    lines.append(f"- **File**: `{f.location.file_path}` (line {f.location.start_line})")
                if f.cwe:
                    lines.append(f"- **CWE**: {', '.join(f.cwe)}")
                if f.cve:
                    lines.append(f"- **CVE**: {', '.join(f.cve)}")
                lines.append("")
                if f.description:
                    desc = f.description.replace("\n", " ")[:300]
                    lines.append(f"> {desc}")
                    lines.append("")
                if f.location and f.location.snippet:
                    lines.append("```")
                    lines.append(f.location.snippet[:400])
                    lines.append("```")
                    lines.append("")
                if f.ai_triaged:
                    lines.append(f"**AI Assessment**: {f.ai_exploitability} — {f.ai_reasoning[:200]}")
                    lines.append("")
                if f.remediation:
                    lines.append(f"**Remediation**: {f.remediation[:300]}")
                    lines.append("")
                if f.references:
                    lines.append("**References**: " + ", ".join(f.references[:3]))
                    lines.append("")
                lines.append("---")
                lines.append("")

        # False positives
        fps = [f for f in report.findings if f.ai_is_false_positive]
        if fps:
            lines += ["## Suppressed False Positives", ""]
            for f in fps:
                loc = f.location.file_path if f.location else "N/A"
                lines.append(f"- **{f.title}** in `{loc}` — {f.ai_reasoning[:100]}")
            lines.append("")

        if report.errors:
            lines += ["## Errors", ""]
            for e in report.errors:
                lines.append(f"- {e}")
            lines.append("")

        return "\n".join(lines)


class DatabaseStorage:
    """Store scan results in a TinyDB JSON database."""

    def __init__(self, db_path: str = "scan_history.json"):
        self.db = None
        self.db_path = db_path
        try:
            from tinydb import TinyDB
            self.db = TinyDB(db_path)
        except ImportError:
            pass

    def store(self, report: ScanReport) -> Optional[int]:
        if not self.db:
            return None
        return self.db.insert(report.to_dict())

    def get_history(self, repo_name: str = "") -> list[dict]:
        if not self.db:
            return []
        if repo_name:
            from tinydb import Query
            q = Query()
            return self.db.search(q.repo.name == repo_name)
        return self.db.all()


def generate_reports(report: ScanReport, config) -> list[str]:
    """Generate all configured report formats. Returns list of output paths."""
    output_dir = config.output_dir
    paths = []

    if "json" in config.output_format:
        p = JSONReporter().generate(report, output_dir)
        paths.append(p)

    if "markdown" in config.output_format:
        p = MarkdownReporter().generate(report, output_dir)
        paths.append(p)

    # DB storage
    try:
        db = DatabaseStorage(os.path.join(output_dir, "scan_history.json"))
        db.store(report)
    except Exception:
        pass

    return paths
