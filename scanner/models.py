"""Core data models for scan findings."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import hashlib
import json


class FindingType(Enum):
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    DEPENDENCY = "dependency"
    MISCONFIGURATION = "misconfiguration"
    CODE_SMELL = "code_smell"


@dataclass
class Location:
    file_path: str
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "snippet": self.snippet[:500],  # Truncate long snippets
        }


@dataclass
class Finding:
    """A single security finding from any scanner."""

    id: str = ""
    title: str = ""
    description: str = ""
    finding_type: FindingType = FindingType.VULNERABILITY
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: float = 0.5  # 0.0 - 1.0
    location: Optional[Location] = None
    scanner: str = ""  # Which scanner produced this
    rule_id: str = ""
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    raw_data: dict = field(default_factory=dict)

    # AI triage fields
    ai_triaged: bool = False
    ai_is_false_positive: bool = False
    ai_exploitability: str = ""  # "confirmed", "likely", "unlikely", "false_positive"
    ai_reasoning: str = ""
    ai_adjusted_severity: str = ""

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def __post_init__(self):
        if not self.id:
            self.id = self._generate_id()

    def _generate_id(self) -> str:
        unique = f"{self.scanner}:{self.rule_id}:{self.location.file_path if self.location else ''}:{self.title}"
        return hashlib.sha256(unique.encode()).hexdigest()[:16]

    @property
    def effective_severity(self) -> str:
        return self.ai_adjusted_severity or self.severity

    @property
    def is_actionable(self) -> bool:
        if self.ai_triaged:
            return not self.ai_is_false_positive and self.ai_exploitability != "false_positive"
        return True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "finding_type": self.finding_type.value,
            "severity": self.severity,
            "effective_severity": self.effective_severity,
            "confidence": self.confidence,
            "location": self.location.to_dict() if self.location else None,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "cve": self.cve,
            "references": self.references,
            "remediation": self.remediation,
            "ai_triaged": self.ai_triaged,
            "ai_is_false_positive": self.ai_is_false_positive,
            "ai_exploitability": self.ai_exploitability,
            "ai_reasoning": self.ai_reasoning,
            "ai_adjusted_severity": self.ai_adjusted_severity,
            "timestamp": self.timestamp,
        }


@dataclass
class DependencyInfo:
    name: str
    version: str
    ecosystem: str  # npm, pypi, maven, go, etc.
    direct: bool = True
    license: str = ""

    def to_dict(self) -> dict:
        return vars(self)


@dataclass
class RepoMetadata:
    url: str = ""
    name: str = ""
    owner: str = ""
    default_branch: str = "main"
    languages: dict[str, int] = field(default_factory=dict)
    file_count: int = 0
    total_size_kb: int = 0
    stars: int = 0
    forks: int = 0
    last_commit: str = ""
    dependencies: list[DependencyInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = vars(self).copy()
        d["dependencies"] = [dep.to_dict() for dep in self.dependencies]
        return d


@dataclass
class ScanReport:
    """Complete scan report aggregating all findings."""

    repo: RepoMetadata = field(default_factory=RepoMetadata)
    findings: list[Finding] = field(default_factory=list)
    scan_started: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_completed: str = ""
    scan_duration_seconds: float = 0
    scanners_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        by_severity = {}
        by_type = {}
        actionable = 0
        false_positives = 0
        for f in self.findings:
            sev = f.effective_severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
            ft = f.finding_type.value
            by_type[ft] = by_type.get(ft, 0) + 1
            if f.is_actionable:
                actionable += 1
            if f.ai_is_false_positive:
                false_positives += 1
        return {
            "total_findings": len(self.findings),
            "actionable_findings": actionable,
            "false_positives": false_positives,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    def to_dict(self) -> dict:
        return {
            "repo": self.repo.to_dict(),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "scan_started": self.scan_started,
            "scan_completed": self.scan_completed,
            "scan_duration_seconds": self.scan_duration_seconds,
            "scanners_used": self.scanners_used,
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
