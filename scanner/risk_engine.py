"""Finding correlation and risk engine: deduplication, scoring, confidence weighting."""

from __future__ import annotations
from collections import defaultdict
from scanner.config import ScanConfig, SeverityLevel
from scanner.models import Finding


SEVERITY_SCORES = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}


class RiskEngine:
    """Deduplicates, correlates, and scores findings."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def process(self, findings: list[Finding]) -> list[Finding]:
        """Full pipeline: deduplicate, correlate, score, filter, sort."""
        findings = self._deduplicate(findings)
        findings = self._correlate(findings)
        findings = self._apply_confidence_weighting(findings)
        findings = self._filter_by_threshold(findings)
        findings = self._sort(findings)
        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings across scanners."""
        seen = {}
        deduped = []

        for f in findings:
            # Build a dedup key based on location + type
            key_parts = [
                f.finding_type.value,
                f.location.file_path if f.location else "",
                str(f.location.start_line if f.location else 0),
            ]
            # Also consider rule similarity
            if f.rule_id:
                # Normalize rule IDs for cross-scanner dedup
                rule_base = f.rule_id.split("/")[-1].lower().replace("-", "_").replace(" ", "_")
                key_parts.append(rule_base)

            key = "|".join(key_parts)

            if key in seen:
                # Keep the one with higher confidence
                existing = seen[key]
                if f.confidence > existing.confidence:
                    # Replace - but boost confidence since multiple scanners found it
                    f.confidence = min(1.0, f.confidence + 0.1)
                    seen[key] = f
                    deduped = [x for x in deduped if x.id != existing.id]
                    deduped.append(f)
                else:
                    # Boost existing confidence
                    existing.confidence = min(1.0, existing.confidence + 0.1)
            else:
                seen[key] = f
                deduped.append(f)

        return deduped

    def _correlate(self, findings: list[Finding]) -> list[Finding]:
        """Correlate related findings to identify attack chains."""
        # Group by file
        by_file = defaultdict(list)
        for f in findings:
            if f.location:
                by_file[f.location.file_path].append(f)

        # Boost severity for files with multiple findings (attack surface concentration)
        for file_path, file_findings in by_file.items():
            if len(file_findings) >= 3:
                # Multiple vulnerabilities in same file = higher risk
                for f in file_findings:
                    if f.severity == "medium":
                        f.severity = "high"
                    elif f.severity == "low":
                        f.severity = "medium"

        # Check for dangerous combinations
        finding_types = {f.rule_id.split("/")[-1] if f.rule_id else "" for f in findings}

        # SQL injection + secrets = critical combination
        has_sqli = any("sql" in t.lower() for t in finding_types)
        has_secrets = any(f.finding_type.value == "secret" for f in findings)
        if has_sqli and has_secrets:
            for f in findings:
                if "sql" in (f.rule_id or "").lower():
                    f.severity = "critical"
                    f.description += "\n\n⚠️ CORRELATED: SQL injection found alongside exposed secrets - elevated risk."

        return findings

    def _apply_confidence_weighting(self, findings: list[Finding]) -> list[Finding]:
        """Adjust effective severity based on confidence score."""
        for f in findings:
            # If AI triage was done, use that
            if f.ai_triaged and f.ai_adjusted_severity:
                continue

            # Low confidence findings get severity reduction
            if f.confidence < 0.4:
                downgrade = {
                    "critical": "high", "high": "medium",
                    "medium": "low", "low": "info",
                }
                f.severity = downgrade.get(f.severity, f.severity)

        return findings

    def _filter_by_threshold(self, findings: list[Finding]) -> list[Finding]:
        """Filter findings below severity/confidence thresholds."""
        min_score = self.config.min_severity.score
        min_confidence = self.config.confidence_threshold

        filtered = []
        for f in findings:
            sev = f.effective_severity
            score = SEVERITY_SCORES.get(sev, 0)
            if score >= min_score and f.confidence >= min_confidence:
                filtered.append(f)

        return filtered

    def _sort(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings by severity (desc), then confidence (desc)."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            findings,
            key=lambda f: (
                order.get(f.effective_severity, 5),
                -f.confidence,
            ),
        )
