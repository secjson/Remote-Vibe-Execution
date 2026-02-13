"""Secret scanner: TruffleHog integration + built-in regex patterns."""

from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path

from scanner.config import ScanConfig
from scanner.models import Finding, FindingType, Location
from scanners import BaseScanner


# Built-in secret patterns as fallback when TruffleHog is not available
SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "cwe": ["CWE-798"],
    },
    "AWS Secret Key": {
        "pattern": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "cwe": ["CWE-798"],
    },
    "GitHub Token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": "critical",
        "cwe": ["CWE-798"],
    },
    "Generic API Key": {
        "pattern": r"""(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,64})['\"]?""",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
    "Private Key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
        "cwe": ["CWE-321"],
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
    "Database Connection String": {
        "pattern": r"""(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s'"<>]{10,}""",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
    "Stripe Key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "cwe": ["CWE-798"],
    },
    "Heroku API Key": {
        "pattern": r"(?i)heroku[_\-]?api[_\-]?key[\s]*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
    "Password in Config": {
        "pattern": r"""(?i)(?:password|passwd|pwd)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]""",
        "severity": "high",
        "cwe": ["CWE-798", "CWE-259"],
    },
    "Bearer Token": {
        "pattern": r"""(?i)(?:bearer|authorization)[\s]*[=:]\s*['\"]?(?:Bearer\s+)?([A-Za-z0-9_\-.]{20,})['\"]?""",
        "severity": "high",
        "cwe": ["CWE-798"],
    },
}

# Files that often contain false positive secrets
FALSE_POSITIVE_FILES = {
    ".env.example", ".env.sample", ".env.template",
    "example.env", "sample.env",
}


class SecretScanner(BaseScanner):
    """Detects hardcoded secrets using TruffleHog + regex fallback."""

    name = "secret_scanner"

    def scan(self, repo_path: str, **kwargs) -> list[Finding]:
        findings = []

        # Try TruffleHog first
        if self._trufflehog_available():
            findings.extend(self._run_trufflehog(repo_path))
        else:
            # Fallback to regex-based scanning
            findings.extend(self._run_regex_scan(repo_path))

        return findings

    def is_available(self) -> bool:
        return True  # Always available via regex fallback

    def _trufflehog_available(self) -> bool:
        try:
            result = subprocess.run(
                ["trufflehog", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_trufflehog(self, repo_path: str) -> list[Finding]:
        findings = []
        try:
            result = subprocess.run(
                [
                    "trufflehog", "filesystem", repo_path,
                    "--json", "--no-update",
                ],
                capture_output=True, text=True, timeout=600,
            )
            for line in result.stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    finding = self._parse_trufflehog_finding(data, repo_path)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            pass
        return findings

    def _parse_trufflehog_finding(self, data: dict, repo_path: str) -> Finding | None:
        source = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        file_path = source.get("file", "")
        if not file_path:
            return None

        # Make relative
        rel_path = file_path
        if file_path.startswith(repo_path):
            rel_path = file_path[len(repo_path):].lstrip("/")

        # Skip false-positive files
        if Path(rel_path).name in FALSE_POSITIVE_FILES:
            return None

        detector = data.get("DetectorName", "Unknown")
        verified = data.get("Verified", False)

        return Finding(
            title=f"Secret Detected: {detector}",
            description=f"TruffleHog detected a potential {detector} secret. Verified: {verified}",
            finding_type=FindingType.SECRET,
            severity="critical" if verified else "high",
            confidence=0.95 if verified else 0.7,
            location=Location(
                file_path=rel_path,
                start_line=source.get("line", 0),
                snippet=data.get("Raw", "")[:200] + "..." if len(data.get("Raw", "")) > 200 else data.get("Raw", ""),
            ),
            scanner=self.name,
            rule_id=f"trufflehog/{detector}",
            cwe=["CWE-798"],
            remediation=f"Rotate the {detector} credential immediately and remove it from source code. Use environment variables or a secrets manager.",
            raw_data={"verified": verified, "detector": detector},
        )

    def _run_regex_scan(self, repo_path: str) -> list[Finding]:
        findings = []
        root = Path(repo_path)

        for fp in root.rglob("*"):
            if not fp.is_file():
                continue
            if fp.stat().st_size > self.config.max_file_size_kb * 1024:
                continue
            if fp.name in FALSE_POSITIVE_FILES:
                continue

            # Skip binary files
            try:
                content = fp.read_text(errors="replace")
            except Exception:
                continue

            rel_path = str(fp.relative_to(root))

            # Skip excluded paths
            skip = False
            for pattern in self.config.exclude_patterns:
                if pattern.startswith("*"):
                    if rel_path.endswith(pattern[1:]):
                        skip = True
                        break
                elif pattern in rel_path:
                    skip = True
                    break
            if skip:
                continue

            lines = content.splitlines()
            for secret_name, secret_info in SECRET_PATTERNS.items():
                compiled = re.compile(secret_info["pattern"])
                for i, line in enumerate(lines):
                    if compiled.search(line):
                        # Basic false positive filtering
                        if self._is_likely_false_positive(line, rel_path):
                            continue
                        findings.append(Finding(
                            title=f"Potential {secret_name}",
                            description=f"Regex pattern matched for {secret_name} in {rel_path}",
                            finding_type=FindingType.SECRET,
                            severity=secret_info["severity"],
                            confidence=0.6,
                            location=Location(
                                file_path=rel_path,
                                start_line=i + 1,
                                end_line=i + 1,
                                snippet=self._redact_secret(line.strip()),
                            ),
                            scanner=self.name,
                            rule_id=f"regex/{secret_name.lower().replace(' ', '_')}",
                            cwe=secret_info["cwe"],
                            remediation=f"Verify if this is a real {secret_name}. If so, rotate it and use a secrets manager.",
                        ))
        return findings

    def _is_likely_false_positive(self, line: str, file_path: str) -> bool:
        line_lower = line.lower().strip()

        # Comments explaining secrets
        if line_lower.startswith(("#", "//", "/*", "*", "<!--")):
            if any(word in line_lower for word in ["example", "placeholder", "your_", "xxx", "changeme", "todo"]):
                return True

        # Test/example files
        if any(x in file_path.lower() for x in ["test", "example", "mock", "fixture", "sample", "demo"]):
            return True

        # Common placeholder values
        placeholders = ["your_api_key", "xxx", "changeme", "replace_me", "insert_", "put_your", "<your", "PLACEHOLDER"]
        if any(p.lower() in line_lower for p in placeholders):
            return True

        return False

    def _redact_secret(self, line: str, visible_chars: int = 8) -> str:
        """Partially redact the secret value in the snippet."""
        if len(line) > 80:
            return line[:40] + "...[REDACTED]..." + line[-20:]
        return line
