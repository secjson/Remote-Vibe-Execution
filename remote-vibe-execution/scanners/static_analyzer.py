"""Static analyzer: Semgrep integration + built-in vulnerability patterns."""

from __future__ import annotations
import json
import subprocess
from pathlib import Path

from scanner.config import ScanConfig
from scanner.models import Finding, FindingType, Location
from scanners import BaseScanner


# Built-in vulnerability patterns when Semgrep is not available
BUILTIN_RULES = {
    "python": [
        {
            "id": "sql-injection",
            "pattern": r"""(?:execute|cursor\.execute|raw|RawSQL)\s*\(.*(?:f['\"]|\.format\(|%\s)""",
            "title": "Potential SQL Injection",
            "description": "String formatting used in SQL query construction. Use parameterized queries instead.",
            "severity": "high",
            "cwe": ["CWE-89"],
        },
        {
            "id": "command-injection",
            "pattern": r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(.*(?:f['\"]|\.format\(|\+\s*\w)""",
            "title": "Potential Command Injection",
            "description": "User-controlled input may reach OS command execution.",
            "severity": "critical",
            "cwe": ["CWE-78"],
        },
        {
            "id": "ssrf",
            "pattern": r"""(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get)\s*\(.*(?:f['\"]|\.format\(|\+\s*\w)""",
            "title": "Potential SSRF",
            "description": "User-controlled URL in HTTP request may allow SSRF.",
            "severity": "high",
            "cwe": ["CWE-918"],
        },
        {
            "id": "eval-usage",
            "pattern": r"""\beval\s*\(""",
            "title": "Use of eval()",
            "description": "eval() can execute arbitrary code. Avoid using it with untrusted input.",
            "severity": "high",
            "cwe": ["CWE-95"],
        },
        {
            "id": "pickle-deserialize",
            "pattern": r"""pickle\.loads?\s*\(""",
            "title": "Unsafe Deserialization (pickle)",
            "description": "pickle.load can execute arbitrary code during deserialization.",
            "severity": "high",
            "cwe": ["CWE-502"],
        },
        {
            "id": "hardcoded-temp-path",
            "pattern": r"""['\"]\/tmp\/[^'\"]+['\"]""",
            "title": "Hardcoded Temp Path",
            "description": "Hardcoded /tmp paths can lead to symlink attacks.",
            "severity": "low",
            "cwe": ["CWE-377"],
        },
        {
            "id": "weak-crypto",
            "pattern": r"""(?:hashlib\.md5|hashlib\.sha1|DES\.|RC4\.)""",
            "title": "Weak Cryptographic Algorithm",
            "description": "MD5/SHA1/DES/RC4 are cryptographically weak. Use SHA-256+ or AES.",
            "severity": "medium",
            "cwe": ["CWE-327"],
        },
        {
            "id": "debug-enabled",
            "pattern": r"""(?i)DEBUG\s*=\s*True""",
            "title": "Debug Mode Enabled",
            "description": "Debug mode may expose sensitive information in production.",
            "severity": "medium",
            "cwe": ["CWE-489"],
        },
    ],
    "javascript": [
        {
            "id": "xss-innerhtml",
            "pattern": r"""\.innerHTML\s*=""",
            "title": "Potential XSS via innerHTML",
            "description": "Direct innerHTML assignment can lead to XSS. Use textContent or sanitize input.",
            "severity": "high",
            "cwe": ["CWE-79"],
        },
        {
            "id": "eval-usage",
            "pattern": r"""\beval\s*\(""",
            "title": "Use of eval()",
            "description": "eval() can execute arbitrary code.",
            "severity": "high",
            "cwe": ["CWE-95"],
        },
        {
            "id": "sql-injection",
            "pattern": r"""(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|['"].*\+)""",
            "title": "Potential SQL Injection",
            "description": "String concatenation/interpolation in SQL query.",
            "severity": "high",
            "cwe": ["CWE-89"],
        },
        {
            "id": "prototype-pollution",
            "pattern": r"""(?:__proto__|constructor\s*\[|Object\.assign\s*\(\s*\{\},.*(?:req\.|params|query|body))""",
            "title": "Potential Prototype Pollution",
            "description": "Object property assignment from user input may cause prototype pollution.",
            "severity": "high",
            "cwe": ["CWE-1321"],
        },
        {
            "id": "path-traversal",
            "pattern": r"""(?:readFile|readFileSync|createReadStream)\s*\(.*(?:req\.|params|query)""",
            "title": "Potential Path Traversal",
            "description": "User input in file path without sanitization.",
            "severity": "high",
            "cwe": ["CWE-22"],
        },
        {
            "id": "cors-wildcard",
            "pattern": r"""(?:Access-Control-Allow-Origin|cors)\s*.*\*""",
            "title": "CORS Wildcard",
            "description": "Wildcard CORS allows any origin to make requests.",
            "severity": "medium",
            "cwe": ["CWE-942"],
        },
        {
            "id": "no-csrf",
            "pattern": r"""app\.(?:post|put|delete|patch)\s*\(""",
            "title": "State-Changing Route (verify CSRF protection)",
            "description": "Ensure CSRF protection is enabled for state-changing routes.",
            "severity": "info",
            "cwe": ["CWE-352"],
        },
    ],
    "go": [
        {
            "id": "sql-injection",
            "pattern": r"""(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(.*(?:fmt\.Sprintf|\+\s*\w)""",
            "title": "Potential SQL Injection",
            "description": "String formatting used in SQL query.",
            "severity": "high",
            "cwe": ["CWE-89"],
        },
        {
            "id": "command-injection",
            "pattern": r"""exec\.Command\s*\(.*(?:fmt\.Sprintf|\+\s*\w)""",
            "title": "Potential Command Injection",
            "description": "User input in command execution.",
            "severity": "critical",
            "cwe": ["CWE-78"],
        },
        {
            "id": "tls-insecure",
            "pattern": r"""InsecureSkipVerify\s*:\s*true""",
            "title": "TLS Verification Disabled",
            "description": "Disabling TLS verification allows MITM attacks.",
            "severity": "high",
            "cwe": ["CWE-295"],
        },
    ],
    "generic": [
        {
            "id": "todo-security",
            "pattern": r"""(?i)(?:TODO|FIXME|HACK|XXX).*(?:security|vuln|auth|password|token|secret|inject|sanitiz)""",
            "title": "Security-Related TODO",
            "description": "Developer left a security-related TODO comment.",
            "severity": "info",
            "cwe": [],
        },
        {
            "id": "disable-security",
            "pattern": r"""(?i)(?:nosec|nolint|nosonar|NOSONAR|@SuppressWarnings.*security|# nosemgrep)""",
            "title": "Security Check Suppressed",
            "description": "A security linting rule has been intentionally suppressed.",
            "severity": "medium",
            "cwe": [],
        },
    ],
}


class StaticAnalyzer(BaseScanner):
    """Static analysis using Semgrep + built-in regex rules."""

    name = "static_analyzer"

    def scan(self, repo_path: str, **kwargs) -> list[Finding]:
        findings = []

        # Try Semgrep
        if self._semgrep_available():
            findings.extend(self._run_semgrep(repo_path))
        
        # Always run built-in rules (they complement Semgrep)
        findings.extend(self._run_builtin_rules(repo_path))

        return findings

    def _semgrep_available(self) -> bool:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_semgrep(self, repo_path: str) -> list[Finding]:
        findings = []
        for rule_config in self.config.semgrep_rules:
            try:
                cmd = [
                    "semgrep", "--config", rule_config,
                    "--json", "--quiet",
                    "--timeout", "60",
                    repo_path,
                ]
                # Add custom rules if directory exists
                custom_dir = Path(self.config.custom_rules_dir)
                if custom_dir.is_dir() and list(custom_dir.glob("*.yml")):
                    cmd = [
                        "semgrep", "--config", rule_config,
                        "--config", str(custom_dir),
                        "--json", "--quiet",
                        "--timeout", "60",
                        repo_path,
                    ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                if result.stdout:
                    data = json.loads(result.stdout)
                    for r in data.get("results", []):
                        findings.append(self._parse_semgrep_result(r, repo_path))
            except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
                continue
        return findings

    def _parse_semgrep_result(self, result: dict, repo_path: str) -> Finding:
        path = result.get("path", "")
        if path.startswith(repo_path):
            path = path[len(repo_path):].lstrip("/")

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}
        severity = severity_map.get(extra.get("severity", "WARNING"), "medium")

        cwe_list = []
        for cwe in metadata.get("cwe", []):
            if isinstance(cwe, str):
                cwe_list.append(cwe.split(":")[0] if ":" in cwe else cwe)

        return Finding(
            title=extra.get("message", result.get("check_id", "Semgrep Finding"))[:200],
            description=extra.get("message", ""),
            finding_type=FindingType.VULNERABILITY,
            severity=severity,
            confidence=0.8,
            location=Location(
                file_path=path,
                start_line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0),
                snippet=extra.get("lines", "")[:500],
            ),
            scanner=self.name,
            rule_id=result.get("check_id", ""),
            cwe=cwe_list,
            references=metadata.get("references", []),
            remediation=metadata.get("fix", ""),
        )

    def _run_builtin_rules(self, repo_path: str) -> list[Finding]:
        import re
        findings = []
        root = Path(repo_path)

        from scanner.preprocessor import FileFilter, detect_language
        file_filter = FileFilter(self.config)

        for fp in root.rglob("*"):
            if not fp.is_file():
                continue
            if not file_filter.should_include(fp, root):
                continue

            try:
                content = fp.read_text(errors="replace")
            except Exception:
                continue

            rel_path = str(fp.relative_to(root))
            lang = detect_language(fp.suffix.lower())

            # Get applicable rules
            rules = BUILTIN_RULES.get(lang, []) + BUILTIN_RULES.get("generic", [])

            lines = content.splitlines()
            for rule in rules:
                compiled = re.compile(rule["pattern"])
                for i, line in enumerate(lines):
                    if compiled.search(line):
                        findings.append(Finding(
                            title=rule["title"],
                            description=rule["description"],
                            finding_type=FindingType.VULNERABILITY,
                            severity=rule["severity"],
                            confidence=0.6,
                            location=Location(
                                file_path=rel_path,
                                start_line=i + 1,
                                end_line=i + 1,
                                snippet=line.strip()[:500],
                            ),
                            scanner=self.name,
                            rule_id=f"builtin/{lang}/{rule['id']}",
                            cwe=rule["cwe"],
                            remediation=rule["description"],
                        ))
        return findings
