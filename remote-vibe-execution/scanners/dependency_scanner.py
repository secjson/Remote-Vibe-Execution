"""Dependency scanner: OSV.dev API + local vulnerability checks."""

from __future__ import annotations
import json
import subprocess
from typing import Optional

import requests

from scanner.config import ScanConfig
from scanner.models import DependencyInfo, Finding, FindingType, Location
from scanners import BaseScanner


class DependencyScanner(BaseScanner):
    """Scans dependencies for known vulnerabilities via OSV.dev and npm/pip audit."""

    name = "dependency_scanner"

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    def scan(self, repo_path: str, **kwargs) -> list[Finding]:
        dependencies: list[DependencyInfo] = kwargs.get("dependencies", [])
        findings = []

        # OSV.dev API scan
        findings.extend(self._scan_osv(dependencies))

        # npm audit
        findings.extend(self._run_npm_audit(repo_path))

        # pip-audit
        findings.extend(self._run_pip_audit(repo_path))

        return findings

    def _scan_osv(self, dependencies: list[DependencyInfo]) -> list[Finding]:
        """Query OSV.dev for known vulnerabilities in dependencies."""
        if not dependencies:
            return []

        findings = []
        ecosystem_map = {
            "npm": "npm", "pypi": "PyPI", "go": "Go",
            "rubygems": "RubyGems", "maven": "Maven",
            "crates.io": "crates.io",
        }

        # Build batch query
        queries = []
        dep_lookup = {}
        for dep in dependencies:
            eco = ecosystem_map.get(dep.ecosystem)
            if not eco:
                continue
            # Clean version string
            version = dep.version.lstrip("^~>=<! ")
            if not version or version == "*":
                continue
            query = {
                "package": {"name": dep.name, "ecosystem": eco},
                "version": version,
            }
            queries.append({"query": query})
            dep_lookup[f"{dep.name}@{version}"] = dep

        if not queries:
            return []

        # Batch query in chunks of 100
        for i in range(0, len(queries), 100):
            batch = queries[i:i + 100]
            try:
                resp = requests.post(
                    self.OSV_BATCH_URL,
                    json={"queries": [q["query"] for q in batch]},
                    timeout=30,
                )
                resp.raise_for_status()
                results = resp.json().get("results", [])

                for j, result in enumerate(results):
                    vulns = result.get("vulns", [])
                    if not vulns:
                        continue

                    # Reconstruct which dependency this is
                    q = batch[j]["query"]
                    dep_key = f"{q['package']['name']}@{q['version']}"
                    dep = dep_lookup.get(dep_key)

                    for vuln in vulns:
                        findings.append(self._osv_to_finding(vuln, dep))

            except (requests.RequestException, json.JSONDecodeError):
                continue

        return findings

    def _osv_to_finding(self, vuln: dict, dep: Optional[DependencyInfo]) -> Finding:
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No summary available")
        details = vuln.get("details", "")
        severity_data = vuln.get("database_specific", {}).get("severity", "")

        # Determine severity from CVSS or severity field
        severity = "medium"
        if vuln.get("severity"):
            for sev in vuln["severity"]:
                score = sev.get("score", "")
                if "CVSS" in sev.get("type", ""):
                    try:
                        # Extract base score
                        import re
                        match = re.search(r"(\d+\.\d+)", score)
                        if match:
                            cvss = float(match.group(1))
                            if cvss >= 9.0:
                                severity = "critical"
                            elif cvss >= 7.0:
                                severity = "high"
                            elif cvss >= 4.0:
                                severity = "medium"
                            else:
                                severity = "low"
                    except (ValueError, AttributeError):
                        pass

        # Get CVEs
        aliases = vuln.get("aliases", [])
        cves = [a for a in aliases if a.startswith("CVE-")]
        cwes = []

        # Get fixed version
        fixed_version = ""
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]

        references = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

        pkg_name = dep.name if dep else "unknown"
        pkg_version = dep.version if dep else "unknown"
        ecosystem = dep.ecosystem if dep else "unknown"

        remediation = f"Upgrade {pkg_name} to version {fixed_version}" if fixed_version else f"Check for patched versions of {pkg_name}"

        return Finding(
            title=f"{vuln_id}: {summary[:100]}",
            description=f"{summary}\n\nPackage: {pkg_name}@{pkg_version} ({ecosystem})\n\n{details[:500]}",
            finding_type=FindingType.DEPENDENCY,
            severity=severity,
            confidence=0.9,
            location=Location(file_path=f"[dependency] {pkg_name}@{pkg_version}"),
            scanner=self.name,
            rule_id=vuln_id,
            cve=cves,
            cwe=cwes,
            references=references[:5],
            remediation=remediation,
            raw_data={"vuln_id": vuln_id, "package": pkg_name, "version": pkg_version},
        )

    def _run_npm_audit(self, repo_path: str) -> list[Finding]:
        """Run npm audit if package-lock.json exists."""
        import os
        lock_file = os.path.join(repo_path, "package-lock.json")
        if not os.path.exists(lock_file):
            return []

        findings = []
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True,
                cwd=repo_path, timeout=120,
            )
            data = json.loads(result.stdout)
            for vuln_name, vuln_data in data.get("vulnerabilities", {}).items():
                severity = vuln_data.get("severity", "medium")
                findings.append(Finding(
                    title=f"npm: {vuln_name} - {vuln_data.get('title', 'vulnerability')}",
                    description=vuln_data.get("url", ""),
                    finding_type=FindingType.DEPENDENCY,
                    severity=severity,
                    confidence=0.85,
                    location=Location(file_path=f"[npm] {vuln_name}@{vuln_data.get('range', '')}"),
                    scanner=self.name,
                    rule_id=f"npm-audit/{vuln_name}",
                    remediation=f"Run: npm audit fix, or upgrade {vuln_name} to {vuln_data.get('fixAvailable', 'latest')}",
                ))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return findings

    def _run_pip_audit(self, repo_path: str) -> list[Finding]:
        """Run pip-audit if requirements.txt exists."""
        import os
        req_file = os.path.join(repo_path, "requirements.txt")
        if not os.path.exists(req_file):
            return []

        findings = []
        try:
            result = subprocess.run(
                ["pip-audit", "-r", req_file, "--format", "json"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
            for vuln in data.get("dependencies", []):
                for v in vuln.get("vulns", []):
                    findings.append(Finding(
                        title=f"pip: {vuln['name']}@{vuln['version']} - {v.get('id', '')}",
                        description=v.get("description", ""),
                        finding_type=FindingType.DEPENDENCY,
                        severity="high",
                        confidence=0.85,
                        location=Location(file_path=f"[pip] {vuln['name']}@{vuln['version']}"),
                        scanner=self.name,
                        rule_id=v.get("id", ""),
                        cve=[v["id"]] if v.get("id", "").startswith("CVE-") else [],
                        remediation=f"Upgrade {vuln['name']} to {v.get('fix_versions', ['latest'])}",
                    ))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return findings
