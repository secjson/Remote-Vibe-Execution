"""AI Agent Layer: Context reasoning, false positive triage, exploitability assessment."""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

from scanner.config import AIProvider, ScanConfig
from scanner.models import Finding


TRIAGE_SYSTEM_PROMPT = """You are an expert application security engineer performing triage on automated scan findings.

For each finding, analyze:
1. **False Positive Assessment**: Is this likely a real vulnerability or a false positive? Consider:
   - Is the pattern match in a comment, documentation, or test file?
   - Is the detected secret a placeholder, example, or template value?
   - Is the vulnerable code actually reachable?

2. **Exploitability**: How exploitable is this in practice?
   - "confirmed": Clear evidence of exploitability
   - "likely": Probable exploitability given typical usage
   - "unlikely": Requires unusual conditions to exploit
   - "false_positive": Not a real vulnerability

3. **Severity Adjustment**: Should the severity be adjusted based on context?
   - Consider data flow, authentication barriers, network exposure
   - Consider if the vulnerability is in dead code or test code

4. **Remediation**: Provide specific, actionable remediation advice.

Respond ONLY in JSON format with these fields:
{
    "is_false_positive": boolean,
    "exploitability": "confirmed" | "likely" | "unlikely" | "false_positive",
    "adjusted_severity": "critical" | "high" | "medium" | "low" | "info",
    "reasoning": "brief explanation",
    "remediation": "specific fix advice"
}"""


class AITriageAgent:
    """Uses LLM to triage and assess findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.provider = config.ai_provider
        self._client = None

    def _get_client(self):
        if self._client:
            return self._client

        if self.provider == AIProvider.OPENAI:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.config.ai_api_key)
        elif self.provider == AIProvider.ANTHROPIC:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.config.ai_api_key)
        return self._client

    def triage_findings(
        self, findings: list[Finding], repo_path: str
    ) -> list[Finding]:
        """Triage all findings using AI. Returns findings with AI fields populated."""
        if self.provider == AIProvider.NONE:
            return findings

        client = self._get_client()
        if not client:
            return findings

        triaged = []
        for finding in findings:
            try:
                result = self._triage_single(finding, repo_path)
                if result:
                    finding.ai_triaged = True
                    finding.ai_is_false_positive = result.get("is_false_positive", False)
                    finding.ai_exploitability = result.get("exploitability", "")
                    finding.ai_reasoning = result.get("reasoning", "")
                    finding.ai_adjusted_severity = result.get("adjusted_severity", finding.severity)
                    if result.get("remediation"):
                        finding.remediation = result["remediation"]
            except Exception as e:
                finding.ai_reasoning = f"AI triage failed: {str(e)}"
            triaged.append(finding)

        return triaged

    def _triage_single(self, finding: Finding, repo_path: str) -> Optional[dict]:
        """Triage a single finding."""
        # Build context
        context = self._build_context(finding, repo_path)
        prompt = self._build_prompt(finding, context)

        response_text = self._call_llm(prompt)
        if not response_text:
            return None

        # Parse JSON response
        try:
            # Handle potential markdown code blocks
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                text = text.rsplit("```", 1)[0]
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _build_context(self, finding: Finding, repo_path: str) -> str:
        """Build context around the finding for better triage."""
        context_parts = []

        if finding.location and finding.location.file_path:
            file_path = os.path.join(repo_path, finding.location.file_path)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, "r", errors="replace") as f:
                        lines = f.readlines()

                    # Get surrounding context (30 lines before and after)
                    start = max(0, finding.location.start_line - 30)
                    end = min(len(lines), finding.location.end_line + 30)
                    context_parts.append(
                        f"File: {finding.location.file_path}\n"
                        f"Lines {start + 1}-{end}:\n"
                        + "".join(lines[start:end])
                    )
                except Exception:
                    pass

        return "\n".join(context_parts)[:4000]  # Limit context size

    def _build_prompt(self, finding: Finding, context: str) -> str:
        return f"""Triage this security finding:

**Title**: {finding.title}
**Type**: {finding.finding_type.value}
**Scanner**: {finding.scanner}
**Rule**: {finding.rule_id}
**Current Severity**: {finding.severity}
**Confidence**: {finding.confidence}
**CWE**: {', '.join(finding.cwe)}

**Location**: {finding.location.file_path if finding.location else 'N/A'} (line {finding.location.start_line if finding.location else 'N/A'})

**Code Snippet**:
```
{finding.location.snippet if finding.location else 'N/A'}
```

**Surrounding Context**:
```
{context}
```

**Description**: {finding.description}

Analyze this finding and respond with JSON only."""

    def _call_llm(self, prompt: str) -> Optional[str]:
        client = self._get_client()

        if self.provider == AIProvider.OPENAI:
            model = self.config.ai_model or "gpt-4o"
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=1000,
            )
            return response.choices[0].message.content

        elif self.provider == AIProvider.ANTHROPIC:
            model = self.config.ai_model or "claude-sonnet-4-20250514"
            response = client.messages.create(
                model=model,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=1000,
            )
            return response.content[0].text

        return None


class DataFlowAnalyzer:
    """Simple data flow analysis to identify taint paths."""

    # Common source functions (user input)
    SOURCES = {
        "python": ["request.args", "request.form", "request.json", "request.data",
                    "request.files", "input(", "sys.argv", "os.environ"],
        "javascript": ["req.params", "req.query", "req.body", "req.headers",
                       "process.argv", "process.env", "document.location",
                       "window.location", "document.URL"],
    }

    # Common sink functions (dangerous operations)
    SINKS = {
        "python": ["execute(", "system(", "popen(", "eval(", "exec(",
                    "subprocess", "render_template_string(", "send_file("],
        "javascript": ["eval(", "exec(", "innerHTML", "document.write(",
                       "child_process", "Function(", "setTimeout(", "setInterval("],
    }

    def analyze_file(self, file_path: str, language: str) -> list[dict]:
        """Find potential taint paths in a file."""
        if language not in self.SOURCES:
            return []

        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        lines = content.splitlines()
        source_lines = []
        sink_lines = []

        sources = self.SOURCES.get(language, [])
        sinks = self.SINKS.get(language, [])

        for i, line in enumerate(lines):
            for src in sources:
                if src in line:
                    source_lines.append({"line": i + 1, "source": src, "code": line.strip()})
            for sink in sinks:
                if sink in line:
                    sink_lines.append({"line": i + 1, "sink": sink, "code": line.strip()})

        # Simple proximity-based taint tracking (within same function/block)
        paths = []
        for src in source_lines:
            for sink in sink_lines:
                if abs(src["line"] - sink["line"]) < 50:  # Within 50 lines
                    paths.append({
                        "source": src,
                        "sink": sink,
                        "distance": abs(src["line"] - sink["line"]),
                    })

        return paths
