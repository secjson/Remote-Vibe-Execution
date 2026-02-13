"""Configuration models for Remote Vibe Execution."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import yaml
import os


class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    NONE = "none"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}[self.value]


@dataclass
class ScanConfig:
    """Master configuration for a scan run."""

    # Target
    repo_url: str = ""
    repo_path: str = ""
    github_token: str = ""

    # Scan toggles
    enable_secret_scan: bool = True
    enable_static_analysis: bool = True
    enable_dependency_scan: bool = True
    enable_ai_triage: bool = True

    # AI config
    ai_provider: AIProvider = AIProvider.NONE
    ai_model: str = ""
    ai_api_key: str = ""

    # Filtering
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "node_modules/", ".git/", "__pycache__/", "*.min.js",
        "vendor/", "dist/", "build/", ".venv/", "venv/",
        "*.lock", "package-lock.json",
    ])
    include_extensions: list[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".c", ".cpp", ".h", ".rs", ".swift", ".kt",
        ".scala", ".sh", ".bash", ".yml", ".yaml", ".json", ".xml",
        ".tf", ".hcl", ".dockerfile", ".sql", ".html", ".env",
    ])
    max_file_size_kb: int = 500
    chunk_size_lines: int = 200

    # Output
    output_dir: str = "./output"
    output_format: list[str] = field(default_factory=lambda: ["json", "markdown"])

    # Semgrep
    semgrep_rules: list[str] = field(default_factory=lambda: [
        "p/security-audit", "p/secrets", "p/owasp-top-ten",
    ])
    custom_rules_dir: str = "./rules"

    # Severity thresholds
    min_severity: SeverityLevel = SeverityLevel.LOW
    ai_min_severity: SeverityLevel = SeverityLevel.INFO
    confidence_threshold: float = 0.5

    @classmethod
    def from_yaml(cls, path: str) -> ScanConfig:
        with open(path) as f:
            data = yaml.safe_load(f)
        config = cls()
        for k, v in (data or {}).items():
            if k == "ai_provider":
                v = AIProvider(v)
            elif k in ("min_severity", "ai_min_severity"):
                v = SeverityLevel(v)
            if hasattr(config, k):
                setattr(config, k, v)
        return config

    @classmethod
    def from_env(cls) -> ScanConfig:
        """Load sensitive values from environment variables."""
        config = cls()
        config.github_token = os.getenv("GITHUB_TOKEN", "")
        config.ai_api_key = os.getenv("AI_API_KEY", os.getenv("OPENAI_API_KEY", os.getenv("ANTHROPIC_API_KEY", "")))
        provider = os.getenv("AI_PROVIDER", "none")
        config.ai_provider = AIProvider(provider)
        config.ai_model = os.getenv("AI_MODEL", "")
        return config

    def merge(self, other: ScanConfig) -> ScanConfig:
        """Merge another config into this one (other takes precedence for non-default values)."""
        import copy
        merged = copy.deepcopy(self)
        defaults = ScanConfig()
        for fld in vars(other):
            val = getattr(other, fld)
            default_val = getattr(defaults, fld)
            if val != default_val:
                setattr(merged, fld, val)
        return merged
