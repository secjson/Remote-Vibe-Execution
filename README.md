# 🔒 Remote Vibe Execution

AI-powered security code scanner for GitHub repositories. Combines secret detection, static analysis, dependency scanning, and LLM-based triage into a single pipeline.

## Architecture

```
GitHub API → Repo Ingestion → Pre-Processing → ┬─ Secret Scanner (TruffleHog + regex)
                                                 ├─ Static Analyzer (Semgrep + built-in rules)
                                                 └─ Dependency Scanner (OSV.dev + npm/pip audit)
                                                          │
                                                    AI Agent Layer (triage, exploitability)
                                                          │
                                                    Risk Engine (dedup, score, correlate)
                                                          │
                                                    Reports (JSON + Markdown + DB)
```

## Quick Start

```bash
# Install
pip install -e .

# Scan a GitHub repo
remote-vibe-execution scan https://github.com/owner/repo

# Scan a local directory
remote-vibe-execution scan ./my-project

# With AI triage (OpenAI)
export AI_API_KEY="sk-..."
remote-vibe-execution scan https://github.com/owner/repo --ai-provider openai

# With AI triage (Anthropic)
export AI_API_KEY="sk-ant-..."
remote-vibe-execution scan https://github.com/owner/repo --ai-provider anthropic --ai-model claude-sonnet-4-20250514

# Search GitHub repos
remote-vibe-execution search "django vulnerable app"
```

## Installation

### Prerequisites

- Python 3.10+
- Git

### Optional (for enhanced scanning)

```bash
# TruffleHog - better secret detection
brew install trufflehog  # or: pip install trufflehog

# Semgrep - advanced static analysis
pip install semgrep

# pip-audit - Python dependency auditing
pip install pip-audit
```

### Install the scanner

```bash
git clone <this-repo>
cd remote-vibe-execution
pip install -e .
```

## Configuration

### CLI Options

```
remote-vibe-execution scan TARGET [OPTIONS]

TARGET: GitHub URL or local path

Options:
  --github-token TEXT     GitHub token (or set GITHUB_TOKEN env var)
  --ai-provider TEXT      AI provider: openai, anthropic, none
  --ai-key TEXT           AI API key (or set AI_API_KEY env var)
  --ai-model TEXT         AI model name
  -o, --output TEXT       Output directory (default: ./output)
  -f, --format TEXT       Output format: json, markdown (repeatable)
  --no-secrets            Disable secret scanning
  --no-static             Disable static analysis
  --no-deps               Disable dependency scanning
  --no-ai                 Disable AI triage
  --min-severity TEXT     Minimum severity: critical, high, medium, low, info
  --config TEXT           YAML config file
  --semgrep-rules TEXT    Additional Semgrep rule packs (repeatable)
```

### YAML Config

Copy `config.example.yaml` to `config.yaml` and customize:

```bash
cp config.example.yaml config.yaml
remote-vibe-execution scan https://github.com/owner/repo --config config.yaml
```

### Environment Variables

```bash
export GITHUB_TOKEN="ghp_..."        # GitHub API access
export AI_API_KEY="sk-..."           # OpenAI or Anthropic key
export AI_PROVIDER="openai"          # or "anthropic"
export AI_MODEL="gpt-4o"             # Model name
```

## Scanners

### 🔑 Secret Scanner
- **TruffleHog** integration (if installed) for high-fidelity secret detection
- **Built-in regex** patterns for 13+ secret types (AWS, GitHub, Stripe, JWT, etc.)
- False positive filtering for example/template files and placeholder values
- Automatic secret redaction in reports

### 🔍 Static Analyzer
- **Semgrep** integration with OWASP Top 10 and security audit rule packs
- **Built-in rules** for Python, JavaScript, Go, and generic patterns
- Detects: SQL injection, command injection, XSS, SSRF, deserialization, weak crypto, etc.
- Custom Semgrep rules support via `rules/` directory

### 📦 Dependency Scanner
- **OSV.dev** API for cross-ecosystem vulnerability lookup
- **npm audit** for Node.js projects
- **pip-audit** for Python projects
- Supports: npm, PyPI, Go, RubyGems, Maven, crates.io
- Parses: package.json, requirements.txt, Pipfile, pyproject.toml, go.mod, Gemfile, pom.xml, Cargo.toml

### 🤖 AI Triage Agent
- LLM-powered false positive detection
- Exploitability assessment with code context
- Severity adjustment based on data flow analysis
- Supports OpenAI (GPT-4o) and Anthropic (Claude)

## Output

### JSON Report
Full structured data including all findings, metadata, and AI assessments.

### Markdown Report
Human-readable report with severity breakdown, code snippets, remediation advice, and false positive tracking.

### Database
TinyDB-based scan history for tracking findings over time.

## Project Structure

```
remote-vibe-execution/
├── scanner/
│   ├── __init__.py
│   ├── cli.py              # CLI entrypoint
│   ├── config.py           # Configuration models
│   ├── models.py           # Data models (Finding, Report, etc.)
│   ├── github_client.py    # GitHub API + repo cloning
│   ├── preprocessor.py     # File filtering, chunking, dep extraction
│   ├── orchestrator.py     # Main pipeline orchestrator
│   ├── ai_agent.py         # AI triage + data flow analysis
│   ├── risk_engine.py      # Dedup, correlation, scoring
│   └── reporters.py        # JSON, Markdown, DB output
├── scanners/
│   ├── __init__.py         # Base scanner class
│   ├── secret_scanner.py   # TruffleHog + regex secrets
│   ├── static_analyzer.py  # Semgrep + built-in rules
│   └── dependency_scanner.py # OSV + npm/pip audit
├── rules/
│   └── custom_rules.yml    # Custom Semgrep rules
├── config.example.yaml
├── pyproject.toml
└── README.md
```

## Adding Custom Rules

### Semgrep Rules
Add `.yml` files to the `rules/` directory following [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/).

### Built-in Patterns
Add regex patterns to `scanners/static_analyzer.py` → `BUILTIN_RULES` dict.

### Secret Patterns
Add patterns to `scanners/secret_scanner.py` → `SECRET_PATTERNS` dict.

## License

MIT
