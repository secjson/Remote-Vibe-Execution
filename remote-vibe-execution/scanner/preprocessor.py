"""Pre-processing layer: file filtering, chunking, and dependency extraction."""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from scanner.config import ScanConfig
from scanner.models import DependencyInfo


@dataclass
class FileInfo:
    path: str
    relative_path: str
    extension: str
    size_kb: float
    language: str = ""


@dataclass
class CodeChunk:
    file_path: str
    relative_path: str
    start_line: int
    end_line: int
    content: str
    language: str = ""


def detect_language(ext: str) -> str:
    mapping = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".c": "c", ".cpp": "cpp", ".h": "c", ".rs": "rust",
        ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
        ".sh": "bash", ".bash": "bash", ".yml": "yaml", ".yaml": "yaml",
        ".json": "json", ".xml": "xml", ".tf": "terraform",
        ".hcl": "hcl", ".sql": "sql", ".html": "html",
        ".dockerfile": "dockerfile", ".env": "dotenv",
    }
    return mapping.get(ext.lower(), "unknown")


class FileFilter:
    """Filters files based on config rules."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def should_include(self, file_path: Path, repo_root: Path) -> bool:
        relative = str(file_path.relative_to(repo_root))

        # Check exclude patterns
        for pattern in self.config.exclude_patterns:
            if pattern.startswith("*"):
                if relative.endswith(pattern[1:]):
                    return False
            elif pattern in relative:
                return False

        # Check extension
        ext = file_path.suffix.lower()
        if ext and ext not in self.config.include_extensions:
            # Also check if filename matches (e.g., Dockerfile)
            if file_path.name.lower() not in ("dockerfile", "makefile", ".env"):
                return False

        # Check size
        try:
            size_kb = file_path.stat().st_size / 1024
            if size_kb > self.config.max_file_size_kb:
                return False
        except OSError:
            return False

        return True

    def collect_files(self, repo_root: str) -> list[FileInfo]:
        """Collect all relevant files from the repo."""
        root = Path(repo_root)
        files = []
        for fp in root.rglob("*"):
            if not fp.is_file():
                continue
            if not self.should_include(fp, root):
                continue
            ext = fp.suffix.lower()
            files.append(FileInfo(
                path=str(fp),
                relative_path=str(fp.relative_to(root)),
                extension=ext,
                size_kb=fp.stat().st_size / 1024,
                language=detect_language(ext),
            ))
        return files


class Chunker:
    """Splits source files into manageable chunks for analysis."""

    def __init__(self, config: ScanConfig):
        self.chunk_size = config.chunk_size_lines
        self.overlap = 20  # Lines of overlap between chunks

    def chunk_file(self, file_info: FileInfo) -> list[CodeChunk]:
        try:
            with open(file_info.path, "r", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        if len(lines) <= self.chunk_size:
            return [CodeChunk(
                file_path=file_info.path,
                relative_path=file_info.relative_path,
                start_line=1,
                end_line=len(lines),
                content="".join(lines),
                language=file_info.language,
            )]

        chunks = []
        start = 0
        while start < len(lines):
            end = min(start + self.chunk_size, len(lines))
            chunks.append(CodeChunk(
                file_path=file_info.path,
                relative_path=file_info.relative_path,
                start_line=start + 1,
                end_line=end,
                content="".join(lines[start:end]),
                language=file_info.language,
            ))
            start = end - self.overlap if end < len(lines) else end
        return chunks


class DependencyExtractor:
    """Extracts dependency information from manifest files."""

    def extract_all(self, repo_root: str) -> list[DependencyInfo]:
        root = Path(repo_root)
        deps = []
        deps.extend(self._parse_package_json(root))
        deps.extend(self._parse_requirements_txt(root))
        deps.extend(self._parse_pipfile(root))
        deps.extend(self._parse_pyproject_toml(root))
        deps.extend(self._parse_go_mod(root))
        deps.extend(self._parse_gemfile(root))
        deps.extend(self._parse_pom_xml(root))
        deps.extend(self._parse_cargo_toml(root))
        return deps

    def _parse_package_json(self, root: Path) -> list[DependencyInfo]:
        deps = []
        for pj in root.rglob("package.json"):
            if "node_modules" in str(pj):
                continue
            try:
                data = json.loads(pj.read_text())
                for name, ver in data.get("dependencies", {}).items():
                    deps.append(DependencyInfo(name=name, version=ver, ecosystem="npm", direct=True))
                for name, ver in data.get("devDependencies", {}).items():
                    deps.append(DependencyInfo(name=name, version=ver, ecosystem="npm", direct=True))
            except Exception:
                continue
        return deps

    def _parse_requirements_txt(self, root: Path) -> list[DependencyInfo]:
        deps = []
        for req in root.rglob("requirements*.txt"):
            try:
                for line in req.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.]+)?", line)
                    if match:
                        name = match.group(1)
                        ver = (match.group(2) or "").strip()
                        deps.append(DependencyInfo(name=name, version=ver, ecosystem="pypi", direct=True))
            except Exception:
                continue
        return deps

    def _parse_pipfile(self, root: Path) -> list[DependencyInfo]:
        deps = []
        pipfile = root / "Pipfile"
        if not pipfile.exists():
            return deps
        try:
            content = pipfile.read_text()
            in_packages = False
            for line in content.splitlines():
                if line.strip() == "[packages]":
                    in_packages = True
                    continue
                elif line.strip().startswith("["):
                    in_packages = False
                    continue
                if in_packages:
                    match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*"?([^"]*)"?', line.strip())
                    if match:
                        deps.append(DependencyInfo(
                            name=match.group(1), version=match.group(2),
                            ecosystem="pypi", direct=True
                        ))
        except Exception:
            pass
        return deps

    def _parse_pyproject_toml(self, root: Path) -> list[DependencyInfo]:
        deps = []
        pp = root / "pyproject.toml"
        if not pp.exists():
            return deps
        try:
            content = pp.read_text()
            # Simple regex parsing for dependencies list
            match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                for dep_str in re.findall(r'"([^"]+)"', match.group(1)):
                    parts = re.match(r'^([a-zA-Z0-9_.-]+)\s*(.*)', dep_str)
                    if parts:
                        deps.append(DependencyInfo(
                            name=parts.group(1), version=parts.group(2).strip(),
                            ecosystem="pypi", direct=True
                        ))
        except Exception:
            pass
        return deps

    def _parse_go_mod(self, root: Path) -> list[DependencyInfo]:
        deps = []
        gomod = root / "go.mod"
        if not gomod.exists():
            return deps
        try:
            in_require = False
            for line in gomod.read_text().splitlines():
                if line.strip().startswith("require ("):
                    in_require = True
                    continue
                elif line.strip() == ")":
                    in_require = False
                    continue
                if in_require:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        deps.append(DependencyInfo(
                            name=parts[0], version=parts[1],
                            ecosystem="go", direct=True
                        ))
        except Exception:
            pass
        return deps

    def _parse_gemfile(self, root: Path) -> list[DependencyInfo]:
        deps = []
        gemfile = root / "Gemfile"
        if not gemfile.exists():
            return deps
        try:
            for line in gemfile.read_text().splitlines():
                match = re.match(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", line)
                if match:
                    deps.append(DependencyInfo(
                        name=match.group(1), version=match.group(2) or "",
                        ecosystem="rubygems", direct=True
                    ))
        except Exception:
            pass
        return deps

    def _parse_pom_xml(self, root: Path) -> list[DependencyInfo]:
        deps = []
        for pom in root.rglob("pom.xml"):
            try:
                content = pom.read_text()
                for match in re.finditer(
                    r'<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?(?:<version>([^<]+)</version>)?.*?</dependency>',
                    content, re.DOTALL
                ):
                    deps.append(DependencyInfo(
                        name=f"{match.group(1)}:{match.group(2)}",
                        version=match.group(3) or "",
                        ecosystem="maven", direct=True
                    ))
            except Exception:
                continue
        return deps

    def _parse_cargo_toml(self, root: Path) -> list[DependencyInfo]:
        deps = []
        cargo = root / "Cargo.toml"
        if not cargo.exists():
            return deps
        try:
            in_deps = False
            for line in cargo.read_text().splitlines():
                if line.strip() == "[dependencies]":
                    in_deps = True
                    continue
                elif line.strip().startswith("["):
                    in_deps = False
                    continue
                if in_deps:
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"?([^"]*)"?', line.strip())
                    if match:
                        deps.append(DependencyInfo(
                            name=match.group(1), version=match.group(2),
                            ecosystem="crates.io", direct=True
                        ))
        except Exception:
            pass
        return deps


def preprocess(config: ScanConfig, repo_path: str) -> tuple[list[FileInfo], list[CodeChunk], list[DependencyInfo]]:
    """Run the full preprocessing pipeline. Returns (files, chunks, dependencies)."""
    file_filter = FileFilter(config)
    files = file_filter.collect_files(repo_path)

    chunker = Chunker(config)
    chunks = []
    for fi in files:
        chunks.extend(chunker.chunk_file(fi))

    dep_extractor = DependencyExtractor()
    deps = dep_extractor.extract_all(repo_path)

    return files, chunks, deps
