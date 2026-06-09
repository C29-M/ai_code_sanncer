"""
Language detection for routing Semgrep to the right rule packs.

Scans a cloned repository's file tree, counts source-file extensions, and
returns the appropriate /opt/semgrep-rules/<language> paths to use as
--config arguments. Repos with multiple major languages get multiple
paths. Repos with no recognised source files fall back to the full pack.
"""

from __future__ import annotations

from pathlib import Path

# File extension -> Semgrep language directory name under /opt/semgrep-rules/
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".scala": "scala",
    ".kt": "kotlin",
    ".rs": "rust",
    ".swift": "swift",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
}

# Folders to ignore during the file walk (vendored / generated / VCS).
SKIP_DIRS: set[str] = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "vendor",
    "dist",
    "build",
    "out",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "target",  # Java / Rust
    "bin",
    "obj",  # .NET
    ".gradle",
    ".idea",
    ".vscode",
}

RULES_ROOT = "/opt/semgrep-rules"
DOMINANCE_THRESHOLD_PCT = 15  # languages contributing < 15% of files are ignored
MIN_LANGUAGE_FILES = 2  # need at least 2 files of a language to count it


def detect_languages(repo_path: Path) -> dict[str, int]:
    """Walk the repo and return {language_name: file_count}."""
    counts: dict[str, int] = {}
    if not repo_path.is_dir():
        return counts

    for f in repo_path.rglob("*"):
        if not f.is_file():
            continue
        # Skip files inside vendored / generated / VCS directories
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        # Skip minified bundles
        if f.name.endswith(".min.js") or f.name.endswith(".min.css"):
            continue
        lang = EXTENSION_TO_LANGUAGE.get(f.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    return counts


def select_rule_paths(repo_path: Path) -> list[str]:
    """
    Decide which Semgrep rule paths to use for a cloned repo.

    Returns a list of /opt/semgrep-rules/<language> paths. If no major language
    is detected, falls back to the full rule pack so coverage is never zero.
    """
    counts = detect_languages(repo_path)
    if not counts:
        return [RULES_ROOT]

    total = sum(counts.values())
    selected: list[str] = []

    # Sort by file count descending so the dominant language goes first
    for lang, count in sorted(counts.items(), key=lambda x: -x[1]):
        pct = (count / total) * 100
        if count >= MIN_LANGUAGE_FILES and pct >= DOMINANCE_THRESHOLD_PCT:
            selected.append(f"{RULES_ROOT}/{lang}")

    return selected if selected else [RULES_ROOT]


def language_summary(repo_path: Path) -> str:
    """Human-readable summary of detected languages for logging."""
    counts = detect_languages(repo_path)
    if not counts:
        return "no recognised source files"
    total = sum(counts.values())
    parts = [
        f"{lang} ({count}, {round((count / total) * 100)}%)"
        for lang, count in sorted(counts.items(), key=lambda x: -x[1])
    ]
    return ", ".join(parts)
