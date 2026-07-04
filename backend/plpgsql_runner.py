"""PL/pgSQL security scanner — regex-based rules for .sql files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple


class _Rule(NamedTuple):
    rule_id: str
    severity: str  # HIGH | MEDIUM | LOW
    description: str
    pattern: re.Pattern
    category: str
    cwe: str


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
_RULES: list[_Rule] = [
    _Rule(
        rule_id="PLPGSQL001",
        severity="HIGH",
        description="Dynamic SQL built with string concatenation — SQL injection risk.",
        pattern=re.compile(
            r"EXECUTE\s+.{0,120}(\|\||\bformat\s*\()",
            re.IGNORECASE | re.DOTALL,
        ),
        category="sast",
        cwe="CWE-89",
    ),
    _Rule(
        rule_id="PLPGSQL002",
        severity="HIGH",
        description=(
            "SECURITY DEFINER function without SET search_path — "
            "search_path hijack / privilege escalation risk."
        ),
        pattern=re.compile(
            r"SECURITY\s+DEFINER(?![\s\S]{0,300}SET\s+search_path)",
            re.IGNORECASE,
        ),
        category="sast",
        cwe="CWE-269",
    ),
    _Rule(
        rule_id="PLPGSQL003",
        severity="HIGH",
        description="Hardcoded password literal in PL/pgSQL.",
        pattern=re.compile(
            r"(?:password|passwd|pwd)\s*(?::=|=)\s*'[^']{3,}'",
            re.IGNORECASE,
        ),
        category="secrets",
        cwe="CWE-798",
    ),
    _Rule(
        rule_id="PLPGSQL004",
        severity="HIGH",
        description="GRANT ALL … TO PUBLIC — overly permissive privilege grant.",
        pattern=re.compile(
            r"GRANT\s+ALL\b.{0,80}\bTO\s+PUBLIC",
            re.IGNORECASE | re.DOTALL,
        ),
        category="sast",
        cwe="CWE-732",
    ),
    _Rule(
        rule_id="PLPGSQL005",
        severity="MEDIUM",
        description=(
            "pg_read_file / pg_write_file usage — "
            "direct filesystem access from database context."
        ),
        pattern=re.compile(
            r"\bpg_(read_file|write_file|read_binary_file|ls_dir)\b",
            re.IGNORECASE,
        ),
        category="sast",
        cwe="CWE-552",
    ),
    _Rule(
        rule_id="PLPGSQL006",
        severity="MEDIUM",
        description="COPY … FROM with dynamic/variable path — path traversal risk.",
        pattern=re.compile(
            r"COPY\b.{0,120}\bFROM\b.{0,80}(\$\d+|\|\||\bformat\b)",
            re.IGNORECASE | re.DOTALL,
        ),
        category="sast",
        cwe="CWE-22",
    ),
    _Rule(
        rule_id="PLPGSQL007",
        severity="MEDIUM",
        description=(
            "EXECUTE with unquoted variable — "
            "use quote_ident() / quote_literal() / format() with %I/%L."
        ),
        pattern=re.compile(
            r"EXECUTE\s+\$?\w+\s*;",
            re.IGNORECASE,
        ),
        category="sast",
        cwe="CWE-89",
    ),
    _Rule(
        rule_id="PLPGSQL008",
        severity="LOW",
        description="RAISE NOTICE leaks internal data — avoid in production code.",
        pattern=re.compile(
            r"RAISE\s+NOTICE\b.{0,200}(?:password|secret|token|key|credential)",
            re.IGNORECASE | re.DOTALL,
        ),
        category="sast",
        cwe="CWE-209",
    ),
    _Rule(
        rule_id="PLPGSQL009",
        severity="LOW",
        description="SUPERUSER role granted — review necessity.",
        pattern=re.compile(
            r"\bCREATE\s+(?:USER|ROLE)\b.{0,120}\bSUPERUSER\b",
            re.IGNORECASE | re.DOTALL,
        ),
        category="sast",
        cwe="CWE-269",
    ),
]

SQL_EXTENSIONS = {".sql", ".pgsql", ".plpgsql", ".psql"}


def _find_sql_files(repo_path: Path) -> list[Path]:
    skip = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv"}
    return [
        f
        for f in repo_path.rglob("*")
        if f.is_file()
        and f.suffix.lower() in SQL_EXTENSIONS
        and not any(part in skip for part in f.parts)
    ]


def _line_of_match(text: str, match_start: int) -> int:
    return text[:match_start].count("\n") + 1


def _snippet(text: str, match_start: int, match_end: int, limit: int = 200) -> str:
    # expand to line boundaries, then truncate
    start = text.rfind("\n", 0, match_start)
    start = 0 if start == -1 else start + 1
    end = text.find("\n", match_end)
    end = len(text) if end == -1 else end
    return text[start:end].strip()[:limit]


def run_plpgsql_scan(repo_path: Path) -> list[dict]:
    """Scan all SQL files in *repo_path* and return raw findings."""
    findings: list[dict] = []

    for sql_file in _find_sql_files(repo_path):
        try:
            text = sql_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(sql_file.relative_to(repo_path))

        for rule in _RULES:
            for m in rule.pattern.finditer(text):
                findings.append(
                    {
                        "rule_id": rule.rule_id,
                        "severity": rule.severity,
                        "description": rule.description,
                        "file": rel_path,
                        "line": _line_of_match(text, m.start()),
                        "snippet": _snippet(text, m.start(), m.end()),
                        "category": rule.category,
                        "cwe": rule.cwe,
                    }
                )

    return findings
