"""Text processing utilities for prompt_guard."""
import re
import unicodedata
from typing import List, Tuple


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()


def split_into_lines(text: str) -> List[Tuple[int, str]]:
    lines = text.split("\n")
    return [(i + 1, line) for i, line in enumerate(lines)]


def get_context_window(text: str, match_start: int, match_end: int, window: int = 50) -> str:
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    ctx = text[start:end]
    if start > 0:
        ctx = "..." + ctx
    if end < len(text):
        ctx = ctx + "..."
    return ctx


def truncate_match(text: str, max_len: int = 100) -> str:
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def count_words(text: str) -> int:
    return len(text.split())


def is_likely_code(text: str) -> bool:
    code_patterns = [
        r"def\s+\w+\s*\(",
        r"function\s+\w+\s*\(",
        r"class\s+\w+[:\s{]",
        r"import\s+\w+",
        r"#include\s*<",
        r"\bif\s*\(.+\)\s*\{",
        r"for\s*\(.+;.+;",
        r"\bvar\s+\w+\s*=",
        r"\bconst\s+\w+\s*=",
        r"\blet\s+\w+\s*=",
    ]
    matches = sum(1 for p in code_patterns if re.search(p, text))
    return matches >= 2


def find_line_number(text: str, char_pos: int) -> int:
    return text[:char_pos].count("\n") + 1


def keyword_density(text: str, keywords: List[str]) -> float:
    if not text:
        return 0.0
    word_count = count_words(text)
    if word_count == 0:
        return 0.0
    text_lower = text.lower()
    matches = sum(1 for kw in keywords if kw.lower() in text_lower)
    return matches / word_count
