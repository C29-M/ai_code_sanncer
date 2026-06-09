"""Utility modules for prompt_guard."""
from prompt_guard.utils.text_utils import (
    normalize_text,
    split_into_lines,
    truncate_match,
    find_line_number,
    keyword_density,
)
from prompt_guard.utils.encoding_detector import (
    decode_and_check,
    has_suspicious_encoding,
    detect_base64,
    detect_url_encoding,
)

__all__ = [
    "normalize_text",
    "split_into_lines",
    "truncate_match",
    "find_line_number",
    "keyword_density",
    "decode_and_check",
    "has_suspicious_encoding",
    "detect_base64",
    "detect_url_encoding",
]
