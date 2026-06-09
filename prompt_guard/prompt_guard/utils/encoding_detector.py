"""Encoding and obfuscation detection utilities for prompt_guard."""
import re
import base64
import urllib.parse
import logging
from typing import List

logger = logging.getLogger(__name__)


def detect_base64(text: str) -> List[str]:
    pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    matches = pattern.findall(text)
    decoded = []
    for m in matches:
        try:
            dec = base64.b64decode(m).decode("utf-8", errors="replace")
            if any(c.isalpha() for c in dec):
                decoded.append(dec)
        except Exception:
            pass
    return decoded


def detect_url_encoding(text: str) -> List[str]:
    pattern = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
    matches = pattern.findall(text)
    decoded = []
    for m in matches:
        try:
            decoded.append(urllib.parse.unquote(m))
        except Exception:
            pass
    return decoded


def detect_unicode_escapes(text: str) -> List[str]:
    pattern = re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}")
    matches = pattern.findall(text)
    decoded = []
    for m in matches:
        try:
            dec = m.encode("utf-8").decode("unicode_escape")
            decoded.append(dec)
        except Exception:
            pass
    return decoded


def decode_and_check(text: str) -> str:
    b64 = detect_base64(text)
    url = detect_url_encoding(text)
    unicode_esc = detect_unicode_escapes(text)
    extra = " ".join(b64 + url + unicode_esc)
    return (text + " " + extra).strip() if extra else text


def has_suspicious_encoding(text: str) -> bool:
    if detect_base64(text):
        return True
    if detect_url_encoding(text):
        return True
    if detect_unicode_escapes(text):
        return True
    return False
