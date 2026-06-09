"""
VulBERTa label mapping and vuln_type classification.

mrm8488/codebert-base-finetuned-detect-insecure-code is a binary classifier:
  LABEL_0 = secure code
  LABEL_1 = insecure code

Since it doesn't output a vuln type, we derive vuln_type from the snippet +
description using keyword heuristics. The model's score for LABEL_1 becomes
classifier_confidence.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Vuln type enum (must match week 5 spec exactly)
# ---------------------------------------------------------------------------
VULN_TYPES = {"sqli", "xss", "rce", "secrets", "iac", "crypto", "other"}

# ---------------------------------------------------------------------------
# Keyword → vuln_type mapping (ordered, first match wins)
# ---------------------------------------------------------------------------
_VULN_KEYWORDS: list[tuple[str, list[str]]] = [
    ("sqli", [
        "sql", "query", "select ", "insert ", "update ", "delete from",
        "execute(", "cursor.execute", "raw query", "orm bypass",
        "nosql", "mongo injection",
    ]),
    ("xss", [
        "innerhtml", "document.write", "xss", "cross-site scripting",
        "dangerouslysetinnerhtml", "eval(", "settimeout(", "setinterval(",
        "outerhtml", "insertadjacenthtml",
    ]),
    ("rce", [
        "eval(", "exec(", "subprocess", "os.system", "popen",
        "remote code", "code execution", "shell injection",
        "command injection", "spawn(", "execsync",
    ]),
    ("secrets", [
        "password", "passwd", "secret", "api_key", "apikey", "api key",
        "token", "credential", "private key", "hardcoded", "aws_secret",
        "auth", "bearer", "access_key",
    ]),
    ("crypto", [
        "md5", "sha1", "des ", "3des", "rc4", "ecb mode", "weak cipher",
        "insecure hash", "random()", "math.random", "weak random",
        "no ssl", "no tls", "verify=false", "ssl verify",
    ]),
    ("iac", [
        "terraform", "cloudformation", "kubernetes", "k8s", "dockerfile",
        "privileged", "host network", "root container", "insecure port",
        "public bucket", "open security group", "0.0.0.0",
    ]),
]


def classify_vuln_type(snippet: str, description: str) -> str:
    """
    Derive vuln_type from snippet + description text via keyword matching.
    Returns one of: sqli | xss | rce | secrets | iac | crypto | other
    """
    text = (snippet + " " + description).lower()
    for vuln_type, keywords in _VULN_KEYWORDS:
        for kw in keywords:
            if kw in text:
                return vuln_type
    return "other"


def vulberta_confidence(label: str, score: float) -> float:
    """
    Convert VulBERTa binary output to a confidence score for 'insecure'.

    LABEL_1 = insecure → confidence is the raw score
    LABEL_0 = secure   → confidence is 1 - score (model thinks it's safe)
    """
    if label == "LABEL_1":
        return round(score, 4)
    return round(1.0 - score, 4)
