"""
prompt_loader.py

Handles loading prompts from various file formats (.txt, .md, .json, .yaml).
"""

import json
import os
from typing import List

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


class InvalidPromptError(Exception):
    """Raised when a prompt fails validation."""


MAX_PROMPT_SIZE = 50000  # characters


def get_supported_extensions() -> List[str]:
    """Return list of supported file extensions for prompt loading."""
    extensions = [".txt", ".md", ".json"]
    if _YAML_AVAILABLE:
        extensions += [".yaml", ".yml"]
    return extensions


def load_txt(file_path: str) -> str:
    """Load a plain text prompt file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="latin-1", errors="replace") as f:
            return f.read()


def load_md(file_path: str) -> str:
    """Load a Markdown prompt file, returning raw text content."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="latin-1", errors="replace") as f:
            return f.read()


def load_json(file_path: str) -> str:
    """
    Load a prompt from a JSON file.

    Checks for the following keys (in order of precedence):
      - "prompt"
      - "system_prompt"
      - "messages" (list of message dicts; extracts "content" from each)

    Falls back to dumping the entire JSON if none of those keys are found.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="latin-1", errors="replace") as f:
            raw = f.read()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in file '{file_path}': {exc}") from exc

    if not isinstance(data, dict):
        # If the top-level is a list or scalar, just stringify it
        return json.dumps(data, ensure_ascii=False)

    if "prompt" in data:
        value = data["prompt"]
        return (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )

    if "system_prompt" in data:
        value = data["system_prompt"]
        return (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )

    if "messages" in data:
        messages = data["messages"]
        if isinstance(messages, list):
            parts = []
            for msg in messages:
                if isinstance(msg, dict):
                    role = msg.get("role", "")
                    content = msg.get("content", "")
                    if role:
                        parts.append(f"{role}: {content}")
                    else:
                        parts.append(str(content))
                else:
                    parts.append(str(msg))
            return "\n".join(parts)

    # Fallback: return the full JSON as a string
    return json.dumps(data, ensure_ascii=False, indent=2)


def load_yaml(file_path: str) -> str:
    """
    Load a prompt from a YAML file.

    Checks for the following keys (in order of precedence):
      - "prompt"
      - "system_prompt"
      - "messages" (list of message dicts; extracts role/content)

    Falls back to dumping the entire YAML document if none of those keys are found.

    Raises ImportError if PyYAML is not installed.
    """
    if not _YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required to load YAML prompt files. "
            "Install it with: pip install pyyaml"
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="latin-1", errors="replace") as f:
            raw = f.read()

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in file '{file_path}': {exc}") from exc

    if data is None:
        return ""

    if not isinstance(data, dict):
        return str(data)

    if "prompt" in data:
        value = data["prompt"]
        return value if isinstance(value, str) else yaml.dump(value, allow_unicode=True)

    if "system_prompt" in data:
        value = data["system_prompt"]
        return value if isinstance(value, str) else yaml.dump(value, allow_unicode=True)

    if "messages" in data:
        messages = data["messages"]
        if isinstance(messages, list):
            parts = []
            for msg in messages:
                if isinstance(msg, dict):
                    role = msg.get("role", "")
                    content = msg.get("content", "")
                    if role:
                        parts.append(f"{role}: {content}")
                    else:
                        parts.append(str(content))
                else:
                    parts.append(str(msg))
            return "\n".join(parts)

    # Fallback: dump the full YAML document as a string
    return yaml.dump(data, allow_unicode=True)


def load_prompt_file(file_path: str) -> str:
    """
    Dispatch to the correct loader based on file extension.

    Supported extensions: .txt, .md, .json, .yaml, .yml

    Returns the validated prompt text.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: if the extension is unsupported or the file content is malformed.
        InvalidPromptError: if the loaded prompt fails validation.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Prompt file not found: '{file_path}'")

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    loaders = {
        ".txt": load_txt,
        ".md": load_md,
        ".json": load_json,
        ".yaml": load_yaml,
        ".yml": load_yaml,
    }

    if ext not in loaders:
        supported = ", ".join(get_supported_extensions())
        raise ValueError(
            f"Unsupported file extension '{ext}'. Supported formats: {supported}"
        )

    text = loaders[ext](file_path)
    return validate_prompt(text)


def validate_prompt(text: str) -> str:
    """
    Validate prompt text.

    Raises:
        InvalidPromptError: if the text is empty (after stripping) or exceeds
                            MAX_PROMPT_SIZE characters.

    Returns the original (un-stripped) text on success.
    """
    if not isinstance(text, str):
        raise InvalidPromptError(f"Prompt must be a string, got {type(text).__name__}.")

    if not text.strip():
        raise InvalidPromptError("Prompt is empty or contains only whitespace.")

    if len(text) > MAX_PROMPT_SIZE:
        raise InvalidPromptError(
            f"Prompt exceeds maximum allowed size of {MAX_PROMPT_SIZE} characters "
            f"(got {len(text)} characters)."
        )

    return text
