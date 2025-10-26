import json
import re
from typing import Any


def joern_literal(value: Any) -> str:
    """Convert a Python value to a Joern literal string.

    Mirrors the TypeScript implementation semantics used by the original client:
    - Strings are quoted with double quotes and escape \\, ", ', `, newlines, tabs, etc.
    - Numbers are emitted as-is when finite; NaN/±Inf become null.
    - Booleans are lowercased to true/false.
    - Other values are JSON-serialized and then treated like strings (escaped and quoted).
    """
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (int,)):
        return str(value)

    if isinstance(value, float):
        # NaN or Infinity -> null
        if value != value or value in (float("inf"), float("-inf")):
            return "null"
        return str(value)

    def _escape_string(s: str) -> str:
        s = s.replace("\\", "\\\\")
        s = s.replace('"', '\\"')
        s = s.replace("'", "\\'")
        s = s.replace("`", "\\`")
        s = s.replace("\n", "\\n")
        s = s.replace("\r", "\\r")
        s = s.replace("\t", "\\t")
        s = s.replace("\f", "\\f")
        return s

    if isinstance(value, str):
        return f'"{_escape_string(value)}"'

    # Fallback: JSON stringify then treat as string literal
    try:
        json_str = json.dumps(value)
    except (TypeError, ValueError):
        return '"{}"'
    return f'"{_escape_string(json_str)}"'


def strip_ansi(input_str: str) -> str:
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", input_str)