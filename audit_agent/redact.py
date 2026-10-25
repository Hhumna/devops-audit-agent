"""Secret redaction."""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)

_TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]

_ASSIGN = re.compile(
    r"""(?i)((?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key"""
    r"""|access[_-]?key|auth[_-]?token)[\w\-]*["']?\s*[:=]\s*)(["']?)([^\s"'#,;]{6,})(\2)"""
)

# Values that are clearly placeholders or references, not real secrets.
_SAFE_HINTS = (
    "your", "example", "changeme", "placeholder", "environ", "getenv",
    "secrets.", "<", ">", "xxxx", "dummy",
)


def _assign_sub(match: re.Match) -> str:
    prefix, quote, value, _ = match.groups()
    low = value.lower()
    if value.startswith(("$", "{", "%")) or any(h in low for h in _SAFE_HINTS):
        return match.group(0)
    return f"{prefix}{quote}{REDACTED}{quote}"


def redact_text(text: str) -> str:
    """Mask secrets in text. Newline count is preserved so line numbers stay valid."""
    if not text:
        return text
    text = _PRIVATE_KEY.sub(lambda m: REDACTED + "\n" * m.group(0).count("\n"), text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return _ASSIGN.sub(_assign_sub, text)