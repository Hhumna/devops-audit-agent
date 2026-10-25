"""Report builder and validation."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from audit_agent.redact import redact_text

CATEGORY_PREFIX = {
    "repository_hygiene": "HYG",
    "dependency_management": "DEP",
    "code_quality": "QUAL",
    "testing": "TEST",
    "ci_cd": "CI",
    "security": "SEC",
    "configuration": "CFG",
    "collaboration": "COL",
    "build_release": "BLD",
}
CATEGORIES = tuple(CATEGORY_PREFIX)
SEVERITIES = ("critical", "high", "medium", "low")
FIELDS = (
    "rule_id", "category", "severity", "file", "line",
    "description", "evidence", "recommendation",
)
MIN_EVIDENCE_CHARS = 20
SIMILARITY_LIMIT = 0.6
_WORD = re.compile(r"[a-z0-9]+")


def _is_null(value) -> bool:
    return value is None or (isinstance(value, str) and value.strip().lower() in {"", "null", "none", "n/a"})


def _clean_text(value, limit: int) -> str:
    return redact_text(" ".join(str(value).split()))[:limit]


class ViolationCollector:
    """Validates, redacts, de-duplicates and numbers violations as the agent records them."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.violations: list[dict] = []
        self._counters: dict[str, int] = {}

    def _check_file(self, raw):
        if _is_null(raw):
            return None, None
        rel = str(raw).strip().replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        target = (self.root / rel).resolve()
        try:
            parts = target.relative_to(self.root).parts
        except ValueError:
            return None, "file path must stay inside the repository"
        if not parts or parts[0] == ".git" or not target.is_file():
            return None, (
                f"file not found in repository: {rel!r}. Check the exact path with list_files, "
                "or omit file if the problem is a missing file or repository-wide."
            )
        return "/".join(parts), None

    def _check_line(self, rel: str, raw):
        if _is_null(raw):
            return None, None
        try:
            number = int(raw)
        except (TypeError, ValueError):
            return None, "line must be an integer, or omitted"
        if number < 1:
            return None, "line must be 1 or greater"
        try:
            text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return number, None
        total = len(text.splitlines())
        if number > total:
            return None, f"line {number} is beyond the end of {rel} ({total} lines)"
        return number, None

    def _duplicate_of(self, category, file, line, description):
        words = set(_WORD.findall(description.lower()))
        for old in self.violations:
            if old["category"] != category or old["file"] != file:
                continue
            if line is not None and old["line"] == line:
                return old["rule_id"]
            old_words = set(_WORD.findall(old["description"].lower()))
            union = words | old_words
            if union and len(words & old_words) / len(union) >= SIMILARITY_LIMIT:
                return old["rule_id"]
        return None

    def add(self, args: dict) -> tuple[bool, str]:
        """Try to record a violation. Returns (ok, message shown to the LLM)."""
        category = str(args.get("category") or "").strip().lower()
        if category not in CATEGORY_PREFIX:
            return False, f"invalid category {category!r}; use one of: {', '.join(CATEGORIES)}"
        severity = str(args.get("severity") or "").strip().lower()
        if severity not in SEVERITIES:
            return False, f"invalid severity {severity!r}; use one of: {', '.join(SEVERITIES)}"
        description = _clean_text(args.get("description") or "", 300)
        evidence = _clean_text(args.get("evidence") or "", 800)
        recommendation = _clean_text(args.get("recommendation") or "", 600)
        if not description or not recommendation:
            return False, "description and recommendation are required"
        if len(evidence) < MIN_EVIDENCE_CHARS:
            return False, (
                "evidence must state what you actually observed (which file, what it contains "
                "or lacks)"
            )
        file, error = self._check_file(args.get("file"))
        if error:
            return False, error
        line = None
        if file is not None:
            line, error = self._check_line(file, args.get("line"))
            if error:
                return False, error
        duplicate = self._duplicate_of(category, file, line, description)
        if duplicate:
            return False, f"duplicate of {duplicate}; do not record the same problem twice"
        number = self._counters.get(category, 0) + 1
        self._counters[category] = number
        rule_id = f"{CATEGORY_PREFIX[category]}-{number:03d}"
        self.violations.append({
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "file": file,
            "line": line,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        })
        return True, f"recorded {rule_id}"


def build_report(repo_url: str, violations: list[dict]) -> dict:
    return {"repository": repo_url, "violations": list(violations)}


def validate_report(report: dict) -> None:
    """Raise ValueError if the report does not match the required output contract."""
    if not isinstance(report, dict) or not isinstance(report.get("repository"), str):
        raise TypeError("report must contain a string 'repository'")
    items = report.get("violations")
    if not isinstance(items, list):
        raise TypeError("report must contain a 'violations' list")
    for index, item in enumerate(items):
        if not isinstance(item, dict) or any(key not in item for key in FIELDS):
            raise ValueError(f"violation {index} is missing required fields")
        if item["severity"] not in SEVERITIES:
            raise ValueError(f"violation {index} has an invalid severity")
        if item["file"] is not None and not isinstance(item["file"], str):
            raise ValueError(f"violation {index}: file must be a string or null")
        if item["line"] is not None and not isinstance(item["line"], int):
            raise ValueError(f"violation {index}: line must be an integer or null")
        for key in ("rule_id", "category", "description", "evidence", "recommendation"):
            if not isinstance(item[key], str) or not item[key]:
                raise ValueError(f"violation {index}: {key} must be a non-empty string")


def write_report(path: str, report: dict) -> None:
    """Validate and write the report atomically as UTF-8 JSON."""
    validate_report(report)
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise