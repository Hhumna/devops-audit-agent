"""Inspection tools."""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import time
from pathlib import Path

from audit_agent.redact import redact_text

MAX_OUTPUT_CHARS = 12_000
MAX_FILE_BYTES = 300_000
MAX_LISTED_FILES = 600
MAX_READ_LINES = 400
MAX_MATCHES = 40
MAX_LINE_CHARS = 300
SEARCH_TIME_BUDGET_S = 15
GIT_TIMEOUT_S = 30
SKIP_DIRS = {".git"}
TOOL_NAMES = ("list_files", "read_file", "search_code", "git_log")


class ToolError(Exception):
    """Invalid tool input. The message is shown to the LLM so it can retry."""


class RepoTools:
    """Read-only inspection tools bound to one cloned repository."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self._tracked: list[str] | None = None

    # ---- helpers ----
    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(self.root), "-c", f"core.hooksPath={os.devnull}", *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=GIT_TIMEOUT_S, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            check=False,
        )

    def _tracked_files(self) -> list[str]:
        if self._tracked is None:
            files: list[str] = []
            try:
                res = self._git("ls-files", "-z")
                if res.returncode == 0:
                    files = [f for f in res.stdout.split("\0") if f]
            except (OSError, subprocess.TimeoutExpired):
                pass
            if not files:
                for dirpath, dirnames, filenames in os.walk(self.root):
                    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                    for name in filenames:
                        rel = Path(dirpath, name).relative_to(self.root)
                        files.append(rel.as_posix())
            self._tracked = sorted(files)
        return self._tracked

    def _resolve(self, rel: str) -> Path:
        if not rel or "\0" in rel:
            raise ToolError("a valid relative path is required")
        target = (self.root / rel).resolve()
        try:
            parts = target.relative_to(self.root).parts
        except ValueError:
            raise ToolError("path escapes the repository; access denied") from None
        if parts and parts[0] == ".git":
            raise ToolError("access to .git is not allowed")
        return target

    @staticmethod
    def _is_binary(path: Path) -> bool:
        with path.open("rb") as fh:
            return b"\0" in fh.read(4096)

    # ---- tools ----
    def list_files(self, directory: str = "") -> str:
        prefix = (directory or "").strip().replace("\\", "/").strip("/")
        files = self._tracked_files()
        if prefix:
            files = [f for f in files if f.startswith(prefix + "/")]
        total = len(files)
        where = f" under '{prefix}'" if prefix else ""
        if total == 0:
            return f"No tracked files found{where}."
        shown = files[:MAX_LISTED_FILES]
        lines = [f"{total} tracked file(s){where}:", *shown]
        if total > len(shown):
            lines.append(
                f"... {total - len(shown)} more not shown; call list_files with a subdirectory."
            )
        return "\n".join(lines)

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        target = self._resolve(path)
        if not target.exists():
            raise ToolError(f"file not found: {path}")
        if not target.is_file():
            raise ToolError(f"not a file: {path}")
        size = target.stat().st_size
        if self._is_binary(target):
            return f"{path}: binary file ({size} bytes), content not shown."
        with target.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES)
        lines = redact_text(raw.decode("utf-8", errors="replace")).splitlines()
        if not lines:
            return f"{path}: empty file."
        start = max(1, int(start_line))
        if start > len(lines):
            return f"{path}: file has only {len(lines)} line(s)."
        end = int(end_line) if end_line else start + MAX_READ_LINES - 1
        end = min(end, start + MAX_READ_LINES - 1, len(lines))
        body = "\n".join(f"{i}: {lines[i - 1][:MAX_LINE_CHARS * 2]}" for i in range(start, end + 1))
        note = "; file truncated at 300 KB" if size > MAX_FILE_BYTES else ""
        return f"{path} (lines {start}-{end} of {len(lines)}{note})\n{body}"

    def search_code(self, pattern: str, path_glob: str | None = None,
                    case_sensitive: bool = False) -> str:
        if not pattern:
            raise ToolError("pattern is required")
        try:
            rx = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            raise ToolError(f"invalid regex: {exc}") from None
        deadline = time.monotonic() + SEARCH_TIME_BUDGET_S
        matches: list[str] = []
        truncated = timed_out = False
        for rel in self._tracked_files():
            if path_glob and not (
                fnmatch.fnmatch(rel, path_glob) or fnmatch.fnmatch(Path(rel).name, path_glob)
            ):
                continue
            if time.monotonic() > deadline:
                timed_out = True
                break
            try:
                target = self._resolve(rel)
                if (not target.is_file() or target.stat().st_size > MAX_FILE_BYTES
                        or self._is_binary(target)):
                    continue
                content = target.read_text(encoding="utf-8", errors="replace")
            except (ToolError, OSError):
                continue
            for number, line in enumerate(content.splitlines(), 1):
                if rx.search(line[:2000]):
                    snippet = redact_text(line.strip()[:MAX_LINE_CHARS])
                    matches.append(f"{rel}:{number}: {snippet}")
                    if len(matches) >= MAX_MATCHES:
                        truncated = True
                        break
            if truncated:
                break
        if not matches:
            return f"No matches for /{pattern}/" + (" (search timed out)" if timed_out else ".")
        out = [f"{len(matches)} match(es) for /{pattern}/:", *matches]
        if truncated:
            out.append(f"... stopped at {MAX_MATCHES} matches; narrow the pattern or use path_glob.")
        if timed_out:
            out.append("... search time budget exceeded; results are partial.")
        return "\n".join(out)

    def git_log(self, max_count: int = 30, path: str | None = None) -> str:
        count = max(1, min(int(max_count), 100))
        args = ["log", f"--max-count={count}", "--date=short", "--pretty=format:%h %ad %an: %s"]
        if path:
            clean = path.replace("\\", "/")
            if clean.startswith("-"):
                raise ToolError("invalid path")
            args += ["--", clean]
        res = self._git(*args)
        if res.returncode != 0:
            raise ToolError("git log failed: " + redact_text(res.stderr.strip())[:300])
        out = res.stdout.strip()
        if not out:
            return "No commits found."
        shallow = self._git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
        note = "\n(note: shallow clone, older history is not visible)" if shallow else ""
        return redact_text(out) + note


TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "list_files",
        "description": "List git-tracked files in the repository (optionally under one directory).",
        "parameters": {"type": "object", "properties": {
            "directory": {"type": "string", "description": "Optional subdirectory, e.g. '.github/workflows'."},
        }, "required": []}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a file. Output lines are prefixed with line numbers. Secrets are masked.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Relative path from the repo root."},
            "start_line": {"type": "integer", "description": "First line to read (default 1)."},
            "end_line": {"type": "integer", "description": "Last line to read (max 400 lines per call)."},
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search_code",
        "description": "Regex search across tracked text files. Returns file:line: text. Secrets are masked.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string", "description": "Python regular expression."},
            "path_glob": {"type": "string", "description": "Optional filename glob, e.g. '*.yml'."},
            "case_sensitive": {"type": "boolean", "description": "Default false."},
        }, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "git_log",
        "description": "Show recent commits (hash, date, author, subject), optionally for one path.",
        "parameters": {"type": "object", "properties": {
            "max_count": {"type": "integer", "description": "Number of commits (default 30, max 100)."},
            "path": {"type": "string", "description": "Optional path to filter history."},
        }, "required": []}}},
]


def execute_tool(tools: RepoTools, name: str, arguments: dict) -> str:
    """Run one tool call. Never raises: errors are returned as text for the LLM."""
    if name not in TOOL_NAMES:
        return f"ERROR: unknown tool '{name}'. Available tools: {', '.join(TOOL_NAMES)}"
    if not isinstance(arguments, dict):
        return "ERROR: tool arguments must be a JSON object."
    try:
        result = str(getattr(tools, name)(**arguments))
    except TypeError as exc:
        return f"ERROR: invalid arguments for {name}: {exc}"
    except ToolError as exc:
        return f"ERROR: {exc}"
    except subprocess.TimeoutExpired:
        return f"ERROR: {name} timed out."
    except Exception as exc:  # noqa: BLE001 - tool failures must not crash the agent
        return f"ERROR: {name} failed ({type(exc).__name__})."
    if len(result) > MAX_OUTPUT_CHARS:
        result = result[:MAX_OUTPUT_CHARS] + "\n... [output truncated]"
    return result