"""Safe repo cloning."""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager

_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


class RepoError(Exception):
    """Raised when the repository URL is invalid or cannot be cloned."""


def parse_github_url(url: str) -> tuple[str, str]:
    match = _URL_RE.match((url or "").strip())
    if not match or match.group(1) in {".", ".."} or match.group(2) in {".", ".."}:
        raise RepoError(
            f"invalid repository URL: {url!r}. Expected https://github.com/<owner>/<repo>"
        )
    return match.group(1), match.group(2)


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove_tree(path: str) -> None:
    if not os.path.exists(path):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_force_remove)
    else:
        shutil.rmtree(path, onerror=_force_remove)


def clone_repo(url: str, depth: int = 200, timeout: int = 180) -> str:
    """Shallow-clone a public GitHub repo into a temp dir and return its path.

    Hooks and symlinks are disabled; no code from the repo is executed.
    """
    owner, name = parse_github_url(url)
    workdir = tempfile.mkdtemp(prefix="audit_")
    dest = os.path.join(workdir, name)
    cmd = [
        "git", "-c", f"core.hooksPath={os.devnull}", "-c", "core.symlinks=false",
        "clone", "--depth", str(depth), "--no-tags", "--single-branch", "--quiet",
        f"https://github.com/{owner}/{name}.git", dest,
    ]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, check=False,
        )
    except FileNotFoundError:
        remove_tree(workdir)
        raise RepoError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        remove_tree(workdir)
        raise RepoError(f"cloning timed out after {timeout}s") from None
    if res.returncode != 0:
        remove_tree(workdir)
        lines = res.stderr.strip().splitlines()
        err = lines[-1] if lines else "unknown error"
        raise RepoError(
            f"could not clone {owner}/{name} (missing, private, or network issue): {err}"
        )
    return dest


@contextmanager
def cloned_repo(url: str, depth: int = 200, timeout: int = 180):
    """Clone, yield the path, and always delete the temp dir afterwards."""
    path = clone_repo(url, depth=depth, timeout=timeout)
    try:
        yield path
    finally:
        remove_tree(os.path.dirname(path))