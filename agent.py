"""CLI entry point."""
from __future__ import annotations

import argparse
import json
import os
import sys

from dotenv import load_dotenv

from audit_agent.llm import LLMClient, LLMError
from audit_agent.loop import run_audit
from audit_agent.redact import redact_text
from audit_agent.repo import RepoError, cloned_repo, parse_github_url
from audit_agent.report import build_report, write_report
from tools import RepoTools

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_FATAL = 2
EXIT_PARTIAL = 3
DEFAULT_MAX_STEPS = 25


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="LLM-driven agent that audits a public GitHub repository for DevOps issues."
    )
    parser.add_argument("--repo", required=True, help="Public GitHub repository URL")
    parser.add_argument("--output", required=True, help="Path of the JSON report to write")
    parser.add_argument("--trace", help="Optional path to save the tool-call trace as JSON")
    return parser.parse_args(argv)


def _max_steps() -> int:
    try:
        value = int(os.getenv("MAX_AGENT_STEPS", "") or DEFAULT_MAX_STEPS)
    except ValueError:
        value = DEFAULT_MAX_STEPS
    return max(5, min(value, 60))


def _fail(message: str, code: int) -> int:
    print(f"error: {redact_text(message)}", file=sys.stderr)
    return code


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    load_dotenv()
    args = parse_args(argv)
    try:
        owner, name = parse_github_url(args.repo)
        repo_url = f"https://github.com/{owner}/{name}"
        llm = LLMClient()
        max_steps = _max_steps()
        print(f"Auditing {repo_url} (max {max_steps} steps)...", file=sys.stderr, flush=True)
        with cloned_repo(repo_url) as path:
            result = run_audit(repo_url, RepoTools(path), llm, max_steps=max_steps)
        if not result.completed and result.steps <= 1:
            raise LLMError(result.stop_reason)
        write_report(args.output, build_report(repo_url, result.violations))
        if args.trace:
            with open(args.trace, "w", encoding="utf-8") as fh:
                json.dump(result.trace, fh, indent=2, ensure_ascii=False)
        print(
            f"Done: {len(result.violations)} violation(s) in {result.steps} step(s) "
            f"[{result.stop_reason}]. Report: {args.output}",
            file=sys.stderr,
        )
        if result.summary:
            print(f"Summary: {result.summary}", file=sys.stderr)
        if not result.completed:
            print(f"warning: inspection incomplete: {result.stop_reason}", file=sys.stderr)
            return EXIT_PARTIAL
        return EXIT_OK
    except (RepoError, LLMError) as exc:
        return _fail(str(exc), EXIT_FATAL)
    except KeyboardInterrupt:
        return _fail("interrupted", 130)
    except Exception as exc:  # noqa: BLE001 - last-resort handler, must exit cleanly
        return _fail(f"unexpected failure ({type(exc).__name__}): {exc}", EXIT_UNEXPECTED)


if __name__ == "__main__":
    sys.exit(main())