"""Agent loop."""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field

from audit_agent.llm import LLMError, message_to_dict
from audit_agent.prompts import build_system_prompt, build_user_message
from audit_agent.redact import redact_text
from audit_agent.report import CATEGORIES, SEVERITIES, ViolationCollector
from tools import TOOL_SCHEMAS, RepoTools, execute_tool

INSPECTION_TOOLS = {"list_files", "read_file", "search_code", "git_log"}
MAX_NUDGES = 2
KEEP_RECENT_TOOL_RESULTS = 3
OLD_RESULT_CHARS = 500

RECORD_SCHEMA = {"type": "function", "function": {
    "name": "record_violation",
    "description": (
        "Record ONE confirmed DevOps violation backed by evidence you saw in tool output. "
        "Omit file and line for absences or repository-wide problems."
    ),
    "parameters": {"type": "object", "properties": {
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "file": {"type": ["string", "null"], "description": "Repo-relative path of the affected file."},
        "line": {"type": ["integer", "null"], "description": "Line number you actually saw."},
        "description": {"type": "string", "description": "Short title of the problem."},
        "evidence": {"type": "string",
                     "description": "What you observed and where. Never include secret values."},
        "recommendation": {"type": "string", "description": "A specific fix."},
    }, "required": ["category", "severity", "description", "evidence", "recommendation"]}}}

FINISH_SCHEMA = {"type": "function", "function": {
    "name": "finish_audit",
    "description": "Call when the investigation is complete and all violations are recorded.",
    "parameters": {"type": "object", "properties": {
        "summary": {"type": "string", "description": "One or two sentences on what was checked."},
    }, "required": []}}}


@dataclass
class AuditResult:
    violations: list[dict]
    completed: bool
    stop_reason: str
    steps: int
    summary: str = ""
    trace: list[dict] = field(default_factory=list)


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _compact(messages: list[dict]) -> list[dict]:
    """Shorten old tool outputs so the context stays small on long audits."""
    tool_positions = [i for i, m in enumerate(messages) if m["role"] == "tool"]
    old = set(tool_positions[:-KEEP_RECENT_TOOL_RESULTS]) if len(tool_positions) > KEEP_RECENT_TOOL_RESULTS else set()
    out = []
    for index, message in enumerate(messages):
        if index in old and len(message["content"]) > OLD_RESULT_CHARS:
            message = {
                **message,
                "content": message["content"][:OLD_RESULT_CHARS]
                + "\n... [older output shortened; re-read the file if you need it]",
            }
        out.append(message)
    return out


def _parse_arguments(raw):
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def run_audit(repo_url: str, tools: RepoTools, llm, max_steps: int = 25, log=_log) -> AuditResult:
    """Run the LLM-driven investigation loop and return the recorded violations."""
    collector = ViolationCollector(tools.root)
    messages: list[dict] = [
        {"role": "system", "content": build_system_prompt(max_steps)},
        {"role": "user", "content": build_user_message(repo_url, max_steps)},
    ]
    schemas = [*TOOL_SCHEMAS, RECORD_SCHEMA, FINISH_SCHEMA]
    trace: list[dict] = []
    inspected = 0
    nudges = 0
    bad_calls = 0
    shrinks = 0
    summary = ""
    stop_reason = "step limit reached"
    step = 0
    try:
        for step in range(1, max_steps + 1):
            if max_steps > 3 and step == max_steps - 5:
                messages.append({"role": "user", "content": (
                    "Only 5 turns remain and inspection tools are now disabled. Record EVERY confirmed violation now, "
                    "then call finish_audit."
                )})
            active = schemas
            try:
                reply = llm.chat(_compact(messages), active)
            except LLMError as exc:
                if 'HTTP 413' in str(exc) and shrinks < 3:
                    shrinks += 1
                    log(f'[step {step}] request too large; shortening history and waiting')
                    for old in messages[:-4]:
                        if old.get('role') == 'tool' and len(old['content']) > 200:
                            old['content'] = old['content'][:200] + ' ... [shortened]'
                    time.sleep(30)
                    continue
                if ('tool_use_failed' in str(exc) or 'output_parse_failed' in str(exc)) and bad_calls < 4:
                    bad_calls += 1
                    log(f'[step {step}] invalid tool call from model; retrying')
                    messages.append({'role': 'user', 'content': 'Your last tool call was invalid or that tool is not available right now. Call only an available tool, using its exact name.'})
                    continue
                raise
            entry = message_to_dict(reply)
            messages.append(entry)
            thought = redact_text(entry["content"]).strip()
            if thought:
                log(f"[step {step}] {thought[:300]}")
            calls = entry.get("tool_calls", [])
            if not calls:
                nudges += 1
                if nudges > MAX_NUDGES:
                    stop_reason = "model stopped calling tools"
                    break
                messages.append({"role": "user", "content": (
                    "Continue by calling a tool. When your investigation is complete, "
                    "call finish_audit."
                )})
                continue
            finished = False
            for call in calls:
                name = call["function"]["name"]
                args = _parse_arguments(call["function"].get("arguments"))
                shown = redact_text(json.dumps(args, ensure_ascii=False))[:150] if args is not None else "<invalid>"
                log(f"[step {step}] {name}({shown})")
                if args is None:
                    result = "ERROR: tool arguments must be a valid JSON object."
                elif name == "record_violation":
                    ok, message = collector.add(args)
                    result = message if ok else f"ERROR: {message}"
                elif name in INSPECTION_TOOLS and max_steps > 8 and step > max_steps - 5:
                    result = 'ERROR: inspection budget is over. Call record_violation for confirmed problems, then finish_audit.'
                elif name == "finish_audit":
                    if inspected == 0:
                        result = "ERROR: inspect the repository with the tools before finishing."
                    else:
                        finished = True
                        summary = redact_text(str(args.get("summary", "")))[:500]
                        result = "Audit finished."
                else:
                    result = ('ERROR: search pattern too broad; use a specific regex.' if name == 'search_code' and str(args.get('pattern', '')).strip() in ('.*', '*', '.', '') else execute_tool(tools, name, args))
                    if name in INSPECTION_TOOLS:
                        inspected += 1
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})
                trace.append({
                    "step": step,
                    "tool": name,
                    "arguments": shown,
                    "result": result[:300],
                })
            if finished:
                stop_reason = "finished"
                break
    except LLMError as exc:
        return AuditResult(collector.violations, False, str(exc), step, summary, trace)
    return AuditResult(collector.violations, True, stop_reason, step, summary, trace)