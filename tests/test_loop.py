import json

import pytest

from audit_agent.llm import LLMError
from audit_agent.loop import run_audit
from tools import RepoTools


class FakeCall:
    def __init__(self, call_id, name, args):
        self.data = {
            "id": call_id, "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)},
        }

    def model_dump(self, exclude_none=True):
        return dict(self.data)


class FakeMessage:
    def __init__(self, content="", calls=()):
        self.content = content
        self.tool_calls = list(calls)


class ScriptedLLM:
    """Stands in for the real LLM: replays a script and records what it was shown."""

    def __init__(self, script):
        self.script = list(script)
        self.seen = []
        self.tool_names = set()

    def chat(self, messages, tools):
        self.seen.append(messages)
        self.tool_names = {t["function"]["name"] for t in tools}
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def msg(name, args, call_id="c", content=""):
    return FakeMessage(content, [FakeCall(call_id, name, args)])


GOOD_RECORD = {
    "category": "security", "severity": "high", "file": "config.py", "line": 2,
    "description": "Hardcoded password in source",
    "evidence": "config.py line 2 assigns a literal password value",
    "recommendation": "Read the password from an environment variable",
}


@pytest.fixture()
def tools(tmp_path):
    (tmp_path / "config.py").write_text(
        'DEBUG = True\npassword = "hunter2hunter2"\n', encoding="utf-8"
    )
    return RepoTools(tmp_path)


def run(tools, script, max_steps=10):
    llm = ScriptedLLM(script)
    return run_audit("https://github.com/a/b", tools, llm, max_steps=max_steps, log=lambda m: None), llm


def test_full_cycle_records_violation(tools):
    result, llm = run(tools, [
        msg("list_files", {}, "c1", "Looking at the layout."),
        msg("read_file", {"path": "config.py"}, "c2"),
        msg("record_violation", GOOD_RECORD, "c3"),
        msg("finish_audit", {"summary": "done"}, "c4"),
    ])
    assert result.completed and result.stop_reason == "finished"
    assert len(result.violations) == 1
    assert result.violations[0]["rule_id"] == "SEC-001"
    assert {"list_files", "read_file", "search_code", "git_log",
            "record_violation", "finish_audit"} <= llm.tool_names
    # the LLM is shown each tool result before choosing the next step
    assert llm.seen[1][-1]["role"] == "tool" and "config.py" in llm.seen[1][-1]["content"]
    assert "hunter2hunter2" not in json.dumps(llm.seen[-1])
    assert [t["tool"] for t in result.trace] == [
        "list_files", "read_file", "record_violation", "finish_audit"
    ]


def test_invalid_record_returns_error_and_model_can_retry(tools):
    bad = dict(GOOD_RECORD, file="ghost.py")
    result, llm = run(tools, [
        msg("list_files", {}, "c1"),
        msg("record_violation", bad, "c2"),
        msg("record_violation", GOOD_RECORD, "c3"),
        msg("finish_audit", {}, "c4"),
    ])
    assert llm.seen[2][-1]["content"].startswith("ERROR")
    assert len(result.violations) == 1


def test_finish_before_inspecting_is_refused(tools):
    result, llm = run(tools, [
        msg("finish_audit", {}, "c1"),
        msg("list_files", {}, "c2"),
        msg("finish_audit", {}, "c3"),
    ])
    assert llm.seen[1][-1]["content"].startswith("ERROR")
    assert result.completed and result.stop_reason == "finished"


def test_model_that_stops_calling_tools_is_handled(tools):
    result, _ = run(tools, [FakeMessage("thinking"), FakeMessage("hmm"), FakeMessage("...")])
    assert result.completed
    assert result.stop_reason == "model stopped calling tools"
    assert result.violations == []


def test_llm_failure_returns_partial_result(tools):
    result, _ = run(tools, [
        msg("list_files", {}, "c1"),
        msg("record_violation", GOOD_RECORD, "c2"),
        LLMError("boom"),
    ])
    assert not result.completed and "boom" in result.stop_reason
    assert len(result.violations) == 1


def test_step_limit_stops_the_loop(tools):
    result, _ = run(tools, [msg("list_files", {}, "c1"), msg("list_files", {}, "c2")], max_steps=2)
    assert result.completed and result.stop_reason == "step limit reached"
    assert result.steps == 2