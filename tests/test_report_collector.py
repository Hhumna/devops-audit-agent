import json

import pytest

from audit_agent.report import (
    ViolationCollector,
    build_report,
    validate_report,
    write_report,
)

FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
GOOD = {
    "category": "repository_hygiene",
    "severity": "low",
    "file": "README.md",
    "line": 1,
    "description": "Empty README",
    "evidence": "README.md exists but has no useful content.",
    "recommendation": "Document setup and usage.",
}


@pytest.fixture()
def collector(tmp_path):
    (tmp_path / "README.md").write_text("a\nb\nc\n", encoding="utf-8")
    return ViolationCollector(tmp_path)


def test_valid_violation_is_recorded(collector):
    ok, message = collector.add(dict(GOOD))
    assert ok and message == "recorded HYG-001"
    assert collector.violations[0]["file"] == "README.md"


def test_rejects_bad_category_and_severity(collector):
    assert not collector.add({**GOOD, "category": "nope"})[0]
    assert not collector.add({**GOOD, "severity": "urgent"})[0]


def test_rejects_short_evidence(collector):
    assert not collector.add({**GOOD, "evidence": "bad"})[0]


def test_rejects_missing_file_and_bad_line(collector):
    assert not collector.add({**GOOD, "file": "nope.txt"})[0]
    assert not collector.add({**GOOD, "line": 99})[0]
    assert not collector.add({**GOOD, "file": "../x.txt"})[0]


def test_null_file_and_line_are_allowed(collector):
    ok, _ = collector.add({**GOOD, "file": None, "line": None, "description": "No CI"})
    assert ok
    assert collector.violations[0]["file"] is None and collector.violations[0]["line"] is None


def test_duplicate_is_rejected(collector):
    assert collector.add(dict(GOOD))[0]
    ok, message = collector.add({**GOOD, "description": "Something else entirely"})
    assert not ok and "duplicate" in message


def test_secret_is_redacted_in_evidence(collector):
    ok, _ = collector.add({
        **GOOD, "category": "security", "file": None, "line": None,
        "description": "Hardcoded credential",
        "evidence": f"Found a literal key {FAKE_KEY} assigned in source code.",
    })
    assert ok
    assert FAKE_KEY not in json.dumps(collector.violations)


def test_empty_report_is_valid(tmp_path):
    out = tmp_path / "report.json"
    write_report(str(out), build_report("https://github.com/a/b", []))
    assert json.loads(out.read_text(encoding="utf-8"))["violations"] == []


def test_validate_report_rejects_bad_shapes(collector):
    collector.add(dict(GOOD))
    report = build_report("https://github.com/a/b", collector.violations)
    validate_report(report)
    del report["violations"][0]["evidence"]
    with pytest.raises(ValueError):
        validate_report(report)
    with pytest.raises(TypeError):
        validate_report({"violations": []})