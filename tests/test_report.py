import json

import pytest

from audit_agent.report import (
    ViolationCollector,
    build_report,
    validate_report,
    write_report,
)

FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


@pytest.fixture()
def collector(tmp_path):
    (tmp_path / "config.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    return ViolationCollector(tmp_path)


def good(**changes):
    base = {
        "category": "security", "severity": "high", "file": "config.py", "line": 2,
        "description": "Hardcoded API credential",
        "evidence": "config.py line 2 assigns a literal credential value",
        "recommendation": "Use an environment variable",
    }
    base.update(changes)
    return base


def test_accepts_valid_violation(collector):
    ok, message = collector.add(good())
    assert ok and message == "recorded SEC-001"
    assert collector.violations[0]["file"] == "config.py"
    assert collector.violations[0]["line"] == 2


def test_rejects_bad_category_and_severity(collector):
    assert not collector.add(good(category="nonsense"))[0]
    assert not collector.add(good(severity="urgent"))[0]


def test_rejects_missing_file_and_bad_line(collector):
    assert not collector.add(good(file="ghost.py"))[0]
    assert not collector.add(good(file="../outside.py"))[0]
    assert not collector.add(good(line=99))[0]


def test_null_file_and_line_allowed(collector):
    ok, _ = collector.add(good(file=None, line=None, category="repository_hygiene",
                               description="README is missing"))
    assert ok
    assert collector.violations[0]["file"] is None
    assert collector.violations[0]["line"] is None


def test_rule_ids_increment_per_category(collector):
    collector.add(good())
    ok, message = collector.add(good(line=3, description="Debug mode enabled in settings"))
    assert ok and message == "recorded SEC-002"


def test_duplicates_rejected(collector):
    assert collector.add(good())[0]
    ok, message = collector.add(good(description="Credential hardcoded in source"))
    assert not ok and "duplicate" in message


def test_weak_evidence_rejected(collector):
    assert not collector.add(good(evidence="bad"))[0]


def test_secret_values_are_redacted(collector):
    collector.add(good(evidence=f"config.py line 2 contains the key {FAKE_KEY} in plain text"))
    assert FAKE_KEY not in json.dumps(collector.violations)


def test_write_report_roundtrip(collector, tmp_path):
    collector.add(good())
    out = tmp_path / "out" / "report.json"
    write_report(str(out), build_report("https://github.com/a/b", collector.violations))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["repository"] == "https://github.com/a/b"
    assert data["violations"][0]["rule_id"] == "SEC-001"


def test_empty_violations_is_valid():
    validate_report({"repository": "https://github.com/a/b", "violations": []})


def test_invalid_report_rejected():
    with pytest.raises(ValueError):
        validate_report({"repository": "x", "violations": [{"rule_id": "SEC-001"}]})