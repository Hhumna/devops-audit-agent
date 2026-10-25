import pytest

from audit_agent.redact import redact_text
from audit_agent.repo import RepoError, parse_github_url


def test_parse_valid_urls():
    assert parse_github_url("https://github.com/a/b") == ("a", "b")
    assert parse_github_url("https://github.com/a/b.git") == ("a", "b")
    assert parse_github_url("https://github.com/a/b/") == ("a", "b")


@pytest.mark.parametrize("bad", [
    "", "http://github.com/a/b", "https://evil.com/a/b", "https://github.com/a",
    "git@github.com:a/b.git", "https://github.com/a/b; rm -rf /",
])
def test_parse_invalid_urls(bad):
    with pytest.raises(RepoError):
        parse_github_url(bad)


def test_redacts_private_key_and_keeps_line_count():
    key = "-----BEGIN RSA PRIVATE KEY-----\nabc\ndef\n-----END RSA PRIVATE KEY-----"
    out = redact_text(key)
    assert "abc" not in out and out.count("\n") == 3


def test_redacts_assigned_password():
    assert "hunter2hunter2" not in redact_text('password = "hunter2hunter2"')


def test_keeps_placeholders_and_references():
    assert redact_text("LLM_API_KEY=your_api_key_here") == "LLM_API_KEY=your_api_key_here"
    assert "secrets.X" in redact_text("token: ${{ secrets.X }}")

def test_keeps_code_expressions():
    line = 'self.api_key = (api_key or os.getenv("LLM_API_KEY", "")).strip()'
    assert redact_text(line) == line
