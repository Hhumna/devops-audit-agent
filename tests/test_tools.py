import subprocess

import pytest

from tools import RepoTools, execute_tool

FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def _git(path, *args):
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)


@pytest.fixture()
def tools(tmp_path):
    (tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
    (tmp_path / "config.py").write_text(
        f'DEBUG = True\naws_key = "{FAKE_KEY}"\npassword = "hunter2hunter2"\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "-c", "user.name=T", "-c", "user.email=t@example.com",
         "commit", "-m", "initial commit")
    return RepoTools(tmp_path)


def test_list_files_shows_tracked_files(tools):
    out = execute_tool(tools, "list_files", {})
    assert "README.md" in out and "src/app.py" in out


def test_list_files_subdirectory(tools):
    out = execute_tool(tools, "list_files", {"directory": "src"})
    assert "src/app.py" in out and "README.md" not in out


def test_read_file_has_line_numbers_and_redacts(tools):
    out = execute_tool(tools, "read_file", {"path": "config.py"})
    assert "2: aws_key" in out
    assert FAKE_KEY not in out and "hunter2hunter2" not in out
    assert "[REDACTED]" in out


def test_read_file_blocks_path_traversal(tools):
    out = execute_tool(tools, "read_file", {"path": "../outside.txt"})
    assert out.startswith("ERROR")


def test_read_file_blocks_git_dir(tools):
    out = execute_tool(tools, "read_file", {"path": ".git/config"})
    assert out.startswith("ERROR")


def test_read_file_missing_file(tools):
    assert execute_tool(tools, "read_file", {"path": "nope.txt"}).startswith("ERROR")


def test_search_code_finds_line_and_hides_secret(tools):
    out = execute_tool(tools, "search_code", {"pattern": "debug"})
    assert "config.py:1:" in out
    out = execute_tool(tools, "search_code", {"pattern": "AKIA"})
    assert FAKE_KEY not in out


def test_search_code_invalid_regex(tools):
    assert execute_tool(tools, "search_code", {"pattern": "("}).startswith("ERROR")


def test_git_log_shows_commit(tools):
    assert "initial commit" in execute_tool(tools, "git_log", {})


def test_unknown_tool_and_bad_arguments(tools):
    assert execute_tool(tools, "rm_rf", {}).startswith("ERROR")
    assert execute_tool(tools, "read_file", {"wrong": 1}).startswith("ERROR")