# DevOps Repository Auditing Agent

An LLM-driven agent that audits a public GitHub repository for DevOps best-practice
violations and writes an evidence-based JSON report. The LLM chooses which files to open and
which patterns to search, based on what it observes. There is no fixed checklist.
No agent framework is used (no LangChain, LangGraph or n8n): the loop, tool dispatch and control
flow are plain Python on top of the OpenAI SDK.

## Setup

    git clone https://github.com/Hhumna/devops-audit-agent
    cd devops-audit-agent
    python -m venv .venv
    .venv\Scripts\Activate.ps1        (Linux/macOS: source .venv/bin/activate)
    pip install -r requirements.txt

Copy `.env.example` to `.env` and fill it in:

- `LLM_API_KEY`: key for any OpenAI-compatible provider
- `LLM_MODEL`: model name (must support tool calling)
- `LLM_BASE_URL`: leave empty for OpenAI, or set the provider's OpenAI-compatible endpoint
- `MAX_AGENT_STEPS`: maximum LLM turns (default 25)
- `LLM_TIMEOUT_SECONDS`: per-request timeout (default 60)

Example provider settings (any OpenAI-compatible endpoint works):

    # Gemini
    LLM_MODEL=gemini-2.5-flash
    LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/

    # Groq
    LLM_MODEL=openai/gpt-oss-120b
    LLM_BASE_URL=https://api.groq.com/openai/v1

## Usage

    python agent.py --repo https://github.com/<owner>/<repo> --output report.json

Optional: `--trace trace.json` saves the tool-call trace. The run is fully unattended.

Exit codes: 0 completed, 1 unexpected error, 2 fatal error (bad URL, clone failure, bad LLM
configuration), 3 report written but the inspection was cut short (for example repeated LLM
errors). A clear message is printed to stderr in every error case.

## Report format

    {"repository": "<url>", "violations": [{"rule_id", "category", "severity", "file", "line",
      "description", "evidence", "recommendation"}]}

Severity is one of critical, high, medium, low. `file` and `line` are null when not applicable.
An empty `violations` list is valid. Secret values are never written to the report.

## Agent cycle

Observe -> Reason -> Select Tool -> Execute Tool -> Interpret Results -> Report. At every turn the LLM looks at what it has seen so far and chooses the next tool call itself, including follow-up calls (for example searching for a pattern after reading a workflow file). Tool outputs are fed back to the LLM, which interprets them and records findings with `record_violation`. The run ends when the LLM calls `finish_audit` or the step budget is reached.

Tools available to the LLM: `list_files`, `read_file`, `search_code`, `git_log` (inspection), `record_violation` and `finish_audit` (reporting).

## Architecture

- `agent.py`: CLI entry point, error handling and exit codes.
- `audit_agent/repo.py`: validates the URL, makes a shallow clone with hooks and symlinks
  disabled, deletes it afterwards. No code from the target repository is executed.
- `tools.py`: read-only tools: `list_files`, `read_file`, `search_code`, `git_log`. Paths are
  confined to the repository, `.git` is blocked, outputs are size-limited, errors are returned
  as text so the LLM can recover.
- `audit_agent/loop.py`: the agent loop. The LLM picks tools (including follow-up calls), results
  are fed back, and the model records findings with `record_violation` and ends with
  `finish_audit`. Step budget, invalid tool calls and LLM failures are handled.
- `audit_agent/prompts.py`: system prompt with categories, evidence rules and severity guide.
- `audit_agent/report.py`: validates each finding (category, severity, file exists, line in
  range), removes duplicates, assigns rule ids and writes the JSON atomically.
- `audit_agent/redact.py`: masks secrets in every tool output, log line and report field.
- `audit_agent/llm.py`: OpenAI SDK wrapper with retries and clear error messages.

## Evidence rules

Findings must come from tool output the agent actually saw. A missing optional file is not a
defect when an equivalent exists (for example `pyproject.toml` instead of `requirements.txt`).
Nothing is claimed about branch protection or repository settings. Repository contents are treated
as untrusted data.

## Tests

    python -m pytest -q
    ruff check .

Tests cover the tools, path safety, redaction, URL validation, report validation and the agent loop
with a fake LLM, so they need no API key.

## Limitations

The tools only read files; tests and linters are never executed. Cloning is shallow (200 commits).
Free LLM tiers may hit rate limits, which slows a run but is retried automatically.
LLM output varies between runs, so a defect found in one run may be missed in another.
`sample_report.json` is the real, unedited output of one completed run against a small test repository with injected defects.