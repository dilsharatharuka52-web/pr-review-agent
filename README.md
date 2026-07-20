# DeepSeek PR Review Agent

AI-powered CI/CD agent that reviews every pull request automatically. Triggered by GitHub PR events, it hands the diff to a DeepSeek-powered orchestrator that runs four tools — code review, security scan, release-note generation, and risk scoring — then posts findings back as a PR comment and optionally fires a Slack alert on high-risk changes.

## Architecture

```
GitHub PR event → GitHub Actions (pr-analyze.yml)
                       │
                       ▼
              agent/orchestrator.py (analyze mode)
                       │
          ┌────────────┼────────────┬─────────────┐
          ▼            ▼            ▼             ▼
    code_review   security_scan  release_notes  risk_score
    (DeepSeek)   (Semgrep+OSV)   (git log)     (weighted)
          │            │            │             │
          └────────────┴────────────┴─────────────┘
                       │
                  output/analysis.json  ← artifact
                       │
         pr-respond.yml (triggered by workflow_run)
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    GitHub Comment  Slack Alert  (DRY_RUN opt-out)
```

## Security

- **Two-workflow split:** `pr-analyze.yml` runs on `pull_request` with **no secrets** and minimal token scope (`pull-requests: read`). It produces a JSON artifact.
- `pr-respond.yml` runs on `workflow_run` (which has **secrets**), downloads the pre-built artifact, and never checks out PR code. Forked PRs cannot exfiltrate secrets.
- Scope `GITHUB_TOKEN` to minimum permissions (`pull-requests: write` only on the respond workflow).
- Semgrep (`p/owasp-top-ten`) and OSV.dev are the source of truth for security claims; the LLM only summarizes, never originates vulnerability claims.

## Setup

### 1. Repository secrets

| Secret | Description |
|--------|-------------|
| `DEEPSEEK_API_KEY` | DeepSeek API key for LLM code review |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook for high-risk alerts |
| `GITHUB_TOKEN` | Auto-provided, scope to `pull-requests: write` |

### 2. Repository variables

| Variable | Description |
|----------|-------------|
| `DRY_RUN` | Set to `true` to disable comments/alerts (safety kill switch) |

### 3. Local development

```bash
cp .env.example .env
# Fill in your keys
pip install -r requirements.txt

# Simulate analysis on current branch
python agent/orchestrator.py analyze

# Simulate response (reads output/analysis.json)
python agent/orchestrator.py respond
```

## Project Structure

```
.github/workflows/
  pr-analyze.yml       # pull_request trigger, no secrets, produces artifact
  pr-respond.yml        # workflow_run trigger, has secrets, posts comment/alert
agent/
  orchestrator.py       # Entry point: analyze (all tools) or respond (comment/alert)
  schemas.py            # Dataclass definitions (Finding, Vulnerability, etc.)
tools/
  code_review.py        # DeepSeek-powered code review (structured JSON output)
  security_scan.py      # Semgrep (p/owasp-top-ten) + OSV.dev dependency CVE lookup
  release_notes.py      # Parse conventional commits and diff annotations
  risk_score.py         # Weighted scoring (findings, vulns, diff size, test coverage)
outputs/
  github_comment.py     # PyGithub idempotent commenting (updates existing bot comment)
  slack_alert.py        # Slack Block Kit alert (medium/high risk only)
tests/
  fixtures/             # Sample diffs: trivial, large refactor, vulnerable dep
  test_tools.py         # Pytest suite (mocked external calls)
```

## Testing

```bash
pytest tests/ -v
```

## Runbook

### Disable the agent without removing the workflow

Set the `DRY_RUN` repository variable to `true`. The workflow will still run and log results but will not post comments or alerts.

### Fully disable

Go to repository Settings → Actions → Disable the `PR Analyze` workflow.

### Cost management

- Diffs are truncated at 80,000 characters to cap token usage
- Max 4,096 output tokens per DeepSeek call
- Structured JSON logging includes token count and cost per run
- Score thresholds (medium ≥ 4.0, high ≥ 7.0) control Slack alert volume

### Data governance

Source diffs are sent to the DeepSeek API. Confirm with your org whether this is acceptable for your repository before enabling on private/proprietary code.
