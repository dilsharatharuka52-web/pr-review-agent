import json
import logging
import os

import httpx

from agent.schemas import Finding

log = logging.getLogger(__name__)

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-chat"
MAX_DIFF_CHARS = 80_000

SYSTEM_PROMPT = """You are a senior code reviewer. Analyze the provided git diff and identify:

1. **Bug risks** — logic errors, race conditions, null dereferences, off-by-one, etc.
2. **Security issues** — injection, hardcoded secrets, missing auth, unsafe deserialization, etc.
3. **Code quality** — dead code, overly complex functions, violation of project conventions.
4. **Performance** — N+1 queries, unnecessary allocations, large objects in hot paths.

For each finding, return a JSON object with:
- `file`: the file path
- `line`: approximate line number (0 if unknown)
- `severity`: one of "low", "medium", "high", "critical"
- `message`: concise, actionable description
- `rule`: short identifier like "bug-null-deref", "security-hardcoded-secret", "quality-complexity"

Respond with a JSON array of findings. If no issues, return an empty array."""  # noqa: E501


def _deepseek_review(diff: str) -> list[dict]:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        log.warning("DEEPSEEK_API_KEY not set, skipping LLM review")
        return []

    if len(diff) > MAX_DIFF_CHARS:
        log.warning("diff truncated from %d to %d chars", len(diff), MAX_DIFF_CHARS)
        diff = diff[:MAX_DIFF_CHARS]

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Review this diff:\n\n```diff\n{diff}\n```"},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
        "max_tokens": 4096,
    }

    with httpx.Client(timeout=120) as client:
        resp = client.post(
            DEEPSEEK_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    usage = data.get("usage", {})
    tokens = usage.get("total_tokens", 0)
    content = data["choices"][0]["message"]["content"]

    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict) and "findings" in parsed:
            parsed = parsed["findings"]
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        log.error("DeepSeek returned invalid JSON: %s", content[:500])
        return []


def review(diff: str) -> list[Finding]:
    raw = _deepseek_review(diff)
    findings = []
    for item in raw:
        findings.append(Finding(
            file=item.get("file", ""),
            line=item.get("line", 0),
            severity=item.get("severity", "medium"),
            message=item.get("message", ""),
            rule=item.get("rule", "unknown"),
        ))
    return findings
