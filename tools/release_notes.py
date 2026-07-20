import logging
import os
import re

from agent.schemas import ReleaseNoteEntry

log = logging.getLogger(__name__)

CONVENTIONAL_COMMIT = re.compile(
    r'^(feat|fix|chore|docs|style|refactor|perf|test|build|ci|revert)'
    r'(?:\(([^)]+)\))?:\s*(.+)',
    re.IGNORECASE,
)

DIFF_NOTE = re.compile(
    r'^\+\s*(?:#\s*)?(feat|fix|chore|refactor|perf|test|docs)[:\s]+(.+)',
    re.IGNORECASE,
)


def _get_commit_messages() -> list[str]:
    try:
        base = os.environ.get("GITHUB_BASE_REF", "main")
        os.system(f"git fetch origin {base} --depth=50 >/dev/null 2>&1")
        result = os.popen(f"git log origin/{base}..HEAD --oneline --format=%s").read()
        return [line.strip() for line in result.splitlines() if line.strip()]
    except Exception as exc:
        log.debug("failed to get commit messages: %s", exc)
        return []


def _parse_commits(messages: list[str]) -> list[ReleaseNoteEntry]:
    entries = []
    for msg in messages:
        m = CONVENTIONAL_COMMIT.match(msg)
        if m:
            entries.append(ReleaseNoteEntry(
                category=m.group(1).lower(),
                message=m.group(3).strip(),
            ))
    return entries


def _parse_diff(diff: str) -> list[ReleaseNoteEntry]:
    entries = []
    for line in diff.splitlines():
        m = DIFF_NOTE.match(line)
        if m:
            entries.append(ReleaseNoteEntry(
                category=m.group(1).lower(),
                message=m.group(2).strip(),
            ))
    return entries


def generate_notes(diff: str) -> list[ReleaseNoteEntry]:
    commit_entries = _parse_commits(_get_commit_messages())
    diff_entries = _parse_diff(diff)

    seen = {(e.category, e.message) for e in commit_entries}
    for entry in diff_entries:
        if (entry.category, entry.message) not in seen:
            commit_entries.append(entry)
            seen.add((entry.category, entry.message))

    return commit_entries
