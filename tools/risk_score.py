import logging

from agent.schemas import DiffStats, Finding, Vulnerability

log = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 6, "critical": 10}

# Cap contributions so one category can't dominate
MAX_FINDING_SCORE = 5.0
MAX_VULN_SCORE = 7.0
MAX_SIZE_SCORE = 3.0
TEST_BONUS = 1.5  # lower score if tests were changed


def score(
    findings: list[Finding],
    vulnerabilities: list[Vulnerability],
    stats: DiffStats | None = None,
) -> float:
    finding_score = sum(SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    finding_score = min(finding_score / 4.0, MAX_FINDING_SCORE)

    vuln_score = sum(SEVERITY_WEIGHTS.get(v.severity, 3) for v in vulnerabilities)
    vuln_score = min(vuln_score / 2.0, MAX_VULN_SCORE)

    size_score = 0.0
    if stats:
        total_lines = stats.lines_added + stats.lines_removed
        if total_lines > 1000:
            size_score = 3.0
        elif total_lines > 500:
            size_score = 2.0
        elif total_lines > 100:
            size_score = 1.0
        if stats.tests_changed:
            size_score = max(size_score - TEST_BONUS, 0.0)

    raw = finding_score + vuln_score + size_score
    clamped = min(raw, 10.0)
    return round(clamped, 1)
