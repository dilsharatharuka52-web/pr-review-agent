import logging
import os

from github import Github

from agent.schemas import AnalysisReport

log = logging.getLogger(__name__)

BOT_TAG = "<!-- pr-agent-analysis -->"


def _build_body(report: AnalysisReport) -> str:
    lines = [BOT_TAG]
    lines.append("## PR Analysis Report")
    lines.append("")

    emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}
    risk_icon = emoji.get(report.risk_level, "⚪")
    lines.append(f"### {risk_icon} Risk Score: **{report.risk_score}/10** ({report.risk_level})")

    if report.diff_stats:
        s = report.diff_stats
        lines.append(f"> 📁 {s.files_changed} files  |  **+{s.lines_added}** / **-{s.lines_removed}** lines  |  Tests changed: {'✅' if s.tests_changed else '❌'}")  # noqa: E501

    if report.metadata:
        m = report.metadata
        lines.append(f"> ⚡ {m.duration_ms}ms  |  💰 ${m.cost_usd:.4f}  |  🔤 {m.tokens_used} tokens")

    lines.append("")

    if report.vulnerabilities:
        lines.append("### 🔒 Security Vulnerabilities")
        lines.append("| File | Package | CVE | Severity | Description |")
        lines.append("|------|---------|-----|----------|-------------|")
        for v in report.vulnerabilities:
            cve = v.cve or "—"
            pkg = v.package or "—"
            lines.append(f"| `{v.file}` | {pkg} | {cve} | **{v.severity}** | {v.description} |")
        lines.append("")

    if report.findings:
        lines.append("### 📝 Code Review Findings")
        lines.append("| File | Line | Severity | Message |")
        lines.append("|------|------|----------|---------|")
        for f in report.findings:
            loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
            lines.append(f"| {loc} | {f.line} | **{f.severity}** | {f.message} |")
        lines.append("")

    if report.release_notes:
        lines.append("### 📋 Release Notes")
        categories = {}
        for entry in report.release_notes:
            categories.setdefault(entry.category, []).append(entry.message)
        for cat in ("feat", "fix", "refactor", "perf", "test", "chore", "docs"):
            items = categories.pop(cat, None)
            if items:
                lines.append(f"**{cat.title()}**")
                for msg in items:
                    lines.append(f"- {msg}")
                lines.append("")
        for cat, items in categories.items():
            lines.append(f"**{cat.title()}**")
            for msg in items:
                lines.append(f"- {msg}")
            lines.append("")

    if report.errors:
        lines.append("### ⚠️ Errors")
        for err in report.errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.append("---")
    lines.append(f"<sub>🤖 PR Agent · {report.metadata.duration_ms}ms · ${report.metadata.cost_usd:.4f}</sub>" if report.metadata else "<sub>🤖 PR Agent</sub>")  # noqa: E501

    return "\n".join(lines)


def post_comment(pr_number: int, report: AnalysisReport) -> None:
    token = os.environ["GIT_TOKEN"]
    repo_name = os.environ.get("GIT_REPOSITORY", "")
    if not repo_name:
        raise ValueError("GIT_REPOSITORY not set")

    g = Github(token)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    body = _build_body(report)

    existing = None
    for comment in pr.get_issue_comments():
        if comment.body and comment.body.startswith(BOT_TAG):
            existing = comment
            break

    if existing:
        existing.edit(body)
        log.info("updated existing comment #%d on PR #%d", existing.id, pr_number)
    else:
        pr.create_issue_comment(body)
        log.info("created new comment on PR #%d", pr_number)
