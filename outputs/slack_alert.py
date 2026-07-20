import json
import logging
import os

import httpx

from agent.schemas import AnalysisReport

log = logging.getLogger(__name__)

RISK_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}


def send_alert(report: AnalysisReport) -> None:
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        log.warning("SLACK_WEBHOOK_URL not set, skipping alert")
        return

    emoji = RISK_EMOJI.get(report.risk_level, "⚪")
    pr_num = report.metadata.pr_number if report.metadata else "?"
    repo = os.environ.get("GIT_REPOSITORY", "unknown/repo")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} High-Risk PR: {repo}#{pr_num}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{report.risk_score}/10 ({report.risk_level})"},
                {"type": "mrkdwn", "text": f"*Findings:*\n{len(report.findings)}"},
                {"type": "mrkdwn", "text": f"*Vulnerabilities:*\n{len(report.vulnerabilities)}"},
                {"type": "mrkdwn", "text": f"*Files Changed:*\n{report.diff_stats.files_changed if report.diff_stats else '?'}"},
            ],
        },
    ]

    if report.vulnerabilities:
        vuln_text = "\n".join(
            f"• {v.cve or v.description[:80]} — *{v.severity}*" for v in report.vulnerabilities[:5]
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Vulnerabilities:*\n{vuln_text}"},
        })

    pr_url = f"https://github.com/{repo}/pull/{pr_num}"
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View PR"},
                "url": pr_url,
                "style": "danger" if report.risk_level == "high" else "primary",
            }
        ],
    })

    payload = {"blocks": blocks}

    with httpx.Client(timeout=15) as client:
        resp = client.post(webhook, json=payload)
        resp.raise_for_status()
        log.info("slack alert sent (status=%d)", resp.status_code)
