import argparse
import json
import logging
import os
import time
from pathlib import Path

from agent.schemas import (
    AnalysisReport,
    DiffStats,
    Finding,
    RunMetadata,
    Vulnerability,
    ReleaseNoteEntry,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s %(message)s",
)
log = logging.getLogger("orchestrator")


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _is_dry_run() -> bool:
    return _env("DRY_RUN", "false").lower() in ("1", "true", "yes")


def _load_event() -> dict:
    path = _env("GITHUB_EVENT_PATH", "")
    if path:
        return json.loads(Path(path).read_text())
    return {}


def _parse_pr_info() -> dict:
    event = _load_event()
    return {
        "number": event.get("pull_request", {}).get("number") or int(_env("PR_NUMBER", "0")),
        "title": event.get("pull_request", {}).get("title", ""),
        "base_sha": event.get("pull_request", {}).get("base", {}).get("sha", ""),
        "head_sha": event.get("pull_request", {}).get("head", {}).get("sha", ""),
        "base_ref": event.get("pull_request", {}).get("base", {}).get("ref", "main"),
    }


def _load_diff(base_ref: str = "main") -> str:
    os.system(f"git fetch origin {base_ref} --depth=1 >/dev/null 2>&1")
    return os.popen(f"git diff origin/{base_ref}...HEAD").read()


def _diff_stats(diff: str) -> DiffStats:
    files = set()
    added = removed = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            fname = line[6:]
            files.add(fname)
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1

    tests_changed = any("test" in f.lower() for f in files)
    return DiffStats(
        files_changed=len(files),
        lines_added=added,
        lines_removed=removed,
        tests_changed=tests_changed,
    )


def analyze() -> AnalysisReport:
    pr = _parse_pr_info()
    dry = _is_dry_run()
    t0 = time.monotonic()

    log.info("analyzing PR #%s: %s", pr["number"], pr["title"])

    diff = _load_diff(pr["base_ref"])
    stats = _diff_stats(diff)

    from tools.code_review import review
    from tools.security_scan import scan
    from tools.release_notes import generate_notes
    from tools.risk_score import score

    findings: list[Finding] = []
    vulnerabilities: list[Vulnerability] = []
    release_notes: list[ReleaseNoteEntry] = []
    errors: list[str] = []

    try:
        findings = review(diff)
        log.info("code review: %d findings", len(findings))
    except Exception as exc:
        errors.append(f"code_review: {exc}")
        log.error("code_review failed", exc_info=True)

    try:
        vulnerabilities = scan(diff)
        log.info("security scan: %d vulnerabilities", len(vulnerabilities))
    except Exception as exc:
        errors.append(f"security_scan: {exc}")
        log.error("security_scan failed", exc_info=True)

    try:
        release_notes = generate_notes(diff)
        log.info("release notes: %d entries", len(release_notes))
    except Exception as exc:
        errors.append(f"release_notes: {exc}")
        log.error("release_notes failed", exc_info=True)

    try:
        risk = score(findings=findings, vulnerabilities=vulnerabilities, stats=stats)
    except Exception as exc:
        errors.append(f"risk_score: {exc}")
        log.error("risk_score failed", exc_info=True)
        risk = 0.0

    risk_level = "low"
    if risk >= 7.0:
        risk_level = "high"
    elif risk >= 4.0:
        risk_level = "medium"

    tokens_used = sum(
        getattr(f, "_tokens", 0) for f in findings
    )
    cost = tokens_used * 0.000002

    dt = int((time.monotonic() - t0) * 1000)

    metadata = RunMetadata(
        pr_number=pr["number"],
        pr_title=pr["title"],
        base_sha=pr["base_sha"],
        head_sha=pr["head_sha"],
        tokens_used=tokens_used,
        cost_usd=round(cost, 4),
        duration_ms=dt,
        dry_run=dry,
    )

    report = AnalysisReport(
        risk_score=round(risk, 1),
        risk_level=risk_level,
        findings=findings,
        vulnerabilities=vulnerabilities,
        release_notes=release_notes,
        diff_stats=stats,
        metadata=metadata,
        errors=errors,
    )

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "analysis.json"
    report_path.write_text(_serialize(report))

    log.info("report written to %s (score=%.1f, tokens=%d, cost=$%.4f, errors=%d)",
             report_path, risk, tokens_used, cost, len(errors))

    summary = (
        f"## PR Analysis Summary\n"
        f"- **Risk Score:** {report.risk_score}/10 ({report.risk_level})\n"
        f"- **Findings:** {len(findings)}  | **Vulnerabilities:** {len(vulnerabilities)}\n"
        f"- **Files Changed:** {stats.files_changed}  | **+{stats.lines_added}/-{stats.lines_removed} lines\n"
        f"- **Tokens Used:** {tokens_used} (${cost:.4f})  | **Duration:** {dt}ms\n"
    )
    if errors:
        summary += f"- **Errors:** {len(errors)}\n"
    summary_path = Path(_env("GITHUB_STEP_SUMMARY", "output/step_summary.md"))
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(summary)

    return report


def respond() -> None:
    dry = _is_dry_run()
    report_path = Path("output/analysis.json")
    if not report_path.exists():
        log.error("no analysis report found at %s", report_path)
        return

    report = _deserialize(report_path.read_text())
    pr_number = report.metadata.pr_number if report.metadata else 0

    log.info("responding on PR #%d (dry_run=%s)", pr_number, dry)

    from outputs.github_comment import post_comment
    from outputs.slack_alert import send_alert

    if not dry:
        try:
            post_comment(pr_number, report)
            log.info("comment posted on PR #%d", pr_number)
        except Exception as exc:
            log.error("failed to post comment: %s", exc)
    else:
        log.info("DRY_RUN: skipping comment on PR #%d", pr_number)

    if report.risk_level in ("medium", "high"):
        if not dry:
            try:
                send_alert(report)
                log.info("slack alert sent (risk=%s)", report.risk_level)
            except Exception as exc:
                log.error("failed to send slack alert: %s", exc)
        else:
            log.info("DRY_RUN: skipping slack alert (risk=%s)", report.risk_level)
    else:
        log.info("risk level %s below threshold, no slack alert", report.risk_level)


def _serialize(report: AnalysisReport) -> str:
    return json.dumps(report, cls=_ReportEncoder, indent=2)


def _deserialize(data: str) -> AnalysisReport:
    return json.loads(data, object_hook=_report_decoder)


class _ReportEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (AnalysisReport, DiffStats, Finding, Vulnerability, ReleaseNoteEntry, RunMetadata)):
            d = {k: v for k, v in o.__dict__.items() if not k.startswith("_")}
            d["__type__"] = type(o).__name__
            return d
        return super().default(o)


def _report_decoder(d):
    t = d.pop("__type__", None)
    if t == "Finding":
        return Finding(**d)
    elif t == "Vulnerability":
        return Vulnerability(**d)
    elif t == "ReleaseNoteEntry":
        return ReleaseNoteEntry(**d)
    elif t == "DiffStats":
        return DiffStats(**d)
    elif t == "RunMetadata":
        return RunMetadata(**d)
    elif t == "AnalysisReport":
        return AnalysisReport(**d)
    return d


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["analyze", "respond"])
    args = parser.parse_args()

    from dotenv import load_dotenv
    load_dotenv()

    if args.mode == "analyze":
        analyze()
    else:
        respond()
