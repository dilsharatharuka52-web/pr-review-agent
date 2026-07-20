import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

import httpx

from agent.schemas import Vulnerability

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"
DEP_PATTERN = re.compile(r'^[+-]\s*([\w.-]+)\s*[=><]+\s*([\w.]+)')


def _semgrep_scan(repo_path: str = ".") -> list[Vulnerability]:
    try:
        result = subprocess.run(
            ["semgrep", "--config=p/owasp-top-ten", "--json", repo_path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            log.warning("semgrep exited with code %d: %s", result.returncode, result.stderr[:500])
            return []

        data = json.loads(result.stdout)
        vulns = []
        for result_item in data.get("results", []):
            vulns.append(Vulnerability(
                file=result_item.get("path", ""),
                severity=_map_semgrep_severity(result_item.get("extra", {}).get("severity", "WARNING")),
                description=result_item.get("extra", {}).get("message", ""),
                source="semgrep",
            ))
        return vulns
    except FileNotFoundError:
        log.warning("semgrep not installed, skipping")
        return []
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        log.error("semgrep failed: %s", exc)
        return []


def _map_semgrep_severity(sev: str) -> str:
    mapping = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return mapping.get(sev.upper(), "medium")


def _parse_dep_changes(diff: str) -> list[tuple[str, str, str]]:
    changes = []
    current_file = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        if not current_file.endswith(("requirements.txt", "Pipfile", "pyproject.toml",
                                       "Cargo.toml", "package.json", "go.mod")):
            continue
        m = DEP_PATTERN.match(line)
        if m and line.startswith("+"):
            changes.append((current_file, m.group(1), m.group(2)))
    return changes


def _query_osv(package: str, version: str) -> list[dict]:
    try:
        resp = httpx.post(OSV_API, json={
            "package": {"name": package, "ecosystem": "PyPI"},
            "version": version,
        }, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulns", [])
    except Exception as exc:
        log.debug("OSV query failed for %s@%s: %s", package, version, exc)
        return []


def _osv_scan(diff: str) -> list[Vulnerability]:
    vulns = []
    dep_changes = _parse_dep_changes(diff)
    for file, pkg, ver in dep_changes:
        for vuln in _query_osv(pkg, ver):
            vulns.append(Vulnerability(
                file=file,
                package=pkg,
                cve=vuln.get("id", ""),
                severity=_map_osv_severity(vuln.get("severity", [{}])[0].get("type", "")),
                description=vuln.get("summary", "") or vuln.get("details", ""),
                source="osv",
            ))
    return vulns


def _map_osv_severity(sev: str) -> str:
    mapping = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return mapping.get(sev.upper(), "medium")


def scan(diff: str) -> list[Vulnerability]:
    repo_path = os.environ.get("GITHUB_WORKSPACE", ".")
    semgrep_vulns = _semgrep_scan(repo_path)
    osv_vulns = _osv_scan(diff)
    return semgrep_vulns + osv_vulns
