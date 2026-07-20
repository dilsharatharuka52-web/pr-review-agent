from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    message: str
    rule: str


@dataclass
class Vulnerability:
    file: str
    package: Optional[str] = None
    cve: Optional[str] = None
    severity: str = "medium"
    description: str = ""
    source: str = "semgrep"


@dataclass
class ReleaseNoteEntry:
    category: str
    message: str
    author: Optional[str] = None
    commit_sha: Optional[str] = None


@dataclass
class DiffStats:
    files_changed: int = 0
    lines_added: int = 0
    lines_removed: int = 0
    tests_changed: bool = False


@dataclass
class RunMetadata:
    pr_number: int
    pr_title: str
    base_sha: str
    head_sha: str
    tokens_used: int = 0
    cost_usd: float = 0.0
    duration_ms: int = 0
    dry_run: bool = False


@dataclass
class AnalysisReport:
    risk_score: float = 0.0
    risk_level: str = "low"
    findings: list[Finding] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    release_notes: list[ReleaseNoteEntry] = field(default_factory=list)
    diff_stats: Optional[DiffStats] = None
    metadata: Optional[RunMetadata] = None
    errors: list[str] = field(default_factory=list)
