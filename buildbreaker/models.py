"""Core data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
PROOF_ORDER = {"PROVEN": 3, "LIKELY": 2, "BLOCKED": 1, "NA": 0, "ERROR": 0, "NOT_TESTED": -1}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    target: str
    detail: str
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cves: List[str] = field(default_factory=list)
    refs: List[str] = field(default_factory=list)
    proof: str = "NOT_TESTED"  # PROVEN | LIKELY | BLOCKED | NA | ERROR | NOT_TESTED
    file: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeSpec:
    """One generated probe build project."""

    id: str
    title: str
    category: str
    severity: str
    description: str
    remediation: str
    refs: List[str] = field(default_factory=list)
    # relative path under the emit directory
    context_dir: str = ""
    dockerfile: str = "Dockerfile"
    # extra docker build flags this probe needs (e.g. --secret, --build-arg)
    build_args: Dict[str, str] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)  # id -> file contents
    network: str = "default"  # default | none | host
    # marker substrings the runner looks for in the build log
    markers: Dict[str, str] = field(default_factory=dict)  # status -> marker text


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            -PROOF_ORDER.get(f.proof, -1),
            f.rule_id,
        ),
    )
