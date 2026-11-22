"""Human-readable and JSON reports."""

from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Dict, List, Optional

from . import __version__
from .analyzer import attack_blurb
from .models import Finding, sort_findings

COLORS = {
    "critical": "\033[1;91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[37m",
    "PROVEN": "\033[1;91m",
    "LIKELY": "\033[93m",
    "BLOCKED": "\033[92m",
    "NA": "\033[37m",
    "ERROR": "\033[95m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _c(key: str, text: str, color: bool) -> str:
    return f"{COLORS.get(key, '')}{text}{COLORS['reset']}" if color else text


def _verdict(findings: List[Finding]) -> str:
    if any(f.proof == "PROVEN" and f.severity in ("critical", "high") for f in findings):
        return "BUILD SURFACE EXPOSED"
    if any(f.proof == "PROVEN" for f in findings):
        return "PARTIAL EXPOSURE"
    if any(f.proof == "ERROR" for f in findings):
        return "INCOMPLETE"
    return "HARDENED"


def render_text(
    findings: List[Finding],
    *,
    targets: List[str],
    builder: Optional[str] = None,
    profile: Optional[str] = None,
    color: Optional[bool] = None,
) -> str:
    if color is None:
        color = sys.stdout.isatty()
    findings = sort_findings(findings)
    lines: List[str] = []
    w = lines.append
    w(_c("bold", f"BuildBreaker {__version__}  container build-service probe report", color))
    w("")
    w(_c("bold", "Targets", color))
    for t in targets:
        w(f"  - {t}")
    if builder:
        w("")
        w(_c("bold", "Builder", color))
        w(f"  - {builder}")
    if profile:
        w(f"  - profile: {profile}")
    counts = Counter(f.severity for f in findings)
    proven = sum(1 for f in findings if f.proof == "PROVEN")
    blocked = sum(1 for f in findings if f.proof == "BLOCKED")
    w("")
    w(_c("bold", "Summary", color))
    w(
        "  "
        + "  ".join(
            _c(s, f"{s.upper()} {counts.get(s, 0)}", color)
            for s in ("critical", "high", "medium", "low", "info")
        )
    )
    w(f"  Proven reachable: {proven}   Blocked: {blocked}")
    verdict = _verdict(findings)
    vkey = "PROVEN" if "EXPOSED" in verdict or "PARTIAL" in verdict else "BLOCKED"
    if verdict == "INCOMPLETE":
        vkey = "ERROR"
    w("  Verdict: " + _c(vkey, verdict, color))
    w("")
    w(_c("bold", "Findings", color))
    if not findings:
        w("  No probe results.")
    for f in findings:
        loc = f"  ({f.file}:{f.line})" if f.file and f.line else ""
        tag = f" [{f.proof}]" if f.proof not in ("NOT_TESTED", "") else ""
        w(f"  {_c(f.severity, f.severity.upper().ljust(8), color)} {f.rule_id} {f.title}{tag}{loc}")
        w(f"           {f.detail}")
        if f.refs:
            w(f"           Refs: {', '.join(f.refs)}")
        if f.remediation:
            w(f"           Fix: {f.remediation}")
    refs = sorted({r for f in findings for r in f.refs})
    if refs:
        w("")
        w(_c("bold", "Attack context", color))
        for r in refs:
            blurb = attack_blurb(r)
            if blurb:
                w(f"  - {blurb}")
    w("")
    w(_c("bold", "Safety", color))
    w("  Probes only print BB_FINDING markers into the build log you control.")
    w("  No real secrets are sent to external hosts. Network probes hit example.com or IMDS root only.")
    return "\n".join(lines) + "\n"


def render_json(
    findings: List[Finding],
    *,
    targets: List[str],
    builder: Optional[str] = None,
    profile: Optional[str] = None,
) -> str:
    findings = sort_findings(findings)
    counts = Counter(f.severity for f in findings)
    doc = {
        "tool": "BuildBreaker",
        "version": __version__,
        "targets": targets,
        "builder": builder,
        "profile": profile,
        "summary": {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "proven": sum(1 for f in findings if f.proof == "PROVEN"),
        "blocked": sum(1 for f in findings if f.proof == "BLOCKED"),
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, default=str)


def findings_from_json(doc: Dict) -> List[Finding]:
    out: List[Finding] = []
    for raw in doc.get("findings", []):
        out.append(
            Finding(
                rule_id=raw["rule_id"],
                title=raw["title"],
                severity=raw["severity"],
                target=raw.get("target", ""),
                detail=raw.get("detail", ""),
                remediation=raw.get("remediation", ""),
                evidence=raw.get("evidence") or {},
                cves=raw.get("cves") or [],
                refs=raw.get("refs") or [],
                proof=raw.get("proof", "NOT_TESTED"),
                file=raw.get("file"),
                line=raw.get("line"),
            )
        )
    return out
