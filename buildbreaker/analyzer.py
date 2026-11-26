"""Parse BB_FINDING markers out of build logs into Finding objects."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .catalog import ATTACK_INFO, PROBE_BY_ID
from .models import Finding
from .runner import BuildResult

# Actual echo output looks like:
#   BB_FINDING:BB-NET-EGRESS:REACHABLE:https://example.com
# BuildKit may prefix with "#5 0.123 ".
MARKER_RE = re.compile(
    r"^BB_FINDING:(?P<rule>BB-[A-Z0-9-]+):(?P<status>REACHABLE|BLOCKED|INFO)"
    r"(?::(?P<detail>[A-Za-z0-9_./:=+@% -]*))?$"
)
BUILDKIT_OUT = re.compile(r"^#\d+\s+[\d.]+\s+(.*)$")


def parse_markers(log: str) -> List[Tuple[str, str, str]]:
    hits: List[Tuple[str, str, str]] = []
    for line in log.splitlines():
        cleaned = line.strip()
        m_pref = BUILDKIT_OUT.match(cleaned)
        if m_pref:
            cleaned = m_pref.group(1).strip()
        # Skip the Dockerfile/RUN source lines that merely mention the marker.
        if (
            cleaned.startswith("RUN ")
            or cleaned.startswith("#")
            or "echo " in cleaned
            or "BB_FINDING:" not in cleaned
        ):
            # Allow pure marker lines through.
            if not cleaned.startswith("BB_FINDING:"):
                # Sometimes output is mid-line after a prompt; take from marker.
                idx = cleaned.find("BB_FINDING:")
                if idx < 0 or "echo " in cleaned or 'echo "' in line or "echo '" in line:
                    continue
                cleaned = cleaned[idx:]
        if not cleaned.startswith("BB_FINDING:"):
            continue
        # Truncate at first double-quote leftover from a source line slip-through.
        if '"' in cleaned:
            cleaned = cleaned.split('"', 1)[0]
        m = MARKER_RE.match(cleaned.strip())
        if m:
            hits.append((m.group("rule"), m.group("status"), (m.group("detail") or "").strip()))
    return hits


def _status_to_proof(status: str) -> str:
    return {"REACHABLE": "PROVEN", "BLOCKED": "BLOCKED", "INFO": "NA"}.get(status, "ERROR")


def findings_from_result(result: BuildResult) -> List[Finding]:
    meta = PROBE_BY_ID.get(result.probe_id, {})
    markers = parse_markers(result.log)
    # Keep only markers for this probe id.
    markers = [(r, s, d) for r, s, d in markers if r == result.probe_id]

    if not result.ok and not markers:
        log_l = result.log.lower()
        # Builder rejected RUN --security=insecure (unknown flag or missing entitlement).
        if result.probe_id == "BB-PRIV-INSECURE" and (
            "unknown flag: --security" in log_l
            or "insecure" in log_l and ("entitlement" in log_l or "not allowed" in log_l or "parse error" in log_l)
        ):
            return [
                Finding(
                    rule_id=result.probe_id,
                    title=meta.get("title", result.probe_id),
                    severity="info",
                    target=result.probe_id,
                    detail="security-insecure-not-honored-or-unsupported",
                    remediation=meta.get("remediation", ""),
                    refs=list(meta.get("refs") or []),
                    proof="BLOCKED",
                    evidence={"exit_code": result.exit_code, "duration_s": result.duration_s, "status": "BLOCKED"},
                    file=f"{result.probe_id.lower()}/Dockerfile",
                    line=1,
                )
            ]
        return [
            Finding(
                rule_id=result.probe_id,
                title=meta.get("title", result.probe_id),
                severity=meta.get("severity", "info"),
                target=result.probe_id,
                detail=f"build failed before markers: {result.error or result.exit_code}",
                remediation=meta.get("remediation", ""),
                refs=list(meta.get("refs") or []),
                proof="ERROR",
                evidence={"exit_code": result.exit_code, "duration_s": result.duration_s},
            )
        ]

    if meta.get("host_marker") and markers:
        markers = _judge_host_marker(result, markers)

    by_status: Dict[str, List[str]] = {"REACHABLE": [], "BLOCKED": [], "INFO": []}
    for _rule, status, detail in markers:
        by_status.setdefault(status, []).append(detail)

    primary_status: Optional[str] = None
    for cand in ("REACHABLE", "BLOCKED", "INFO"):
        if by_status.get(cand):
            primary_status = cand
            break

    if primary_status is None:
        return [
            Finding(
                rule_id=result.probe_id,
                title=meta.get("title", result.probe_id),
                severity=meta.get("severity", "info"),
                target=result.probe_id,
                detail="no BB_FINDING markers in build log",
                remediation=meta.get("remediation", ""),
                refs=list(meta.get("refs") or []),
                proof="ERROR",
                evidence={"exit_code": result.exit_code},
            )
        ]

    details = [d for d in by_status[primary_status] if d]
    info_details = [d for d in by_status.get("INFO", []) if d]
    # Dedup while preserving order
    def _uniq(xs: List[str]) -> List[str]:
        seen = set()
        out = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    details = _uniq(details)
    info_details = _uniq(info_details)
    detail_txt = "; ".join(details) if details else primary_status.lower()
    if info_details and primary_status != "INFO":
        detail_txt += " | info: " + "; ".join(info_details)

    refs = list(meta.get("refs") or [])
    severity = meta.get("severity", "info") if primary_status == "REACHABLE" else "info"
    if primary_status == "REACHABLE":
        for needle, sev in (meta.get("severity_escalation") or {}).items():
            if any(needle in d for d in details):
                severity = sev

    return [
        Finding(
            rule_id=result.probe_id,
            title=meta.get("title", result.probe_id),
            severity=severity,
            target=result.probe_id,
            detail=detail_txt,
            remediation=meta.get("remediation", ""),
            refs=refs,
            cves=list(refs),
            proof=_status_to_proof(primary_status),
            evidence={
                "status": primary_status,
                "markers": [
                    {"status": st, "detail": dt}
                    for st, lst in by_status.items()
                    for dt in _uniq(lst)
                ],
                "exit_code": result.exit_code,
                "duration_s": round(result.duration_s, 2),
                "image_tag": result.image_tag,
            },
            file=f"{result.probe_id.lower()}/Dockerfile",
            line=1,
        )
    ]


def _judge_host_marker(
    result: BuildResult, markers: List[Tuple[str, str, str]]
) -> List[Tuple[str, str, str]]:
    """Decide BB-PATH-ESCAPE from the host-side marker, not from the probe.

    The build only ever learns the marker file PATHS. PROVEN requires the
    random value BuildBreaker wrote on the host to appear in a marker line
    the build printed. Anything else is BLOCKED.
    """
    token = result.host_token
    out: List[Tuple[str, str, str]] = []
    proven_paths: List[str] = []
    for rule, status, detail in markers:
        if status == "INFO" and detail.startswith("read path=") and " value=" in detail:
            path_part, value = detail[len("read path="):].split(" value=", 1)
            if token and value.strip() == token:
                proven_paths.append(path_part)
            continue  # never echo marker values into the report
        out.append((rule, status, detail))
    if proven_paths:
        for pth in proven_paths:
            out.insert(0, (result.probe_id, "REACHABLE", f"host-marker-read path={pth}"))
    else:
        n = len(result.host_marker_paths)
        out.insert(
            0,
            (result.probe_id, "BLOCKED", f"host-marker-not-readable host_files={n}"),
        )
    return out


def attack_blurb(ref_id: str) -> Optional[str]:
    info = ATTACK_INFO.get(ref_id)
    if not info:
        return None
    return f"{ref_id} {info['name']}. {info['summary']} Mitigation: {info['fixed_in']}."
