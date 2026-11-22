"""SARIF 2.1.0 emitter for GitHub code scanning."""

from __future__ import annotations

import json
from typing import List

from .. import __version__
from ..models import Finding

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def generate(findings: List[Finding]) -> str:
    rules = {}
    results = []
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.detail or f.title},
                "defaultConfiguration": {"level": LEVEL.get(f.severity, "note")},
                "help": {"text": f.remediation or f.title},
            }
        level = LEVEL.get(f.severity, "note")
        if f.proof == "BLOCKED":
            level = "note"
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file or f"probes/{f.rule_id.lower()}/Dockerfile"},
                "region": {"startLine": f.line or 1},
            }
        }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f"{f.title}: {f.detail} [{f.proof}]"},
                "locations": [loc],
                "properties": {"proof": f.proof, "severity": f.severity, "refs": f.refs},
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BuildBreaker",
                        "version": __version__,
                        "informationUri": "https://github.com/ritvikindupuri/BuildBreaker",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
