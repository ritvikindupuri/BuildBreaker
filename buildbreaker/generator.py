"""Emit probe build projects (Dockerfile + context) to a directory."""

from __future__ import annotations

import json
import os
import secrets
from typing import Dict, Iterable, List, Optional

from .catalog import PROBE_BY_ID, PROBES
from .models import ProbeSpec


def list_probes(category: Optional[str] = None) -> List[Dict]:
    rows = PROBES
    if category:
        rows = [p for p in rows if p["category"] == category]
    return rows


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
        if not content.endswith("\n"):
            fh.write("\n")


def generate(
    out_dir: str,
    probe_ids: Optional[Iterable[str]] = None,
    *,
    canary: Optional[str] = None,
) -> List[ProbeSpec]:
    """Write one subdirectory per probe under out_dir. Returns ProbeSpec list."""
    os.makedirs(out_dir, exist_ok=True)
    canary = canary or secrets.token_hex(16)
    selected = list(probe_ids) if probe_ids else [p["id"] for p in PROBES]
    specs: List[ProbeSpec] = []
    manifest: List[Dict] = []

    for pid in selected:
        meta = PROBE_BY_ID.get(pid)
        if not meta:
            raise ValueError(f"unknown probe id: {pid}")
        ctx = os.path.join(out_dir, pid.lower())
        os.makedirs(ctx, exist_ok=True)
        df = meta["dockerfile_fn"]()
        _write(os.path.join(ctx, "Dockerfile"), df)
        # Tiny context file so COPY . works and the project looks real.
        _write(
            os.path.join(ctx, "README.probe"),
            f"BuildBreaker probe {pid}\n{meta['title']}\nSafe reachability probe. Do not use against systems you do not own.\n",
        )
        _write(os.path.join(ctx, ".dockerignore"), "# intentionally empty\n")

        build_args: Dict[str, str] = {}
        if meta.get("needs_canary_arg"):
            build_args["BB_CANARY_SECRET"] = canary
            build_args["BB_CANARY_TOKEN"] = canary
            build_args["BB_CACHE_TOKEN"] = canary

        spec = ProbeSpec(
            id=pid,
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            description=meta["description"],
            remediation=meta["remediation"],
            refs=list(meta.get("refs") or []),
            context_dir=ctx,
            dockerfile="Dockerfile",
            build_args=build_args,
            network=meta.get("network", "default"),
            markers={
                "REACHABLE": f"BB_FINDING:{pid}:REACHABLE",
                "BLOCKED": f"BB_FINDING:{pid}:BLOCKED",
                "INFO": f"BB_FINDING:{pid}:INFO",
            },
        )
        specs.append(spec)
        manifest.append(
            {
                "id": spec.id,
                "title": spec.title,
                "category": spec.category,
                "severity": spec.severity,
                "context_dir": os.path.relpath(ctx, out_dir),
                "network": spec.network,
                "build_args_keys": sorted(spec.build_args.keys()),
            }
        )

    _write(os.path.join(out_dir, "manifest.json"), json.dumps(manifest, indent=2))
    _write(
        os.path.join(out_dir, "CANARY.txt"),
        (
            "BuildBreaker canary token for this emit.\n"
            f"token={canary}\n"
            "This value is injected only as a build-arg for secret-visibility probes.\n"
            "It is not a real credential.\n"
        ),
    )
    return specs
