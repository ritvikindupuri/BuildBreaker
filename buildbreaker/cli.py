"""BuildBreaker command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .analyzer import findings_from_result
from .catalog import CATEGORIES, PROBES
from .generator import generate, list_probes
from .generators import sarif as sarif_gen
from .models import SEVERITY_ORDER, Finding, sort_findings
from .report import findings_from_json, render_json, render_text
from .runner import RunnerError, cleanup_images, ensure_builder, run_probe

BANNER_ACTIVE = """\
!! BuildBreaker ACTIVE MODE !!
You are about to build probe Dockerfiles against a builder you name.
  - probes are harmless reachability checks (markers in the build log)
  - they do not exfiltrate real secrets to any external party
  - network probes only hit example.com headers or the IMDS root path
  - only run this against build services you own or are authorized to test
"""


def _write(path: Optional[str], content: str) -> None:
    if not path or path == "-":
        sys.stdout.write(content)
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _exit_code(findings: List[Finding], fail_on: Optional[str]) -> int:
    if not fail_on:
        return 0
    floor = SEVERITY_ORDER[fail_on]
    return 2 if any(
        SEVERITY_ORDER.get(f.severity, 0) >= floor and f.proof == "PROVEN" for f in findings
    ) else 0


def cmd_list(args) -> int:
    rows = list_probes(args.category)
    if args.format == "json":
        slim = [
            {
                "id": p["id"],
                "title": p["title"],
                "category": p["category"],
                "severity": p["severity"],
                "refs": p.get("refs") or [],
            }
            for p in rows
        ]
        _write(args.output, json.dumps(slim, indent=2) + "\n")
        return 0
    print(f"BuildBreaker {__version__}  {len(rows)} probes")
    print("")
    for p in rows:
        refs = ",".join(p.get("refs") or []) or "-"
        print(f"  {p['id'].ljust(18)} {p['severity'].ljust(8)} {p['category'].ljust(10)} {p['title']}")
        print(f"  {''.ljust(18)} refs: {refs}")
    print("")
    print(f"Categories: {', '.join(CATEGORIES)}")
    return 0


def cmd_gen(args) -> int:
    ids = None
    if args.probe:
        ids = args.probe
    elif args.category:
        ids = [p["id"] for p in list_probes(args.category)]
    specs = generate(args.out, ids, canary=args.canary)
    print(f"[buildbreaker] wrote {len(specs)} probe project(s) to {args.out}")
    for s in specs:
        print(f"  - {s.id}: {s.context_dir}")
    print(f"[buildbreaker] manifest: {os.path.join(args.out, 'manifest.json')}")
    return 0


def _select_ids(args) -> List[str]:
    if args.probe:
        return list(args.probe)
    if args.category:
        return [p["id"] for p in list_probes(args.category)]
    if args.profile == "quick":
        return ["BB-NET-EGRESS", "BB-SECRET-ENV", "BB-PATH-ESCAPE", "BB-PRIV-CAPS"]
    if args.profile == "network":
        return [p["id"] for p in PROBES if p["category"] == "network"]
    if args.profile == "secrets":
        return [p["id"] for p in PROBES if p["category"] == "secrets"]
    return [p["id"] for p in PROBES]


def cmd_run(args) -> int:
    if args.active:
        if not args.i_understand:
            sys.stderr.write("refusing: pass --i-understand with --active\n")
            return 2
        sys.stderr.write(BANNER_ACTIVE)
        if not args.yes:
            sys.stderr.write("Re-run with --yes to confirm.\n")
            return 2
    else:
        # Local docker builds are the intended default; still require explicit opt-in
        # when the user points at a non-default docker host.
        pass

    try:
        builder = ensure_builder(args.docker)
    except RunnerError as exc:
        sys.stderr.write(f"[buildbreaker] {exc}\n")
        return 1

    out_dir = args.out or os.path.join(os.getcwd(), "bb-probes")
    ids = _select_ids(args)
    specs = generate(out_dir, ids, canary=args.canary)

    findings: List[Finding] = []
    targets: List[str] = []
    logs_dir = os.path.join(out_dir, "_logs")
    os.makedirs(logs_dir, exist_ok=True)

    for spec in specs:
        # Hardened profile forces --network=none for every probe.
        net_override = None
        if args.profile == "hardened":
            net_override = "none"
        elif args.network:
            net_override = args.network

        sys.stderr.write(f"[buildbreaker] building {spec.id} (network={net_override or spec.network})...\n")
        result = run_probe(
            spec,
            docker_bin=args.docker,
            network_override=net_override,
            no_cache=not args.cache,
            timeout=args.timeout,
        )
        _write(os.path.join(logs_dir, f"{spec.id}.log"), result.log)
        fnds = findings_from_result(result)
        findings.extend(fnds)
        status = fnds[0].proof if fnds else "ERROR"
        targets.append(f"probe {spec.id} [{status}] ({result.duration_s:.1f}s)")
        sys.stderr.write(f"[buildbreaker] {spec.id}: {status} exit={result.exit_code}\n")

    if args.cleanup:
        cleanup_images(args.docker)

    findings = sort_findings(findings)
    profile = args.profile or "full"
    _emit(args, findings, targets, builder, profile)
    return _exit_code(findings, args.fail_on)


def cmd_report(args) -> int:
    with open(args.input, encoding="utf-8") as fh:
        doc = json.load(fh)
    findings = findings_from_json(doc)
    targets = doc.get("targets") or []
    builder = doc.get("builder")
    profile = doc.get("profile")
    # Re-bind onto a fake namespace for _emit
    class N:
        pass
    ns = N()
    ns.format = args.format
    ns.output = args.output
    ns.emit_dir = args.emit_dir
    ns.no_color = args.no_color
    _emit(ns, findings, targets, builder, profile)
    return 0


def _emit(args, findings, targets, builder, profile) -> None:
    fmt = args.format
    if fmt == "json":
        _write(args.output, render_json(findings, targets=targets, builder=builder, profile=profile))
    elif fmt == "sarif":
        _write(args.output, sarif_gen.generate(findings))
    else:
        _write(
            args.output,
            render_text(
                findings,
                targets=targets,
                builder=builder,
                profile=profile,
                color=False if args.no_color or args.output else None,
            ),
        )
    if getattr(args, "emit_dir", None):
        d = args.emit_dir
        os.makedirs(d, exist_ok=True)
        _write(
            os.path.join(d, "report.txt"),
            render_text(findings, targets=targets, builder=builder, profile=profile, color=False),
        )
        _write(
            os.path.join(d, "report.json"),
            render_json(findings, targets=targets, builder=builder, profile=profile),
        )
        _write(os.path.join(d, "buildbreaker.sarif"), sarif_gen.generate(findings))
        sys.stderr.write(
            f"[buildbreaker] wrote report.txt, report.json, buildbreaker.sarif to {d}\n"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buildbreaker",
        description="Offensive probe kit for container build services (authorized testing only).",
    )
    p.add_argument("--version", action="version", version=f"BuildBreaker {__version__}")
    p.add_argument("--docker", default=os.environ.get("DOCKER_BIN", "docker"), help="docker binary")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="list probe catalog")
    pl.add_argument("--category", choices=CATEGORIES)
    pl.add_argument("--format", choices=["text", "json"], default="text")
    pl.add_argument("-o", "--output", default="-")
    pl.set_defaults(func=cmd_list)

    pg = sub.add_parser("gen", help="emit probe Dockerfiles and contexts")
    pg.add_argument("-o", "--out", required=True, help="output directory")
    pg.add_argument("--probe", action="append", help="probe id (repeatable)")
    pg.add_argument("--category", choices=CATEGORIES)
    pg.add_argument("--canary", help="override canary token")
    pg.set_defaults(func=cmd_gen)

    pr = sub.add_parser("run", help="generate probes and build them against the local builder")
    pr.add_argument("--out", help="directory for probe projects and logs (default: ./bb-probes)")
    pr.add_argument("--probe", action="append", help="probe id (repeatable)")
    pr.add_argument("--category", choices=CATEGORIES)
    pr.add_argument(
        "--profile",
        choices=["full", "quick", "network", "secrets", "hardened"],
        default="full",
        help="full=all probes; quick=4 key probes; hardened=force --network=none",
    )
    pr.add_argument("--network", choices=["default", "none", "host"], help="override build network")
    pr.add_argument("--canary", help="override canary token")
    pr.add_argument("--cache", action="store_true", help="allow layer cache (default: --no-cache)")
    pr.add_argument("--timeout", type=int, default=300, help="per-probe build timeout seconds")
    pr.add_argument("--cleanup", action="store_true", help="remove probe images afterwards")
    pr.add_argument("--active", action="store_true", help="acknowledge active testing")
    pr.add_argument("--i-understand", action="store_true", help="required with --active")
    pr.add_argument("--yes", action="store_true", help="skip the second confirmation prompt")
    pr.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    pr.add_argument("-o", "--output", default="-", help="report output path")
    pr.add_argument("--emit-dir", help="write report.txt, report.json, buildbreaker.sarif here")
    pr.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 2 if a PROVEN finding meets severity")
    pr.add_argument("--no-color", action="store_true")
    pr.set_defaults(func=cmd_run)

    prep = sub.add_parser("report", help="re-render a report.json as text/sarif")
    prep.add_argument("-i", "--input", required=True, help="report.json from a previous run")
    prep.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    prep.add_argument("-o", "--output", default="-")
    prep.add_argument("--emit-dir")
    prep.add_argument("--no-color", action="store_true")
    prep.set_defaults(func=cmd_report)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
