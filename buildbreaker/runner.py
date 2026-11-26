"""Run probe builds against a local Docker / BuildKit builder and collect logs."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import ProbeSpec


@dataclass
class BuildResult:
    probe_id: str
    ok: bool
    exit_code: int
    log: str
    duration_s: float
    command: List[str] = field(default_factory=list)
    image_tag: str = ""
    error: str = ""
    # Random value written to host-side marker files for BB-PATH-ESCAPE.
    # Never passed to the build; the analyzer looks for it in the log.
    host_token: str = ""
    host_marker_paths: List[str] = field(default_factory=list)


def plant_host_markers(context_dir: str) -> Tuple[str, List[str], List[str]]:
    """Write a random marker file on the host, outside the build context.

    Returns (token, marker_file_paths, paths_to_remove). One marker goes in a
    fresh temp dir; one goes in the parent of the build context (a sibling
    of the context, so it is never part of what docker sends to the builder).
    """
    token = secrets.token_hex(16)
    name = f"bb-host-marker-{secrets.token_hex(4)}.txt"
    tmpdir = tempfile.mkdtemp(prefix="bb-host-marker-")
    p1 = os.path.join(tmpdir, name)
    p2 = os.path.join(os.path.dirname(os.path.abspath(context_dir)), name)
    for path in (p1, p2):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
    return token, [p1, p2], [tmpdir, p2]


def remove_host_markers(paths: List[str]) -> None:
    for path in paths:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.remove(path)


class RunnerError(RuntimeError):
    pass


def _docker(docker_bin: str, args: List[str], *, timeout: int = 300) -> subprocess.CompletedProcess:
    cmd = [docker_bin, *args]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def ensure_builder(docker_bin: str = "docker") -> str:
    """Return a short builder identity string for the report."""
    try:
        ver = _docker(docker_bin, ["version", "--format", "{{.Server.Version}}"], timeout=30)
        bx = _docker(docker_bin, ["buildx", "version"], timeout=30)
        engine = ver.stdout.decode(errors="replace").strip() if ver.returncode == 0 else "?"
        buildx = bx.stdout.decode(errors="replace").splitlines()[0] if bx.returncode == 0 else "no-buildx"
        return f"docker {engine}; {buildx}"
    except Exception as exc:  # noqa: BLE001
        raise RunnerError(f"docker not usable: {exc}") from exc


def run_probe(
    spec: ProbeSpec,
    *,
    docker_bin: str = "docker",
    network_override: Optional[str] = None,
    tag_prefix: str = "buildbreaker-probe",
    no_cache: bool = True,
    timeout: int = 300,
) -> BuildResult:
    """Build one probe project and return the combined build log."""
    from .catalog import PROBE_BY_ID

    tag = f"{tag_prefix}:{spec.id.lower()}"
    build_args = dict(spec.build_args)
    host_token = ""
    marker_paths: List[str] = []
    cleanup_paths: List[str] = []
    if PROBE_BY_ID.get(spec.id, {}).get("host_marker"):
        host_token, marker_paths, cleanup_paths = plant_host_markers(spec.context_dir)
        # Only the PATHS go to the build, never the random value.
        build_args["BB_HOST_MARKER_PATHS"] = " ".join(marker_paths)
    network = network_override if network_override is not None else spec.network
    args: List[str] = ["build"]
    if no_cache:
        args.append("--no-cache")
    if network and network != "default":
        args.extend(["--network", network])
    for k, v in build_args.items():
        args.extend(["--build-arg", f"{k}={v}"])
    args.extend(["-t", tag, "-f", os.path.join(spec.context_dir, spec.dockerfile), spec.context_dir])

    t0 = time.time()
    try:
        return _run(docker_bin, args, tag, spec, t0, timeout, host_token, marker_paths)
    finally:
        remove_host_markers(cleanup_paths)


def _run(docker_bin, args, tag, spec, t0, timeout, host_token, marker_paths) -> BuildResult:
    try:
        proc = _docker(docker_bin, args, timeout=timeout)
        log = proc.stdout.decode(errors="replace")
        return BuildResult(
            probe_id=spec.id,
            ok=proc.returncode == 0,
            exit_code=proc.returncode,
            log=log,
            duration_s=time.time() - t0,
            command=[docker_bin, *args],
            image_tag=tag if proc.returncode == 0 else "",
            error="" if proc.returncode == 0 else f"docker build exit {proc.returncode}",
            host_token=host_token,
            host_marker_paths=marker_paths,
        )
    except subprocess.TimeoutExpired as exc:
        log = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, (bytes, bytearray)) else ""
        return BuildResult(
            probe_id=spec.id,
            ok=False,
            exit_code=124,
            log=log,
            duration_s=time.time() - t0,
            command=[docker_bin, *args],
            error=f"timeout after {timeout}s",
            host_token=host_token,
            host_marker_paths=marker_paths,
        )
    except FileNotFoundError as exc:
        raise RunnerError(f"docker binary not found: {docker_bin}") from exc


def cleanup_images(docker_bin: str, tag_prefix: str = "buildbreaker-probe") -> None:
    proc = _docker(docker_bin, ["images", "-q", "--filter", f"reference={tag_prefix}:*"], timeout=60)
    ids = [x for x in proc.stdout.decode().split() if x]
    if ids:
        _docker(docker_bin, ["rmi", "-f", *ids], timeout=120)
