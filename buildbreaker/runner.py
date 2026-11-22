"""Run probe builds against a local Docker / BuildKit builder and collect logs."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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
    tag = f"{tag_prefix}:{spec.id.lower()}"
    network = network_override if network_override is not None else spec.network
    args: List[str] = ["build"]
    if no_cache:
        args.append("--no-cache")
    if network and network != "default":
        args.extend(["--network", network])
    for k, v in spec.build_args.items():
        args.extend(["--build-arg", f"{k}={v}"])
    args.extend(["-t", tag, "-f", os.path.join(spec.context_dir, spec.dockerfile), spec.context_dir])

    t0 = time.time()
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
        )
    except FileNotFoundError as exc:
        raise RunnerError(f"docker binary not found: {docker_bin}") from exc


def cleanup_images(docker_bin: str, tag_prefix: str = "buildbreaker-probe") -> None:
    proc = _docker(docker_bin, ["images", "-q", "--filter", f"reference={tag_prefix}:*"], timeout=60)
    ids = [x for x in proc.stdout.decode().split() if x]
    if ids:
        _docker(docker_bin, ["rmi", "-f", *ids], timeout=120)
