"""Probe catalog: every build-service attack class BuildBreaker can test.

Each probe emits a Dockerfile + context that prints BB_FINDING markers into
the build log. The runner parses those markers. Probes never exfiltrate
real secrets off the builder; they only report reachability to the operator.
"""

from __future__ import annotations

from typing import Dict, List

# Attack / advisory context referenced from findings and the technical doc.
ATTACK_INFO: Dict[str, Dict[str, str]] = {
    "SMITHERY-2025": {
        "name": "Smithery MCP build-path leak",
        "summary": (
            "A shared MCP build service exposed files outside the project "
            "build context, leaking a token with access to 3000+ servers "
            "(reported via GitGuardian)."
        ),
        "fixed_in": "builder-side path jail and per-tenant isolation",
    },
    "SHAI-HULUD-2": {
        "name": "Shai-Hulud 2.0 supply-chain build abuse",
        "summary": (
            "Malicious packages abuse install and build steps on CI runners "
            "to steal tokens and publish further poisoned packages."
        ),
        "fixed_in": "network-isolated builds, short-lived OIDC tokens, no long-lived secrets in build env",
    },
    "IMDS-BUILD": {
        "name": "Cloud metadata reachability during image build",
        "summary": (
            "If a builder can reach 169.254.169.254, a malicious Dockerfile "
            "can mint temporary cloud credentials from the instance role."
        ),
        "fixed_in": "block link-local ranges in the build network namespace",
    },
}


# Marker protocol printed by every probe Dockerfile.
# Format: BB_FINDING:<RULE_ID>:<STATUS>:<optional detail>
# STATUS is REACHABLE | BLOCKED | INFO


def _df_net_egress() -> str:
    return """\
# BuildBreaker probe: BB-NET-EGRESS
# Tests whether the build can reach an arbitrary external host.
# Safe: only fetches example.com headers; prints a marker; no payload.
FROM alpine:3.20
RUN apk add --no-cache curl >/dev/null 2>&1 \\
 || (apt-get update >/dev/null 2>&1 && apt-get install -y curl >/dev/null 2>&1) \\
 || true
RUN set -eu; \\
  if curl -sS -o /dev/null -m 5 -I https://example.com; then \\
    echo "BB_FINDING:BB-NET-EGRESS:REACHABLE:https://example.com"; \\
  else \\
    echo "BB_FINDING:BB-NET-EGRESS:BLOCKED:https://example.com"; \\
  fi
"""


def _df_meta_imds() -> str:
    return """\
# BuildBreaker probe: BB-META-IMDS
# Tests whether the build can reach cloud instance metadata (IMDS).
# Safe: only GETs the root path with a short timeout; never reads role creds
# into an external channel. Detail is truncated.
FROM alpine:3.20
RUN apk add --no-cache curl >/dev/null 2>&1 || true
RUN set -eu; \\
  code=$(curl -sS -o /tmp/imds.txt -w "%{http_code}" -m 3 \\
    -H "Metadata-Flavor: Google" \\
    http://169.254.169.254/ 2>/dev/null || echo 000); \\
  if [ "$code" != "000" ] && [ "$code" != "000000" ]; then \\
    head -c 80 /tmp/imds.txt >/tmp/imds.head 2>/dev/null || true; \\
    echo "BB_FINDING:BB-META-IMDS:REACHABLE:http_code=$code"; \\
  else \\
    echo "BB_FINDING:BB-META-IMDS:BLOCKED:link-local-unreachable"; \\
  fi
"""


def _df_secret_env() -> str:
    return """\
# BuildBreaker probe: BB-SECRET-ENV
# Tests whether build-args and environment variables are visible to RUN.
# Safe: only echoes the canary build-arg BB_CANARY_SECRET that BuildBreaker
# injects. Never prints real host secrets.
FROM alpine:3.20
ARG BB_CANARY_SECRET=missing
ARG BB_CANARY_TOKEN=missing
ENV BB_CANARY_ENV=from-dockerfile
RUN set -eu; \\
  echo "BB_FINDING:BB-SECRET-ENV:INFO:arg_present"; \\
  if [ "$BB_CANARY_SECRET" != "missing" ] && [ -n "$BB_CANARY_SECRET" ]; then \\
    # Print only a hash prefix so the raw canary never leaves the log as a secret lookalike
    echo "BB_FINDING:BB-SECRET-ENV:REACHABLE:build-arg-visible len=${#BB_CANARY_SECRET}"; \\
  else \\
    echo "BB_FINDING:BB-SECRET-ENV:BLOCKED:build-arg-not-visible"; \\
  fi; \\
  if [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] || [ -n "${GITHUB_TOKEN:-}" ] || [ -n "${NPM_TOKEN:-}" ]; then \\
    echo "BB_FINDING:BB-SECRET-ENV:REACHABLE:real-secret-env-names-present"; \\
  else \\
    echo "BB_FINDING:BB-SECRET-ENV:INFO:no-common-secret-env-names"; \\
  fi
"""


def _df_secret_file() -> str:
    return """\
# BuildBreaker probe: BB-SECRET-FILE
# Tests whether common secret mount paths are readable during the build.
# Safe: only checks existence and length; never prints file contents.
FROM alpine:3.20
RUN set -eu; \\
  hit=0; \\
  for p in \\
      /run/secrets/bb_canary \\
      /run/secrets/github_token \\
      /root/.docker/config.json \\
      /home/*/.docker/config.json \\
      /var/run/secrets/kubernetes.io/serviceaccount/token \\
      /var/run/docker.sock; do \\
    for f in $p; do \\
      if [ -e "$f" ]; then \\
        echo "BB_FINDING:BB-SECRET-FILE:REACHABLE:path=$f"; \\
        hit=1; \\
      fi; \\
    done; \\
  done; \\
  if [ "$hit" -eq 0 ]; then \\
    echo "BB_FINDING:BB-SECRET-FILE:BLOCKED:no-common-secret-paths"; \\
  fi
"""


def _df_path_proc() -> str:
    return """\
# BuildBreaker probe: BB-PATH-PROC
# Tests whether the build can read sensitive procfs entries (builder PID
# environ, root cwd). Safe: reports lengths and key names only.
FROM alpine:3.20
RUN set -eu; \\
  if [ -r /proc/1/environ ]; then \\
    n=$(tr "\\0" "\\n" < /proc/1/environ | wc -l); \\
    echo "BB_FINDING:BB-PATH-PROC:REACHABLE:proc1-environ-lines=$n"; \\
  else \\
    echo "BB_FINDING:BB-PATH-PROC:BLOCKED:proc1-environ"; \\
  fi; \\
  if [ -r /proc/self/cwd ]; then \\
    echo "BB_FINDING:BB-PATH-PROC:INFO:cwd=$(readlink /proc/self/cwd 2>/dev/null || echo unknown)"; \\
  fi; \\
  if [ -r /proc/1/root/etc/passwd ]; then \\
    echo "BB_FINDING:BB-PATH-PROC:REACHABLE:proc1-root-etc-passwd"; \\
  else \\
    echo "BB_FINDING:BB-PATH-PROC:BLOCKED:proc1-root"; \\
  fi
"""


def _df_path_escape() -> str:
    return """\
# BuildBreaker probe: BB-PATH-ESCAPE
# Smithery-class: can the build read host / builder files outside the
# build context? Safe: existence and size only; never dumps contents.
FROM alpine:3.20
COPY . /src
WORKDIR /src
RUN set -eu; \\
  hit=0; \\
  for p in \\
      /etc/passwd \\
      /etc/shadow \\
      /root/.ssh/id_rsa \\
      /home/*/.ssh/id_rsa \\
      /var/run/docker.sock \\
      /proc/1/root/etc/shadow \\
      /workspace \\
      /builder/home \\
      /kaniko \\
      /tekton \\
      /cloud-build \\
      /mnt/secrets \\
      /opt/buildagent/secrets; do \\
    for f in $p; do \\
      if [ -e "$f" ]; then \\
        if [ -d "$f" ]; then \\
          echo "BB_FINDING:BB-PATH-ESCAPE:REACHABLE:dir=$f"; \\
        else \\
          sz=$(wc -c < "$f" 2>/dev/null || echo 0); \\
          echo "BB_FINDING:BB-PATH-ESCAPE:REACHABLE:file=$f size=$sz"; \\
        fi; \\
        hit=1; \\
      fi; \\
    done; \\
  done; \\
  # Parent of the build context via relative path tricks (often blocked by BuildKit)
  if [ -e ../ ] || [ -e ../../ ]; then \\
    echo "BB_FINDING:BB-PATH-ESCAPE:INFO:parent-dirs-visible-from-workdir"; \\
  fi; \\
  if [ "$hit" -eq 0 ]; then \\
    echo "BB_FINDING:BB-PATH-ESCAPE:BLOCKED:no-extra-host-paths"; \\
  fi
"""


def _df_priv_caps() -> str:
    return """\
# BuildBreaker probe: BB-PRIV-CAPS
# Reports whether the build step runs as root with dangerous capabilities
# or sees a Docker socket. Safe: reads /proc only.
FROM alpine:3.20
RUN set -eu; \\
  uid=$(id -u); gid=$(id -g); \\
  echo "BB_FINDING:BB-PRIV-CAPS:INFO:uid=$uid gid=$gid"; \\
  if [ "$uid" = "0" ]; then \\
    echo "BB_FINDING:BB-PRIV-CAPS:REACHABLE:build-runs-as-root"; \\
  else \\
    echo "BB_FINDING:BB-PRIV-CAPS:BLOCKED:build-not-root uid=$uid"; \\
  fi; \\
  if [ -S /var/run/docker.sock ]; then \\
    echo "BB_FINDING:BB-PRIV-CAPS:REACHABLE:docker.sock-mounted"; \\
  else \\
    echo "BB_FINDING:BB-PRIV-CAPS:BLOCKED:no-docker.sock"; \\
  fi; \\
  if [ -r /proc/1/status ]; then \\
    cap=$(awk '/^CapEff:/{print $2}' /proc/1/status); \\
    echo "BB_FINDING:BB-PRIV-CAPS:INFO:CapEff=$cap"; \\
  fi
"""


def _df_priv_insecure() -> str:
    return """\
# BuildBreaker probe: BB-PRIV-INSECURE
# Tries RUN --security=insecure (BuildKit). If the builder honors it, the
# step can disable seccomp/AppArmor. Safe: only writes a marker file under /tmp.
# syntax=docker/dockerfile:1.6
FROM alpine:3.20
RUN --security=insecure set -eu; \\
  echo "BB_FINDING:BB-PRIV-INSECURE:REACHABLE:security-insecure-honored"; \\
  touch /tmp/bb-insecure-ok
# Fallback marker if the insecure RUN was rejected by the frontend:
# a normal RUN still executes and reports that the insecure form was not used.
RUN set -eu; \\
  if [ -f /tmp/bb-insecure-ok ]; then \\
    echo "BB_FINDING:BB-PRIV-INSECURE:INFO:confirmed"; \\
  else \\
    echo "BB_FINDING:BB-PRIV-INSECURE:BLOCKED:security-insecure-not-honored-or-unsupported"; \\
  fi
"""


def _df_cache_cross() -> str:
    return """\
# BuildBreaker probe: BB-CACHE-CROSS
# Writes a unique marker into a well-known shared cache path and reports
# whether pre-existing foreign markers are visible (cross-tenant smell).
# Safe: only touches /tmp and /var/cache paths inside the build.
FROM alpine:3.20
ARG BB_CACHE_TOKEN=none
RUN set -eu; \\
  mkdir -p /var/cache/buildbreaker /tmp/buildbreaker-cache; \\
  echo "$BB_CACHE_TOKEN" > /var/cache/buildbreaker/marker; \\
  echo "$BB_CACHE_TOKEN" > /tmp/buildbreaker-cache/marker; \\
  foreign=0; \\
  for f in /var/cache/buildbreaker/* /tmp/buildbreaker-cache/*; do \\
    [ -e "$f" ] || continue; \\
    val=$(cat "$f" 2>/dev/null || true); \\
    if [ -n "$val" ] && [ "$val" != "$BB_CACHE_TOKEN" ]; then \\
      echo "BB_FINDING:BB-CACHE-CROSS:REACHABLE:foreign-marker-in=$f"; \\
      foreign=1; \\
    fi; \\
  done; \\
  echo "BB_FINDING:BB-CACHE-CROSS:INFO:wrote-marker token_len=${#BB_CACHE_TOKEN}"; \\
  if [ "$foreign" -eq 0 ]; then \\
    echo "BB_FINDING:BB-CACHE-CROSS:BLOCKED:no-foreign-markers"; \\
  fi
"""


def _df_net_internal() -> str:
    return """\
# BuildBreaker probe: BB-NET-INTERNAL
# Tests reachability of common internal endpoints from the build.
# Safe: TCP connect probes with 2s timeout; no payloads.
FROM alpine:3.20
RUN apk add --no-cache curl busybox-extras >/dev/null 2>&1 || true
RUN set -eu; \\
  hit=0; \\
  for target in \\
      http://172.17.0.1:2375/ \\
      http://10.0.0.1/ \\
      http://192.168.1.1/ \\
      http://host.docker.internal/ \\
      http://metadata.google.internal/; do \\
    code=$(curl -sS -o /dev/null -w "%{http_code}" -m 2 "$target" 2>/dev/null || echo 000); \\
    if [ "$code" != "000" ] && [ "$code" != "000000" ]; then \\
      echo "BB_FINDING:BB-NET-INTERNAL:REACHABLE:target=$target code=$code"; \\
      hit=1; \\
    fi; \\
  done; \\
  if [ "$hit" -eq 0 ]; then \\
    echo "BB_FINDING:BB-NET-INTERNAL:BLOCKED:no-internal-hit"; \\
  fi
"""


# Catalog entries consumed by generator / CLI.
PROBES: List[Dict] = [
    {
        "id": "BB-NET-EGRESS",
        "title": "Arbitrary network egress during build",
        "category": "network",
        "severity": "high",
        "description": (
            "A malicious Dockerfile can phone home, pull second-stage "
            "payloads, or exfiltrate build secrets over the network while "
            "the image is being built."
        ),
        "remediation": (
            "Build with --network=none (or an allowlisted egress proxy). "
            "Deny outbound traffic from build pods at the CNI or egress gateway."
        ),
        "refs": ["SHAI-HULUD-2"],
        "dockerfile_fn": _df_net_egress,
        "network": "default",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-META-IMDS",
        "title": "Cloud metadata service reachable during build",
        "category": "network",
        "severity": "critical",
        "description": (
            "If the builder can reach 169.254.169.254, a Dockerfile can "
            "harvest instance-role credentials and move laterally in the cloud account."
        ),
        "remediation": (
            "Block link-local (169.254.0.0/16) from the build network namespace. "
            "Prefer workload identity / OIDC over instance roles on builders."
        ),
        "refs": ["IMDS-BUILD"],
        "dockerfile_fn": _df_meta_imds,
        "network": "default",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-SECRET-ENV",
        "title": "Build-arg and environment secrets visible to RUN",
        "category": "secrets",
        "severity": "high",
        "description": (
            "Classic ARG/ENV secrets are baked into image layers and visible "
            "to every RUN. Attackers who can submit a Dockerfile can read them."
        ),
        "remediation": (
            "Use BuildKit --secret mounts (not ARG) for credentials. "
            "Never pass long-lived tokens as build-args. Prefer short-lived OIDC."
        ),
        "refs": ["SHAI-HULUD-2"],
        "dockerfile_fn": _df_secret_env,
        "network": "none",
        "needs_canary_arg": True,
    },
    {
        "id": "BB-SECRET-FILE",
        "title": "Secret files and docker config readable during build",
        "category": "secrets",
        "severity": "high",
        "description": (
            "Mounted secret files, Kubernetes service-account tokens, or a "
            "host docker config give a malicious build credentials to registries and APIs."
        ),
        "remediation": (
            "Do not mount host docker configs or cluster SA tokens into "
            "untrusted builds. Use ephemeral BuildKit secret mounts scoped to one RUN."
        ),
        "refs": ["SMITHERY-2025", "SHAI-HULUD-2"],
        "dockerfile_fn": _df_secret_file,
        "network": "none",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-PATH-PROC",
        "title": "Sensitive procfs entries readable during build",
        "category": "path",
        "severity": "high",
        "description": (
            "Readable /proc/1/environ or /proc/1/root leaks builder "
            "environment variables and can open a path to the builder host root."
        ),
        "remediation": (
            "Run builds in a dedicated PID and mount namespace (rootless "
            "BuildKit or isolated build pods). Mask sensitive procfs paths."
        ),
        "refs": ["SMITHERY-2025"],
        "dockerfile_fn": _df_path_proc,
        "network": "none",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-PATH-ESCAPE",
        "title": "Host and builder paths readable outside build context",
        "category": "path",
        "severity": "critical",
        "description": (
            "Smithery-class failure: a build can see files outside its "
            "project context (host secrets, sibling tenant workspaces, builder home)."
        ),
        "remediation": (
            "Jail each build in its own mount namespace with only the project "
            "context mounted. Drop unnecessary hostPath volumes from build pods."
        ),
        "refs": ["SMITHERY-2025"],
        "dockerfile_fn": _df_path_escape,
        "network": "none",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-PRIV-CAPS",
        "title": "Build runs as root or with a Docker socket",
        "category": "privilege",
        "severity": "critical",
        "description": (
            "Root builds with a mounted docker.sock can escape to the builder "
            "host or start privileged sibling containers."
        ),
        "remediation": (
            "Use rootless BuildKit. Never mount docker.sock into untrusted "
            "builds. Drop capabilities and enable seccomp/AppArmor on build steps."
        ),
        "refs": ["SHAI-HULUD-2"],
        "dockerfile_fn": _df_priv_caps,
        "network": "none",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-PRIV-INSECURE",
        "title": "BuildKit RUN --security=insecure is honored",
        "category": "privilege",
        "severity": "high",
        "description": (
            "If the builder allows RUN --security=insecure, a Dockerfile can "
            "disable seccomp and AppArmor for that step."
        ),
        "remediation": (
            "Do not start BuildKit with --allow-insecure-entitlement security.insecure "
            "for untrusted tenants. Keep entitlements off by default."
        ),
        "refs": [],
        "dockerfile_fn": _df_priv_insecure,
        "network": "none",
        "needs_canary_arg": False,
    },
    {
        "id": "BB-CACHE-CROSS",
        "title": "Shared cache may expose foreign build markers",
        "category": "isolation",
        "severity": "medium",
        "description": (
            "Shared layer or cache directories across tenants can leak "
            "artifacts or enable cache poisoning."
        ),
        "remediation": (
            "Use per-tenant cache namespaces (BuildKit --opt, separate "
            "cache volumes, or cache backends with tenant prefixes)."
        ),
        "refs": ["SMITHERY-2025"],
        "dockerfile_fn": _df_cache_cross,
        "network": "none",
        "needs_canary_arg": True,
    },
    {
        "id": "BB-NET-INTERNAL",
        "title": "Internal network services reachable during build",
        "category": "network",
        "severity": "medium",
        "description": (
            "Builds that can reach the docker bridge gateway, metadata "
            "aliases, or RFC1918 services can attack infrastructure adjacent to the builder."
        ),
        "remediation": (
            "Put builders on an isolated network with no route to management "
            "planes. Block docker.sock TCP (2375) and host gateway access."
        ),
        "refs": [],
        "dockerfile_fn": _df_net_internal,
        "network": "default",
        "needs_canary_arg": False,
    },
]


PROBE_BY_ID: Dict[str, Dict] = {p["id"]: p for p in PROBES}

CATEGORIES = sorted({p["category"] for p in PROBES})
