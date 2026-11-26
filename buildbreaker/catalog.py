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
# Tests whether the build step can see builder HOST processes through /proc.
# /proc/1 inside a normal build is the build step's own shell, so reading
# /proc/1/environ is reported as INFO only. The REACHABLE signal is a host
# process name (dockerd, containerd, buildkitd, systemd, sshd) showing up in
# /proc, which only happens when the build shares the host PID namespace.
# Safe: reads process names and line counts only; never prints values.
FROM alpine:3.20
RUN set -eu; \\
  if [ -r /proc/1/environ ]; then \\
    n=$(tr "\\0" "\\n" < /proc/1/environ | wc -l); \\
    c1=$(cat /proc/1/comm 2>/dev/null || echo unknown); \\
    echo "BB_FINDING:BB-PATH-PROC:INFO:own-pid1-environ-readable pid1=$c1 lines=$n"; \\
  fi; \\
  total=0; hostp=""; \\
  for d in /proc/[0-9]*; do \\
    [ -r "$d/comm" ] || continue; \\
    total=$((total+1)); \\
    c=$(cat "$d/comm" 2>/dev/null || true); \\
    case "$c" in \\
      dockerd|containerd|buildkitd|systemd|sshd|kubelet) \\
        case " $hostp " in *" $c "*) ;; *) hostp="$hostp $c";; esac;; \\
    esac; \\
  done; \\
  echo "BB_FINDING:BB-PATH-PROC:INFO:visible-processes=$total"; \\
  if [ -n "$hostp" ]; then \\
    echo "BB_FINDING:BB-PATH-PROC:REACHABLE:host-processes-visible names=$(echo $hostp | tr " " "+")"; \\
  else \\
    echo "BB_FINDING:BB-PATH-PROC:BLOCKED:no-host-processes-visible"; \\
  fi
"""


def _df_path_escape() -> str:
    return """\
# BuildBreaker probe: BB-PATH-ESCAPE
# Smithery-class: can the build read a file on the builder HOST that sits
# outside the build context? Before the build, BuildBreaker writes a random
# marker file on the host (a temp dir and the parent of the build context)
# and passes only the file PATHS in BB_HOST_MARKER_PATHS. The random value
# itself is never given to the build. If the value shows up in the build
# log, the build really read a host file. The build container's own
# /etc/passwd, /etc/shadow and /proc/1/root are NOT checked, because those
# belong to the build image, not the host.
# Safe: prints at most the first 64 bytes of BuildBreaker's own marker file.
FROM alpine:3.20
ARG BB_HOST_MARKER_PATHS=""
COPY . /src
WORKDIR /src
RUN set -eu; \\
  tried=0; \\
  for p in $BB_HOST_MARKER_PATHS; do \\
    b=$(basename "$p"); \\
    for c in "$p" "/proc/1/root$p" "/host$p" "/rootfs$p" "../$b" "../../$b"; do \\
      tried=$((tried+1)); \\
      if [ -r "$c" ] && [ -f "$c" ]; then \\
        v=$(head -c 64 "$c" | tr -cd "A-Za-z0-9"); \\
        echo "BB_FINDING:BB-PATH-ESCAPE:INFO:read path=$c value=$v"; \\
      fi; \\
    done; \\
  done; \\
  echo "BB_FINDING:BB-PATH-ESCAPE:INFO:host-marker-paths-tried=$tried"
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
# Tests whether the build can open a TCP connection to internal endpoints:
# the default gateway, the docker bridge, common RFC1918 routers and
# host.docker.internal. Proxy settings are ignored (--noproxy) so a proxy
# error page is never mistaken for reachability. curl exit codes 6, 7 and 28
# (DNS failure, connection refused, timeout) mean NOT connected; any other
# result means the TCP handshake completed. A connect only counts when the
# address curl actually reached is private (RFC1918, loopback, link-local);
# a name that resolves to a public or special-use address is reported as
# INFO. Port 2375 is also checked for an
# unauthenticated Docker API (GET /version returning "ApiVersion").
# Safe: connect plus one GET with 2s timeouts; no payloads.
FROM alpine:3.20
RUN apk add --no-cache curl >/dev/null 2>&1 || true
RUN set -eu; \\
  if ! command -v curl >/dev/null 2>&1; then \\
    echo "BB_FINDING:BB-NET-INTERNAL:BLOCKED:curl-unavailable-no-network"; exit 0; \\
  fi; \\
  h=$(awk '$2=="00000000"{print $3; exit}' /proc/net/route 2>/dev/null || true); \\
  gw=""; \\
  if [ -n "$h" ]; then \\
    set -- $(echo "$h" | sed 's/\\(..\\)\\(..\\)\\(..\\)\\(..\\)/\\4 \\3 \\2 \\1/'); \\
    gw=$(printf "%d.%d.%d.%d" "0x$1" "0x$2" "0x$3" "0x$4"); \\
  fi; \\
  targets="172.17.0.1:2375 10.0.0.1:80 192.168.1.1:80 host.docker.internal:80"; \\
  if [ -n "$gw" ]; then targets="$gw:22 $gw:80 $gw:2375 $targets"; fi; \\
  hit=0; \\
  for t in $targets; do \\
    rc=0; ip=$(curl -sS --noproxy "*" -o /dev/null -m 2 -w "%{remote_ip}" "http://$t/" 2>/dev/null) || rc=$?; \\
    case "$rc" in 6|7|28) continue;; esac; \\
    case "$ip" in \\
      10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|127.*|169.254.*) ;; \\
      *) echo "BB_FINDING:BB-NET-INTERNAL:INFO:connected-but-not-private target=$t ip=$ip"; continue;; \\
    esac; \\
    case "$rc" in \\
      *) echo "BB_FINDING:BB-NET-INTERNAL:REACHABLE:tcp-connect-ok target=$t ip=$ip"; hit=1; \\
         case "$t" in *:2375) \\
           if curl -sS --noproxy "*" -m 2 "http://$t/version" 2>/dev/null | grep -q ApiVersion; then \\
             echo "BB_FINDING:BB-NET-INTERNAL:REACHABLE:docker-api-unauthenticated target=$t"; \\
           fi;; \\
         esac;; \\
    esac; \\
  done; \\
  if [ "$hit" -eq 0 ]; then \\
    echo "BB_FINDING:BB-NET-INTERNAL:BLOCKED:no-private-tcp-connect"; \\
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
        "title": "Builder host processes visible through /proc during build",
        "category": "path",
        "severity": "medium",
        "description": (
            "If the build shares the builder host's PID namespace, /proc lists "
            "host daemons (dockerd, containerd, sshd) and their environments. "
            "Reading /proc/1/environ alone is not a leak: in a normal build, "
            "PID 1 is the build step's own shell."
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
        "title": "Host file outside the build context readable during build",
        "category": "path",
        "severity": "critical",
        "description": (
            "Smithery-class failure: a build can read files on the builder "
            "host outside its project context. Proven only when the build "
            "prints a random marker that BuildBreaker wrote on the host."
        ),
        "remediation": (
            "Jail each build in its own mount namespace with only the project "
            "context mounted. Drop unnecessary hostPath volumes from build pods."
        ),
        "refs": ["SMITHERY-2025"],
        "dockerfile_fn": _df_path_escape,
        "network": "none",
        "needs_canary_arg": False,
        "host_marker": True,
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
        "title": "Internal TCP endpoints reachable during build",
        "category": "network",
        "severity": "low",
        "description": (
            "A completed TCP connection from the build to the gateway, docker "
            "bridge or RFC1918 hosts shows the build can talk to infrastructure "
            "next to the builder. Connect alone is low; an unauthenticated "
            "Docker API on port 2375 raises it to critical."
        ),
        "remediation": (
            "Put builders on an isolated network with no route to management "
            "planes. Block docker.sock TCP (2375) and host gateway access."
        ),
        "refs": [],
        "dockerfile_fn": _df_net_internal,
        "network": "default",
        "needs_canary_arg": False,
        "severity_escalation": {"docker-api-unauthenticated": "critical"},
    },
]


PROBE_BY_ID: Dict[str, Dict] = {p["id"]: p for p in PROBES}

CATEGORIES = sorted({p["category"] for p in PROBES})
