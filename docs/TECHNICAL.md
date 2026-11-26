# BuildBreaker Technical Documentation

## Purpose

BuildBreaker is an offensive probe kit for **container build services** that compile other people's Dockerfiles on shared infrastructure. It generates harmless probe projects, builds them on a builder you control, and reports which attack surfaces are reachable during the build.

It is for authorized testing of builders you own (local Docker/BuildKit, CI runners, MCP build hosts, PaaS image builders). It is not a remote exploit kit and it does not exfiltrate real secrets.

## Threat model

An attacker who can submit a Dockerfile and build context to a shared builder may try to:

1. Read build-args, env vars, mounted secrets, or registry credentials.
2. Reach cloud instance metadata (IMDS) and mint temporary cloud credentials.
3. Read files outside the project build context (host paths, sibling tenant workspaces, builder home). This is the Smithery MCP class.
4. Open arbitrary egress during `RUN` to exfiltrate data or pull a second stage.
5. Abuse root, a mounted docker.sock, or BuildKit `security=insecure` to escape the build step.
6. Observe or poison a shared layer/cache store across tenants.

BuildBreaker encodes each of those as a probe that prints a marker when the step is reachable.

## Marker protocol

Every probe Dockerfile prints lines of the form:

```
BB_FINDING:<RULE_ID>:<STATUS>:<optional detail>
```

| STATUS | Meaning | Report proof tag |
| --- | --- | --- |
| REACHABLE | The attack surface was reachable | PROVEN |
| BLOCKED | The check ran and the surface was not reachable | BLOCKED |
| INFO | Extra context (uid, lengths, paths) | NA |

The runner captures the combined stdout/stderr of `docker build`. The analyzer strips BuildKit prefixes like `#6 1.485 ` and ignores Dockerfile source lines that merely contain the string `BB_FINDING` inside an `echo` command.

## Probe catalog

### BB-NET-EGRESS (high, network)

- **Tests:** `curl -I https://example.com` during `RUN`.
- **Why:** Malicious builds phone home or exfiltrate tokens (Shai-Hulud class).
- **Remediation:** `docker build --network=none`, or an allowlisted egress proxy / CNI deny.

### BB-META-IMDS (critical, network)

- **Tests:** HTTP GET to `http://169.254.169.254/` with a short timeout.
- **Why:** IMDS credentials let a build pivot into the cloud account.
- **Remediation:** Block `169.254.0.0/16` from the build netns. Prefer workload identity / OIDC.

### BB-SECRET-ENV (high, secrets)

- **Tests:** Visibility of a canary `ARG BB_CANARY_SECRET` injected by BuildBreaker. Also checks for common secret env names without printing values.
- **Why:** Classic ARG/ENV secrets land in image history and are readable to every RUN.
- **Remediation:** BuildKit `--secret` mounts, short-lived OIDC, never long-lived tokens as build-args.

### BB-SECRET-FILE (high, secrets)

- **Tests:** Existence of `/run/secrets/*`, `~/.docker/config.json`, K8s SA tokens, docker.sock.
- **Why:** Mounted credentials give registry and API access to a hostile build.
- **Remediation:** Do not mount host docker configs or cluster tokens into untrusted builds.

### BB-PATH-PROC (medium, path)

- **Tests:** Lists `/proc/*/comm` and looks for builder host daemons (`dockerd`, `containerd`, `buildkitd`, `systemd`, `sshd`, `kubelet`). Any hit is REACHABLE, because it means the build shares the host PID namespace. Reading `/proc/1/environ` is reported as INFO only: in a normal build, PID 1 is the build step's own shell, so its environment is the build's own, not the host's.
- **Why:** A shared PID namespace exposes host process names and opens a route to their environments and file descriptors.
- **Remediation:** Dedicated PID/mount namespaces; rootless BuildKit; mask sensitive procfs.

### BB-PATH-ESCAPE (critical, path)

- **Tests:** Before the build, the runner writes a random 32-character marker into two host files outside the build context: one in a fresh temp dir and one next to (not inside) the probe's context dir. Only the file paths are passed to the build (`BB_HOST_MARKER_PATHS`); the random value is not. The probe tries each path directly and through `/proc/1/root`, `/host`, `/rootfs`, and `../`. The analyzer marks PROVEN only if the exact random value appears in the build log; otherwise BLOCKED. Marker files are deleted after the build, pass or fail. The build image's own `/etc/passwd`, `/etc/shadow`, and `/proc/1/root` are not checked, because they belong to the image, not the host.
- **Why:** Smithery-class path leak across the build context boundary.
- **Remediation:** Per-build mount jail with only the project context mounted.

### BB-PRIV-CAPS (critical, privilege)

- **Tests:** uid/gid, CapEff, presence of `/var/run/docker.sock`.
- **Why:** Root + docker.sock is a host escape.
- **Remediation:** Rootless BuildKit; never mount docker.sock into untrusted builds.

### BB-PRIV-INSECURE (high, privilege)

- **Tests:** Whether `RUN --security=insecure` is accepted.
- **Why:** Disables seccomp/AppArmor for that step when the entitlement is enabled.
- **Remediation:** Do not start BuildKit with `--allow-insecure-entitlement security.insecure` for untrusted tenants. A parse/entitlement rejection is reported as BLOCKED.

### BB-CACHE-CROSS (medium, isolation)

- **Tests:** Writes a canary marker under `/var/cache/buildbreaker` and looks for foreign markers.
- **Why:** Shared caches can leak artifacts or enable cache poisoning across tenants.
- **Remediation:** Per-tenant cache namespaces / separate volumes.

### BB-NET-INTERNAL (low, network; critical if the Docker API answers)

- **Tests:** TCP connects (2s timeout, proxy settings ignored) to the build's default gateway on ports 22, 80, and 2375, plus `172.17.0.1:2375`, `10.0.0.1:80`, `192.168.1.1:80`, and `host.docker.internal:80`. curl exit codes 6, 7, and 28 (DNS failure, refused, timeout) mean not connected. A connect counts only if the address reached is private (RFC1918, loopback, link-local); a name that resolves to a public or special-use address is INFO. If port 2375 connects and `GET /version` returns `ApiVersion`, the finding is raised to critical (unauthenticated Docker API).
- **Why:** Builds that reach management planes can attack adjacent infrastructure.
- **Remediation:** Isolated builder network; block docker TCP 2375 and host gateway.

## CLI architecture

| Module | Role |
| --- | --- |
| `catalog.py` | Probe metadata and Dockerfile templates |
| `generator.py` | Writes probe projects + `manifest.json` + `CANARY.txt` |
| `runner.py` | Invokes `docker build`, captures logs, optional image cleanup |
| `analyzer.py` | Parses markers into `Finding` objects |
| `report.py` | Text and JSON rendering, verdict |
| `generators/sarif.py` | SARIF 2.1.0 for GitHub code scanning |
| `cli.py` | `list`, `gen`, `run`, `report` |

## Safety guarantees

1. **No third-party exfil channel.** Markers stay in the build log. Network probes only contact `example.com` (headers) or IMDS root.
2. **Canary secrets only.** The secret-env probe uses a random token BuildBreaker generates. It never reads and reprints real host secrets.
3. **Confirmation gate.** `run` in active mode requires `--active --i-understand --yes`.
4. **Authorized use.** Docs and the runtime banner state the tool is for systems you own or are authorized to test.
5. **Cleanup option.** `--cleanup` removes `buildbreaker-probe:*` images after the run.

## Output formats

### Text

Human report with Targets, Builder, Summary, Findings (severity + proof tag), Attack context, and Safety.

### JSON

```json
{
  "tool": "BuildBreaker",
  "version": "0.1.0",
  "verdict": "BUILD SURFACE EXPOSED",
  "proven": 4,
  "blocked": 6,
  "findings": [ ... ]
}
```

### SARIF 2.1.0

One result per finding. `properties.proof` carries PROVEN/BLOCKED. Blocked findings are emitted at SARIF level `note`.

## Verdict rules

| Verdict | Condition |
| --- | --- |
| BUILD SURFACE EXPOSED | Any PROVEN finding with severity critical or high |
| PARTIAL EXPOSURE | Any other PROVEN finding |
| INCOMPLETE | Errors and no PROVEN findings |
| HARDENED | Everything BLOCKED / NA |

## Limitations

- Reachability is not the same as successful theft. Operators still need to rotate anything that was actually exposed.
- Full cross-tenant cache proof needs two tenants on one shared cache backend; the single-build probe only detects pre-existing foreign markers.
- BB-PATH-ESCAPE checks BuildBreaker's own host marker files only. A builder that mounts a different host path into builds would need that path added to the probe.
- Windows builders are out of scope.

## Testing

```bash
pytest -q
```

20 unit tests cover catalog completeness, marker parsing (including BuildKit noise), report/SARIF shape, generate(), host marker planting and cleanup, the host-marker PROVEN/BLOCKED decision, and BB-NET-INTERNAL severity. Integration evidence lives under `examples/` from `./demo/run-demo.sh` on Kali with Docker 28.5.2.

## Attack advisory index

| Id | Name | Mitigation theme |
| --- | --- | --- |
| SMITHERY-2025 | Smithery MCP build-path leak | Path jail, per-tenant isolation |
| SHAI-HULUD-2 | Shai-Hulud 2.0 build-step abuse | Network isolation, short-lived OIDC |
| IMDS-BUILD | Cloud metadata during build | Block link-local from build netns |
