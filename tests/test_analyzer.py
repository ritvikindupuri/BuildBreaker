from buildbreaker.analyzer import findings_from_result, parse_markers
from buildbreaker.runner import BuildResult


def test_parse_markers_strips_buildkit_prefix():
    log = """\
#5 [3/3] RUN set -eu; echo "BB_FINDING:BB-NET-EGRESS:REACHABLE:https://example.com"; else echo "BB_FINDING:BB-NET-EGRESS:BLOCKED:x"; fi
#5 0.123 BB_FINDING:BB-NET-EGRESS:REACHABLE:https://example.com
#5 0.200 BB_FINDING:BB-NET-EGRESS:INFO:extra
something else
"""
    hits = parse_markers(log)
    assert hits == [
        ("BB-NET-EGRESS", "REACHABLE", "https://example.com"),
        ("BB-NET-EGRESS", "INFO", "extra"),
    ]


def test_parse_path_escape_real_log():
    log = """\
#8 [4/4] RUN set -eu; echo "BB_FINDING:BB-PATH-ESCAPE:INFO:read path=$c value=$v";
#8 0.401 BB_FINDING:BB-PATH-ESCAPE:INFO:read path=/tmp/x/m.txt value=abc123
#8 0.426 BB_FINDING:BB-PATH-ESCAPE:INFO:host-marker-paths-tried=12
"""
    hits = parse_markers(log)
    assert hits[0] == ("BB-PATH-ESCAPE", "INFO", "read path=/tmp/x/m.txt value=abc123")
    assert hits[-1] == ("BB-PATH-ESCAPE", "INFO", "host-marker-paths-tried=12")


def _escape_result(log, token="a" * 32):
    return BuildResult(
        probe_id="BB-PATH-ESCAPE",
        ok=True,
        exit_code=0,
        log=log,
        duration_s=1.0,
        host_token=token,
        host_marker_paths=["/tmp/bb-host-marker-1/m.txt", "/out/m.txt"],
    )


def test_path_escape_proven_only_with_host_marker_value():
    token = "f" * 32
    log = (
        f"#8 0.4 BB_FINDING:BB-PATH-ESCAPE:INFO:read path=/proc/1/root/tmp/m.txt value={token}\n"
        "#8 0.5 BB_FINDING:BB-PATH-ESCAPE:INFO:host-marker-paths-tried=12\n"
    )
    f = findings_from_result(_escape_result(log, token))[0]
    assert f.proof == "PROVEN"
    assert f.severity == "critical"
    assert "host-marker-read path=/proc/1/root/tmp/m.txt" in f.detail
    assert token not in f.detail


def test_path_escape_blocked_without_marker():
    log = "#8 0.5 BB_FINDING:BB-PATH-ESCAPE:INFO:host-marker-paths-tried=12\n"
    f = findings_from_result(_escape_result(log))[0]
    assert f.proof == "BLOCKED"
    assert f.severity == "info"
    assert "host-marker-not-readable" in f.detail


def test_path_escape_wrong_value_is_blocked():
    # A same-named file inside the build image is not the host marker.
    log = (
        "#8 0.4 BB_FINDING:BB-PATH-ESCAPE:INFO:read path=../m.txt value=notthetoken\n"
        "#8 0.5 BB_FINDING:BB-PATH-ESCAPE:INFO:host-marker-paths-tried=12\n"
    )
    f = findings_from_result(_escape_result(log))[0]
    assert f.proof == "BLOCKED"
    assert "notthetoken" not in f.detail


def test_path_proc_own_environ_is_not_a_leak():
    result = BuildResult(
        probe_id="BB-PATH-PROC",
        ok=True,
        exit_code=0,
        log=(
            "#5 0.1 BB_FINDING:BB-PATH-PROC:INFO:own-pid1-environ-readable pid1=sh lines=2\n"
            "#5 0.2 BB_FINDING:BB-PATH-PROC:INFO:visible-processes=2\n"
            "#5 0.3 BB_FINDING:BB-PATH-PROC:BLOCKED:no-host-processes-visible\n"
        ),
        duration_s=0.5,
    )
    f = findings_from_result(result)[0]
    assert f.proof == "BLOCKED"
    assert f.severity == "info"


def test_net_internal_connect_is_low_and_docker_api_is_critical():
    base = dict(probe_id="BB-NET-INTERNAL", ok=True, exit_code=0, duration_s=1.0)
    connect = BuildResult(
        log="#6 0.1 BB_FINDING:BB-NET-INTERNAL:REACHABLE:tcp-connect-ok target=10.0.2.2:22\n", **base
    )
    f = findings_from_result(connect)[0]
    assert f.proof == "PROVEN" and f.severity == "low"
    api = BuildResult(
        log=(
            "#6 0.1 BB_FINDING:BB-NET-INTERNAL:REACHABLE:tcp-connect-ok target=172.17.0.1:2375\n"
            "#6 0.2 BB_FINDING:BB-NET-INTERNAL:REACHABLE:docker-api-unauthenticated target=172.17.0.1:2375\n"
        ),
        **base,
    )
    assert findings_from_result(api)[0].severity == "critical"


def test_findings_reachable():
    result = BuildResult(
        probe_id="BB-NET-EGRESS",
        ok=True,
        exit_code=0,
        log="#6 1.4 BB_FINDING:BB-NET-EGRESS:REACHABLE:https://example.com\n",
        duration_s=1.2,
        image_tag="buildbreaker-probe:bb-net-egress",
    )
    fnds = findings_from_result(result)
    assert len(fnds) == 1
    assert fnds[0].proof == "PROVEN"
    assert fnds[0].severity == "high"
    assert "example.com" in fnds[0].detail
    assert "echo" not in fnds[0].detail


def test_findings_blocked_severity_info():
    result = BuildResult(
        probe_id="BB-META-IMDS",
        ok=True,
        exit_code=0,
        log="#6 0.1 BB_FINDING:BB-META-IMDS:BLOCKED:link-local-unreachable\n",
        duration_s=0.5,
    )
    fnds = findings_from_result(result)
    assert fnds[0].proof == "BLOCKED"
    assert fnds[0].severity == "info"


def test_findings_build_error():
    result = BuildResult(
        probe_id="BB-PRIV-INSECURE",
        ok=False,
        exit_code=1,
        log="error: failed to solve\n",
        duration_s=0.1,
        error="docker build exit 1",
    )
    fnds = findings_from_result(result)
    assert fnds[0].proof == "ERROR"


def test_insecure_rejected_is_blocked():
    result = BuildResult(
        probe_id="BB-PRIV-INSECURE",
        ok=False,
        exit_code=1,
        log="ERROR: failed to build: dockerfile parse error on line 6: unknown flag: --security\n",
        duration_s=0.2,
        error="docker build exit 1",
    )
    fnds = findings_from_result(result)
    assert fnds[0].proof == "BLOCKED"
    assert fnds[0].severity == "info"
