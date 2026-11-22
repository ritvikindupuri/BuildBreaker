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
#8 [4/4] RUN set -eu; echo "BB_FINDING:BB-PATH-ESCAPE:REACHABLE:dir=$f";
#8 0.401 BB_FINDING:BB-PATH-ESCAPE:REACHABLE:file=/etc/passwd size=702
#8 0.412 BB_FINDING:BB-PATH-ESCAPE:REACHABLE:file=/etc/shadow size=260
#8 0.426 BB_FINDING:BB-PATH-ESCAPE:INFO:parent-dirs-visible-from-workdir
"""
    hits = parse_markers(log)
    assert hits[0] == ("BB-PATH-ESCAPE", "REACHABLE", "file=/etc/passwd size=702")
    assert hits[-1][1] == "INFO"


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
