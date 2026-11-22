import json

from buildbreaker.generators.sarif import generate as gen_sarif
from buildbreaker.models import Finding
from buildbreaker.report import render_json, render_text


def _sample():
    return [
        Finding(
            rule_id="BB-NET-EGRESS",
            title="Arbitrary network egress during build",
            severity="high",
            target="BB-NET-EGRESS",
            detail="https://example.com",
            remediation="Use --network=none",
            refs=["SHAI-HULUD-2"],
            proof="PROVEN",
            file="bb-net-egress/Dockerfile",
            line=1,
        ),
        Finding(
            rule_id="BB-META-IMDS",
            title="Cloud metadata service reachable during build",
            severity="info",
            target="BB-META-IMDS",
            detail="link-local-unreachable",
            proof="BLOCKED",
            file="bb-meta-imds/Dockerfile",
            line=1,
        ),
    ]


def test_render_text_has_verdict():
    text = render_text(_sample(), targets=["probe BB-NET-EGRESS"], builder="docker 28", profile="full", color=False)
    assert "BuildBreaker" in text
    assert "BUILD SURFACE EXPOSED" in text
    assert "BB-NET-EGRESS" in text
    assert "Safety" in text


def test_render_json_roundtrip():
    raw = render_json(_sample(), targets=["t"], builder="b", profile="quick")
    doc = json.loads(raw)
    assert doc["tool"] == "BuildBreaker"
    assert doc["verdict"] == "BUILD SURFACE EXPOSED"
    assert doc["proven"] == 1


def test_sarif_schema_shape():
    doc = json.loads(gen_sarif(_sample()))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "BuildBreaker"
    assert len(doc["runs"][0]["results"]) == 2
