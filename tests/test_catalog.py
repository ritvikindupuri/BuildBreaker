from buildbreaker.catalog import PROBE_BY_ID, PROBES
from buildbreaker.generator import generate


def test_probe_ids_unique():
    ids = [p["id"] for p in PROBES]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 8


def test_every_probe_has_dockerfile():
    for p in PROBES:
        df = p["dockerfile_fn"]()
        assert "BB_FINDING:" in df
        assert p["id"] in df
        assert "FROM " in df


def test_generate_writes_manifest(tmp_path):
    specs = generate(str(tmp_path), ["BB-NET-EGRESS", "BB-SECRET-ENV"])
    assert len(specs) == 2
    assert (tmp_path / "manifest.json").exists()
    assert (tmp_path / "bb-net-egress" / "Dockerfile").exists()
    assert (tmp_path / "bb-secret-env" / "Dockerfile").exists()
    assert (tmp_path / "CANARY.txt").exists()


def test_unknown_probe_raises(tmp_path):
    try:
        generate(str(tmp_path), ["BB-NOPE"])
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "unknown probe" in str(exc)
