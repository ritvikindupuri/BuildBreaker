import os

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


def test_host_markers_outside_context_and_cleaned(tmp_path):
    from buildbreaker.runner import plant_host_markers, remove_host_markers

    specs = generate(str(tmp_path), ["BB-PATH-ESCAPE"])
    ctx = specs[0].context_dir
    token, paths, cleanup = plant_host_markers(ctx)
    try:
        for pth in paths:
            assert open(pth).read().strip() == token
            assert not os.path.abspath(pth).startswith(os.path.abspath(ctx) + os.sep)
        # The random value is never handed to the build.
        assert token not in open(os.path.join(ctx, "Dockerfile")).read()
        assert token not in " ".join(specs[0].build_args.values())
    finally:
        remove_host_markers(cleanup)
    assert not any(os.path.exists(p) for p in paths)


def test_path_probes_do_not_treat_own_files_as_escape():
    df = PROBE_BY_ID["BB-PATH-ESCAPE"]["dockerfile_fn"]()
    assert "/etc/shadow \\" not in df and "BB_HOST_MARKER_PATHS" in df
    assert "--noproxy" in PROBE_BY_ID["BB-NET-INTERNAL"]["dockerfile_fn"]()
    assert PROBE_BY_ID["BB-PATH-PROC"]["severity"] == "medium"
