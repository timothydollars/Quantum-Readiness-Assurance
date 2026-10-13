"""Acceptance tests for docs/QESM_SPEC.md, using the Exhibit E-1 worked example."""

import pytest

from qraf.qesm.score import (
    load_assets,
    load_config,
    priority,
    score_assets,
    tier,
    timeline_gap,
    timeline_score,
)
from qraf.qesm.sensitivity import horizon_sensitivity, weight_sensitivity


@pytest.fixture
def config(root):
    return load_config(root / "config" / "qesm_weights.yaml")


@pytest.fixture
def assets(root):
    return load_assets(root / "examples" / "qesm_assets_example.csv")


@pytest.mark.parametrize(
    "gap, expected",
    [(3, 5), (0, 5), (-1, 4), (-2, 4), (-3, 3), (-4, 3), (-5, 2), (-6, 2), (-7, 1), (-10, 1)],
)
def test_timeline_score_bands(gap, expected):
    assert timeline_score(gap) == expected


def test_gap():
    assert timeline_gap(5, 4, 9) == 0


def test_priority_and_tier(config):
    p = priority(5, 3, 5, 5, config["weights"])
    assert p == pytest.approx(4.50)
    assert tier(p, config["tier_thresholds"]) == 1
    assert tier(3.0, config["tier_thresholds"]) == 2
    assert tier(2.99, config["tier_thresholds"]) == 3


EXPECTED = {
    9: [("sftp-core-ach", 4.50, 1), ("tls-online-banking", 4.20, 1), ("backup-key-wrap", 3.70, 2), ("internal-ca", 2.50, 3)],
    4: [("tls-online-banking", 4.55, 1), ("sftp-core-ach", 4.50, 1), ("backup-key-wrap", 3.70, 2), ("internal-ca", 3.55, 2)],
    14: [("sftp-core-ach", 3.45, 2), ("backup-key-wrap", 3.35, 2), ("tls-online-banking", 3.15, 2), ("internal-ca", 2.15, 3)],
}


@pytest.mark.parametrize("horizon", [9, 4, 14])
def test_worked_example(assets, config, horizon):
    rows = score_assets(assets, config, horizon=horizon)
    got = [(r["asset_id"], r["P"], r["tier"]) for r in rows]
    assert [g[0] for g in got] == [e[0] for e in EXPECTED[horizon]]
    for (_, p, t), (_, ep, et) in zip(got, EXPECTED[horizon]):
        assert p == pytest.approx(ep)
        assert t == et


def test_default_horizon_is_9(assets, config):
    rows = score_assets(assets, config)
    assert rows[0]["asset_id"] == "sftp-core-ach"


def test_bad_row_rejected(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text(
        "asset_id,description,x_shelf_life_years,y_migration_years,e_exposure,c_criticality,d_dependency\n"
        "a1,test,5,2,9,3,3\n"
    )
    with pytest.raises(ValueError, match="e_exposure"):
        load_assets(bad)


def test_weights_must_sum_to_one(tmp_path):
    cfg = tmp_path / "w.yaml"
    cfg.write_text(
        "weights: {timeline: 0.5, exposure: 0.25, criticality: 0.25, dependency: 0.15}\n"
        "default_horizon_years: 9\nsensitivity_horizons: [4, 9, 14]\n"
        "tier_thresholds: {tier1_min: 4.0, tier2_min: 3.0}\n"
    )
    with pytest.raises(ValueError):
        load_config(cfg)


def test_horizon_sensitivity(assets, config):
    report = horizon_sensitivity(assets, config)
    assert report["tiers"]["internal-ca"] == {4: 2, 9: 3, 14: 3}
    assert report["changes_vs_default"] == {4: 1, 9: 0, 14: 2}


def test_weight_sensitivity_shape(assets, config):
    scenarios = weight_sensitivity(assets, config)
    assert len(scenarios) == 8
    for s in scenarios:
        assert sum(s["weights"].values()) == pytest.approx(1.0)
        assert s["direction"] in (1, -1)
        assert 0 <= s["tier_changes"] <= len(assets)
