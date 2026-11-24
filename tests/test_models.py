import numpy as np
import pandas as pd
import pytest

from threatdet.config import load_config
from threatdet.data.synthetic import generate
from threatdet.models.detectors import RuleBaseline, ZScoreMax, design_matrix, load_features

pytest.importorskip("sklearn")
pytest.importorskip("torch")

FAST = {
    "evaluation.train_end_day": 6, "evaluation.n_bootstrap": 0,
    "models.iforest.n_estimators": 50, "models.autoencoder.epochs": 3,
    "models.supervised.max_iter": 20,
}


@pytest.fixture(scope="module")
def synth():
    out = generate(load_config(overrides={
        "synthetic.n_users": 60, "synthetic.n_days": 10, "synthetic.attack_days": [6, 7, 8, 9],
        "synthetic.n_compromised_users": 4, "synthetic.n_admin_users": 2}))
    return [",".join(map(str, r)) for r in out.auth], [",".join(map(str, r)) for r in out.redteam]


@pytest.fixture
def con(cfg_factory, run_pipeline, synth):
    return run_pipeline(cfg_factory(**FAST), *synth)


def test_detectors_refuse_label_columns(con):
    frame = load_features(con).assign(is_malicious=0)
    for det in (RuleBaseline(load_config()), ZScoreMax()):
        with pytest.raises(ValueError, match="label"):
            det.fit(frame)
    with pytest.raises(ValueError):
        design_matrix(frame)


def test_design_matrix_is_finite_with_missing_indicators(con):
    frame = load_features(con)
    X, names = design_matrix(frame)
    assert X.shape == (len(frame), len(names)) and np.isfinite(X).all()
    assert X[:, names.index("no_self_baseline")].tolist() == frame["n_events_z"].isna().astype(float).tolist()


def test_rules_hand_case():
    f = pd.DataFrame({
        "n_new_dst_hosts": [0, 3, 3], "n_fail": [0, 0, 9], "n_ntlm": [0, 1, 1],
        "n_ntlm_base_mean": [0.0, 0.0, 2.0], "n_off_hours": [0, 0, 4], "n_off_hours_base_mean": [0.0, 1.0, np.nan],
        "n_new_src_ntlm": [0, 0, 2],
    })
    v1 = RuleBaseline(load_config(overrides={"models.feature_set": "v1"}))
    assert v1.score(f).tolist() == [0, 2, 3]  # NaN baseline counts as "never"
    assert RuleBaseline(load_config()).score(f).tolist() == [0, 2, 4], "v2 adds ntlm_from_new_src"


def test_v1_design_matrix_excludes_novelty_features(con):
    frame = load_features(con)
    _, v1 = design_matrix(frame, "v1")
    _, v2 = design_matrix(frame, "v2")
    assert set(v2) - set(v1) == {"log1p_n_new_src_remote", "log1p_n_new_src_ntlm",
                                 "log1p_n_new_dst_remote", "log1p_n_new_pair_events"}


def test_run_end_to_end_and_unsupervised_scores_ignore_labels(cfg_factory, con):
    from threatdet.evaluate import run
    cfg = cfg_factory(**FAST)
    a = run(cfg, con, with_supervised=True, boot=False)
    assert a["meta"]["test_positives_total"] > 0 and a["meta"]["train_rows"] > 0
    for name, r in a["results"].items():
        assert 0 <= r["pr_auc"] <= 1, name
    # Scramble the labels: every unsupervised score must be bit-identical, the supervised one not.
    con.execute("""CREATE OR REPLACE TABLE labels.user_day AS
                   SELECT entity, (day + 3) % 10 AS day, n_redteam_events, is_malicious FROM labels.user_day""")
    b = run(cfg, con, with_supervised=True, boot=False)
    for name in ("rules", "zscore_max", "new_src_remote", "iforest", "autoencoder", "two_stage"):
        np.testing.assert_array_equal(a["scores"][name], b["scores"][name], err_msg=name)
    assert not np.array_equal(a["scores"]["supervised_ceiling"], b["scores"]["supervised_ceiling"])


def test_learned_detectors_are_reproducible(cfg_factory, con):
    from threatdet.models.detectors import AutoencoderDetector, IsolationForestDetector
    cfg = cfg_factory(**FAST)
    frame = load_features(con)
    train = frame[frame.day < 6]
    for cls in (IsolationForestDetector, AutoencoderDetector):
        s1 = cls(cfg).fit(train).score(frame)
        s2 = cls(cfg).fit(train).score(frame)
        np.testing.assert_allclose(s1, s2, err_msg=cls.__name__)


def test_two_stage_puts_every_gated_row_first_and_keeps_forest_order(cfg_factory, con):
    from threatdet.models.detectors import IsolationForestDetector, TwoStageDetector
    cfg = cfg_factory(**FAST)
    frame = load_features(con)
    train = frame[frame.day < 6]
    two = TwoStageDetector(cfg).fit(train)
    s, gate = two.score(frame), two.gate(frame)
    forest = IsolationForestDetector(cfg).fit(train).score(frame)
    assert gate.any() and (~gate).any()
    assert s[gate].min() > s[~gate].max(), "no ungated row outranks a gated one"
    for m in (gate, ~gate):  # within each stage, order is exactly the forest's
        np.testing.assert_array_equal(np.argsort(s[m], kind="stable"), np.argsort(forest[m], kind="stable"))


def test_holdout_window_and_train_before_test_supervised(cfg_factory, con):
    from threatdet.evaluate import run
    cfg = cfg_factory(**FAST, **{"evaluation.test_start_day": 8, "evaluation.test_end_day": 10,
                                 "evaluation.supervised_mode": "train_before_test"})
    out = run(cfg, con, boot=False)
    assert set(out["test"]["day"]) == {8, 9} and out["meta"]["test_days"] == "8-9"
    assert out["meta"]["train_rows"] == int((load_features(con).day < 6).sum()), "fit days unchanged"
    assert np.isfinite(out["scores"]["supervised_ceiling"]).all()
    with pytest.raises(ValueError, match="overlap"):
        run(cfg_factory(**FAST, **{"evaluation.test_start_day": 3}), con, boot=False)


def test_freeze_detects_any_method_change(tmp_path):
    from threatdet.freeze import fingerprint, verify
    for rel in ("src/threatdet/a.py", "sql/x.sql", "config/c.toml"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("v1\n")
    (tmp_path / "freeze.json").write_text(__import__("json").dumps({"files": fingerprint(tmp_path)}))
    verify(tmp_path / "freeze.json", tmp_path)                       # unchanged: passes
    (tmp_path / "sql/x.sql").write_bytes(b"v1\r\n")                  # line endings only: still passes
    verify(tmp_path / "freeze.json", tmp_path)
    (tmp_path / "config/c.toml").write_text("v2\n")
    with pytest.raises(SystemExit, match="config/c.toml"):
        verify(tmp_path / "freeze.json", tmp_path)
