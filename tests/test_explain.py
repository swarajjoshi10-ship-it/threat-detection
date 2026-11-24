import json

import numpy as np
import pytest

from threatdet.config import REPO_ROOT, load_config
from threatdet.data.synthetic import generate
from threatdet.models.detectors import TwoStageDetector, load_features

pytest.importorskip("sklearn")
pytest.importorskip("shap")

from triage.explain import AlertExplainer, base_column, deletion_check, evidence, run, top_alerts  # noqa: E402

FAST = {"evaluation.train_end_day": 6, "models.iforest.n_estimators": 50}


@pytest.fixture(scope="module")
def synth():
    out = generate(load_config(overrides={
        "synthetic.n_users": 60, "synthetic.n_days": 10, "synthetic.attack_days": [6, 7, 8, 9],
        "synthetic.n_compromised_users": 4, "synthetic.n_admin_users": 2}))
    return [",".join(map(str, r)) for r in out.auth], [",".join(map(str, r)) for r in out.redteam]


@pytest.fixture
def fitted(cfg_factory, run_pipeline, synth):
    cfg = cfg_factory(**FAST)
    con = run_pipeline(cfg, *synth)
    frame = load_features(con)
    train, test = frame[frame.day < 6], frame[frame.day >= 6].reset_index(drop=True)
    return cfg, con, train, test, TwoStageDetector(cfg).fit(train.copy())


def test_shap_reconstructs_the_forest_score_exactly(fitted):
    _, _, _, test, det = fitted
    ex = AlertExplainer(det)
    phi, base = ex.shap_values(test)
    np.testing.assert_allclose(ex.forest_score_from_shap(phi, base), det.ranker.score(test), rtol=0, atol=1e-9)


def test_explainer_refuses_label_columns(fitted):
    _, _, _, test, det = fitted
    with pytest.raises(ValueError, match="label"):
        AlertExplainer(det).explain(test.assign(is_malicious=0))


def test_evidence_packs_are_label_free_and_match_the_gate(fitted):
    _, _, _, test, det = fitted
    packs, err = AlertExplainer(det).explain(test.head(30), top_k=3)
    assert err < 1e-9 and len(packs) == 30
    blob = json.dumps(packs).lower()
    assert not any(b in blob for b in ("malicious", "redteam", "label")), "packs go to the LLM; no labels"
    gate = det.gate(test.head(30))
    assert [p["gate"]["passed"] for p in packs] == gate.tolist()
    for p in packs:
        pushes = [f["push"] for f in p["top_factors"]]
        assert pushes == sorted(pushes, reverse=True) and len(pushes) == 3


def test_evidence_reports_the_raw_values_behind_a_feature():
    import pandas as pd
    row = pd.Series({"n_ntlm": 4, "n_ntlm_base_mean": 0.5, "n_ntlm_z": 3.5, "baseline_days": 7,
                     "n_ntlm_peer_z": np.nan, "peer_group": "other", "peer_n": 3, "n_events_z": 1.0,
                     "n_events_peer_z": np.nan})
    assert base_column("slog_n_ntlm_peer_z") == "n_ntlm_peer_z" and base_column("fail_ratio") == "fail_ratio"
    assert evidence(row, "log1p_n_ntlm") == {"n_ntlm": 4, "n_ntlm_base_mean": 0.5}
    assert evidence(row, "slog_n_ntlm_z") == {"n_ntlm": 4, "n_ntlm_base_mean": 0.5, "n_ntlm_z": 3.5, "baseline_days": 7}
    assert evidence(row, "slog_n_ntlm_peer_z")["n_ntlm_peer_z"] is None, "missing peer z is reported, not hidden"
    assert evidence(row, "no_peer_group") == {"no_peer_group": True, "peer_group": "other"}


def test_top_alerts_is_a_per_day_queue():
    import pandas as pd
    t = pd.DataFrame({"entity": list("abcdef"), "day": [1, 1, 1, 2, 2, 2]})
    out = top_alerts(t, np.array([0.1, 0.9, 0.5, 0.3, 0.2, 0.8]), per_day=2)
    assert out.entity.tolist() == ["b", "c", "f", "d"] and out.rank_in_day.tolist() == [1, 2, 1, 2]


def test_run_and_deletion_check(fitted):
    cfg, con, train, _, _ = fitted
    out = run(cfg, con, per_day=5, top_k=3)
    assert out["max_additivity_error"] < 1e-9 and len(out["packs"]) == 5 * 4
    d = deletion_check(out["explainer"], out["alerts"], train, ks=(1, 3), n_random=5)
    for k in (1, 3):
        assert d[k]["mean_drop_top"] > d[k]["mean_drop_random"], "top-SHAP features should matter more"


def test_triage_package_is_outside_the_freeze():
    from threatdet.freeze import fingerprint
    assert not [f for f in fingerprint(REPO_ROOT) if f.startswith(("triage/", "tests/"))]
