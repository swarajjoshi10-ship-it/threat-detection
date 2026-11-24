"""SHAP explanations ("evidence packs") for the top alerts of the two-stage detector.

    python -m triage.explain                       # LANL days 8-14, top 50 alerts per day
    python -m triage.explain --source synthetic --top 20

How the explanation maps onto the score
---------------------------------------
two_stage = gate (n_new_src_remote >= 1) + Isolation Forest ranker. The gate is a single fact and
is reported as such. The ranker is explained with TreeSHAP, which is exact for the forest:

    forest score  s = 2 ** (-E[h(x)] / c(psi))       (sklearn's -score_samples)
    E[h(x)]       = base + sum_j phi_j(x)            (TreeSHAP, additive in path length)

A short path means "isolated quickly" means anomalous, so each feature's *push* is reported as
-phi_j: positive push = this feature made the user-day look more anomalous. Additivity is checked
for every explained alert (``max_additivity_error``), not assumed.

Labels are read only in ``evaluation_summary`` (to say which factors appear in true vs false
alerts), never by ``AlertExplainer`` or the evidence packs, which go to the LLM triage step.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from threatdet.config import REPO_ROOT, Config, load_config
from threatdet.models.detectors import TwoStageDetector, _assert_label_free, design_matrix, load_features

GATE_COLUMNS = ("n_new_src_remote", "n_new_src_ntlm")
CONTEXT_COLUMNS = ("peer_group", "peer_n", "baseline_days", "is_first_day", "n_events")


def _py(v):
    """JSON-safe scalar: numpy -> python, NaN -> None."""
    if v is None:
        return None
    if isinstance(v, (np.bool_, bool)):
        return bool(v)
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating, float)):
        return None if math.isnan(v) else round(float(v), 4)
    return v


def base_column(feature: str) -> str:
    """Design-matrix name -> feature-table column (log1p_n_ntlm -> n_ntlm, slog_n_ntlm_z -> n_ntlm_z)."""
    for prefix in ("log1p_", "slog_"):
        if feature.startswith(prefix):
            return feature[len(prefix):]
    return feature


def evidence(row: pd.Series, feature: str) -> dict:
    """The raw, human-readable values behind one design feature (what an analyst would check)."""
    if feature == "no_self_baseline":
        out = {"no_self_baseline": pd.isna(row["n_events_z"]), "baseline_days": row["baseline_days"]}
    elif feature == "no_peer_group":
        out = {"no_peer_group": pd.isna(row["n_events_peer_z"]), "peer_group": row["peer_group"]}
    else:
        col = base_column(feature)
        if col.endswith("_peer_z"):
            m = col[: -len("_peer_z")]
            out = {m: row[m], col: row[col], "peer_group": row["peer_group"], "peer_n": row["peer_n"]}
        elif col.endswith("_z"):
            m = col[: -len("_z")]
            out = {m: row[m], f"{m}_base_mean": row[f"{m}_base_mean"], col: row[col],
                   "baseline_days": row["baseline_days"]}
        else:
            out = {col: row[col]}
            if f"{col}_base_mean" in row.index:
                out[f"{col}_base_mean"] = row[f"{col}_base_mean"]
    return {k: _py(v) for k, v in out.items()}


class AlertExplainer:
    """TreeSHAP over the two-stage ranker. Fit the detector first; this never refits anything."""

    def __init__(self, detector: TwoStageDetector):
        import shap
        from sklearn.ensemble._iforest import _average_path_length

        forest = detector.ranker
        self.detector, self.model, self.fset = detector, forest.model, forest.fset
        self.names: list[str] = list(forest.feature_names)
        self.tree = shap.TreeExplainer(self.model)
        self.c = float(_average_path_length([self.model.max_samples_])[0])

    def shap_values(self, frame: pd.DataFrame) -> tuple[np.ndarray, float]:
        """(rows x features) SHAP values in path-length units, and the base value."""
        X, names = design_matrix(frame, self.fset)  # refuses label columns
        assert names == self.names, "design matrix changed since the ranker was fit"
        phi = np.asarray(self.tree.shap_values(X), float)
        return phi, float(np.ravel(self.tree.expected_value)[0])

    def forest_score_from_shap(self, phi: np.ndarray, base: float) -> np.ndarray:
        return 2.0 ** (-(base + phi.sum(1)) / self.c)

    def explain(self, frame: pd.DataFrame, top_k: int = 5) -> tuple[list[dict], float]:
        """One evidence pack per row of ``frame`` (label-free) and the worst additivity error."""
        _assert_label_free(frame)
        frame = frame.reset_index(drop=True)
        phi, base = self.shap_values(frame)
        forest = self.detector.ranker.score(frame)
        err = float(np.abs(self.forest_score_from_shap(phi, base) - forest).max()) if len(frame) else 0.0
        gate = self.detector.gate(frame)
        packs = []
        for i, row in frame.iterrows():
            push = -phi[i]
            order = np.argsort(-push, kind="stable")[:top_k]
            packs.append({
                "alert_id": f"{row['entity']}|d{int(row['day'])}",
                "entity": row["entity"], "day": int(row["day"]),
                "gate": {"passed": bool(gate[i]), **{c: _py(row[c]) for c in GATE_COLUMNS}},
                "forest": {"anomaly_score": _py(forest[i]), "path_length": _py(base + phi[i].sum()),
                           "expected_path_length": _py(base)},
                "top_factors": [{"feature": self.names[j], "push": _py(push[j]),
                                 "evidence": evidence(row, self.names[j])} for j in order],
                "context": {c: _py(row[c]) for c in CONTEXT_COLUMNS},
            })
        return packs, err


def deletion_check(explainer: AlertExplainer, frame: pd.DataFrame, train: pd.DataFrame,
                   ks=(1, 3, 5), n_random: int = 20, seed: int = 0) -> dict:
    """Do the top-SHAP features matter more than random ones?

    For each alert, set its k highest-push features to the training median and rescore the forest;
    compare with resetting k features chosen at random. A faithful attribution should give a larger
    drop. Caveat: resetting one column of a correlated pair (log1p_x and slog_x_z) makes off-manifold
    points, so the absolute drops are only indicative; the comparison with random is the point.
    """
    X, _ = design_matrix(frame.reset_index(drop=True), explainer.fset)
    med = np.median(design_matrix(train, explainer.fset)[0], axis=0)
    phi, _ = explainer.shap_values(frame.reset_index(drop=True))
    score = lambda Z: -explainer.model.score_samples(Z)  # noqa: E731
    s0 = score(X)
    rng = np.random.default_rng(seed)
    n, d = X.shape
    out = {}
    for k in ks:
        top = np.argsort(phi, axis=1, kind="stable")[:, :k]  # most negative phi = largest push
        Xt = X.copy()
        np.put_along_axis(Xt, top, med[top], axis=1)
        drop_top = s0 - score(Xt)
        rand = np.empty((n_random, n))
        for r in range(n_random):
            idx = np.argsort(rng.random((n, d)), axis=1)[:, :k]
            Xr = X.copy()
            np.put_along_axis(Xr, idx, med[idx], axis=1)
            rand[r] = s0 - score(Xr)
        drop_rand = rand.mean(0)
        out[k] = {"mean_drop_top": float(drop_top.mean()), "mean_drop_random": float(drop_rand.mean()),
                  "frac_top_beats_random": float((drop_top > drop_rand).mean())}
    return out


def top_alerts(test: pd.DataFrame, score: np.ndarray, per_day: int) -> pd.DataFrame:
    """The ``per_day`` highest-scored user-days of each day (an analyst's daily queue)."""
    t = test.assign(_score=score)
    t["rank_in_day"] = t.groupby("day")["_score"].rank(ascending=False, method="first").astype(int)
    return t[t.rank_in_day <= per_day].sort_values(["day", "rank_in_day"]).reset_index(drop=True)


def evaluation_summary(packs: list[dict], labels: pd.DataFrame) -> dict:
    """LABELS USED HERE ONLY: which factors lead true vs false alerts. Never fed back to a model."""
    lab = {(e, int(d)) for e, d in labels[["entity", "day"]].itertuples(index=False)}
    rows = [{"tp": (p["entity"], p["day"]) in lab, "gate": p["gate"]["passed"],
             "top1": p["top_factors"][0]["feature"]} for p in packs]
    df = pd.DataFrame(rows)
    by = {}
    for name, g in df.groupby("tp"):
        by["true_alerts" if name else "false_alerts"] = {
            "n": len(g), "gate_pass_rate": round(float(g.gate.mean()), 3),
            "top1_factor_counts": g.top1.value_counts().head(6).to_dict()}
    return by


def _render_pack(p: dict) -> str:
    lines = [f"**{p['alert_id']}**: gate {'passed' if p['gate']['passed'] else 'not passed'} "
             f"(n_new_src_remote={p['gate']['n_new_src_remote']}, n_new_src_ntlm={p['gate']['n_new_src_ntlm']}); "
             f"forest score {p['forest']['anomaly_score']:.3f}, path length {p['forest']['path_length']:.2f} "
             f"vs expected {p['forest']['expected_path_length']:.2f}", ""]
    lines += [f"- `{f['feature']}` push {f['push']:+.3f}: "
              + ", ".join(f"{k}={v}" for k, v in f["evidence"].items()) for f in p["top_factors"]]
    return "\n".join(lines)


def run(cfg: Config, con, per_day: int = 50, top_k: int = 5, days: tuple[int, int] | None = None) -> dict:
    """``days`` = (start, end) overrides the evaluation window, e.g. (0, 8) for in-sample pilot packs."""
    from threatdet.evaluate import test_window

    T = int(cfg["evaluation"]["train_end_day"])
    start, end = days or test_window(cfg)
    frame = load_features(con)
    train = frame[frame.day < T]
    test = frame[(frame.day >= start) & (frame.day < end)].reset_index(drop=True)
    det = TwoStageDetector(cfg).fit(train.copy())
    alerts = top_alerts(test, det.score(test), per_day)
    explainer = AlertExplainer(det)
    feats = alerts.drop(columns=["_score", "rank_in_day"])
    packs, err = explainer.explain(feats, top_k)
    for p, (_, a) in zip(packs, alerts.iterrows()):
        p["rank_in_day"], p["two_stage_score"] = int(a.rank_in_day), float(a._score)  # unrounded: compared to stored
    return {"packs": packs, "max_additivity_error": err, "train": train, "alerts": feats,
            "explainer": explainer, "test_days": f"{start}-{min(end, int(frame.day.max()) + 1) - 1}"}


def _stored_scores_match(con, cfg: Config, packs: list[dict]) -> bool | None:
    """Does the refit reproduce the two_stage scores saved by `threatdet.evaluate`?"""
    from threatdet.models.detectors import feature_set
    table = f"scores.user_day_{feature_set(cfg)}"
    try:
        stored = con.execute(f"SELECT entity, day, score FROM {table} WHERE model = 'two_stage'").df()
    except Exception:  # noqa: BLE001 - table absent: nothing to compare
        return None
    if stored.empty:  # e.g. the DB was rebuilt after the last `evaluate`
        return None
    got = pd.DataFrame([{"entity": p["entity"], "day": p["day"], "s": p["two_stage_score"]} for p in packs])
    m = got.merge(stored, on=["entity", "day"], how="left")
    if m.score.isna().all():  # window not scored by `evaluate` (e.g. in-sample pilot days)
        return None
    return bool(m.score.notna().all() and np.allclose(m.s, m.score, rtol=0, atol=1e-9))


def main(argv=None) -> None:
    from threatdet.evaluate import load_labels
    from threatdet.pipeline import connect

    ap = argparse.ArgumentParser(description="SHAP evidence packs for the top two-stage alerts")
    ap.add_argument("--config", default=None)
    ap.add_argument("--source", choices=["synthetic", "lanl"], default=None)
    ap.add_argument("--db", default=None)
    ap.add_argument("--top", type=int, default=50, help="alerts per day")
    ap.add_argument("--factors", type=int, default=5, help="factors per alert")
    ap.add_argument("--days", default=None, help="start-end (inclusive), overrides the test window, e.g. 0-7")
    ap.add_argument("--tag", default="", help="suffix for output files, e.g. pilot")
    a = ap.parse_args(argv)
    cfg = load_config(a.config, overrides={"data.source": a.source} if a.source else None)
    # data.source alone does not move db_path; without this, --source lanl silently read the
    # synthetic DB and labelled the output "lanl" (caught on the first run: 300 users/day).
    db = a.db or ("data/lanl.duckdb" if cfg["data"]["source"] == "lanl" and not a.config else None)
    with connect(cfg, db) as con:
        n_users = con.execute("SELECT count(DISTINCT entity) FROM features.user_day").fetchone()[0]
        if cfg["data"]["source"].startswith("lanl") and n_users < 1000:
            raise SystemExit(f"source {cfg['data']['source']!r} but the DB has only {n_users} users: wrong --db?")
        days = tuple(int(x) for x in a.days.split("-")) if a.days else None
        out = run(cfg, con, a.top, a.factors, (days[0], days[1] + 1) if days else None)
        positives = load_labels(con)  # evaluation only, after every pack has been built
        match = _stored_scores_match(con, cfg, out["packs"])
    packs, fset = out["packs"], out["explainer"].fset
    src = cfg["data"]["source"] + (f"_{a.tag}" if a.tag else "")
    deletion = deletion_check(out["explainer"], out["alerts"], out["train"], seed=cfg.seed)
    summary = evaluation_summary(packs, positives)

    rep = REPO_ROOT / "reports"
    with open(rep / f"evidence_{src}_{fset}.jsonl", "w", encoding="utf-8") as f:
        for p in packs:
            f.write(json.dumps(p) + "\n")
    meta = {"source": src, "feature_set": fset, "test_days": out["test_days"], "alerts_per_day": a.top,
            "n_alerts": len(packs), "max_additivity_error": out["max_additivity_error"],
            "refit_matches_stored_scores": match, "deletion_check": deletion, "label_summary": summary}
    (rep / f"explanations_{src}_{fset}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    lab = {(e, int(d)) for e, d in positives[["entity", "day"]].itertuples(index=False)}
    first_tp = next((p for p in packs if (p["entity"], p["day"]) in lab), None)
    first_fp = next((p for p in packs if (p["entity"], p["day"]) not in lab), None)
    md = [f"# Alert explanations: {src} {fset}, days {out['test_days']}, top {a.top}/day", "",
          f"- alerts explained: {len(packs)}; max |SHAP reconstruction - forest score| = {out['max_additivity_error']:.2e}",
          f"- refit reproduces stored two_stage scores: {match}", "",
          "## Deletion check (reset k features to the training median, rescore the forest)", "",
          "| k | mean drop, top-SHAP k | mean drop, random k | share of alerts where top beats random |",
          "|---|---|---|---|"]
    md += [f"| {k} | {v['mean_drop_top']:.4f} | {v['mean_drop_random']:.4f} | {v['frac_top_beats_random']:.1%} |"
           for k, v in deletion.items()]
    md += ["", "## Leading factor, true vs false alerts (labels used for this table only)", "",
           "```", json.dumps(summary, indent=2), "```", ""]
    for title, p in (("Highest-ranked true alert", first_tp), ("Highest-ranked false alert", first_fp)):
        if p:
            md += [f"## {title} (rank {p['rank_in_day']} on day {p['day']})", "", _render_pack(p), ""]
    (rep / f"explanations_{src}_{fset}.md").write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({k: v for k, v in meta.items() if k != "label_summary"}, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
