"""Fit detectors on the training days, score the held-out days, report analyst-workload metrics.

    python -m threatdet.evaluate --source lanl --db data/lanl.duckdb

This is the ONLY module that reads `labels.*`. Unsupervised detectors are fitted on feature rows
with day < train_end_day and never receive labels. The supervised model is a ceiling for comparison,
trained with labels, leave-one-day-out.

Outputs: reports/metrics_<source>_<feature_set>.{json,md} and DuckDB table scores.user_day_<feature_set>
(entity, day, model, score).
"""

from __future__ import annotations

import argparse
import json
import time

import numpy as np
import pandas as pd

from threatdet.config import REPO_ROOT, Config, load_config
from threatdet.metrics import (
    alerts_at_recall, average_precision, cluster_bootstrap, daily_budget_recall,
)
from threatdet.models.detectors import design_matrix, feature_set, load_features, unsupervised_detectors
from threatdet.pipeline import connect


def load_labels(con) -> pd.DataFrame:
    return con.execute("SELECT entity, day, 1 AS y FROM labels.user_day WHERE is_malicious").df()


def supervised_ceiling(frame: pd.DataFrame, y: np.ndarray, test_mask: np.ndarray, cfg: Config) -> np.ndarray:
    """Gradient boosting WITH labels; a reference, never a deliverable.

    mode "lodo": leave-one-day-out over the test days, trained on every other day (optimistic: the
    same attacker accounts appear on other days, so it partly learns *who*, not just *what*).
    mode "train_before_test": one model trained on all days before the test window (holdout runs).
    """
    from sklearn.ensemble import HistGradientBoostingClassifier
    p, mode = cfg["models"]["supervised"], cfg["evaluation"].get("supervised_mode", "lodo")
    X, _ = design_matrix(frame, feature_set(cfg))
    days = frame["day"].to_numpy()
    make = lambda: HistGradientBoostingClassifier(
        max_iter=int(p["max_iter"]), learning_rate=float(p["learning_rate"]),
        class_weight="balanced", random_state=cfg.seed)
    out = np.full(len(frame), np.nan)
    if mode == "lodo":
        for d in np.unique(days[test_mask]):
            tr, te = days != d, days == d
            out[te] = make().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    elif mode == "train_before_test":
        tr = days < days[test_mask].min()
        out[test_mask] = make().fit(X[tr], y[tr]).predict_proba(X[test_mask])[:, 1]
    else:
        raise ValueError(f"unknown evaluation.supervised_mode {mode!r}")
    return out[test_mask]


def summarize(y, s, day, entity, *, total_pos, n_days, ev, seed, boot=True) -> dict:
    r = {"pr_auc": average_precision(y, s, total_pos)}
    for t in ev["recall_targets"]:
        r[f"alerts_per_day@{int(t * 100)}"] = alerts_at_recall(y, s, t, total_pos) / n_days
    for k in ev["daily_budgets"]:
        r[f"recall@{k}/day"] = daily_budget_recall(y, s, day, k, total_pos)
    if boot and int(ev["n_bootstrap"]) > 0:
        # CIs cover scored positives only; positives without a feature row (if any) are a fixed
        # handful, counted as misses in the point estimates and reported in meta.
        n = int(ev["n_bootstrap"])
        ap = cluster_bootstrap(y, s, day, entity, lambda a, b, c: average_precision(a, b), n, seed)
        a80 = cluster_bootstrap(y, s, day, entity, lambda a, b, c: alerts_at_recall(a, b, 0.8) / n_days, n, seed)
        r["pr_auc_ci90"] = [float(np.nanpercentile(ap, 5)), float(np.nanpercentile(ap, 95))]
        r["alerts_per_day@80_ci90"] = [float(np.nanpercentile(a80, 5)), float(np.nanpercentile(a80, 95))]
    return r


def test_window(cfg: Config) -> tuple[int, int]:
    """[start, end) of scored days. Default: everything from train_end_day on."""
    ev = cfg["evaluation"]
    start = int(ev.get("test_start_day", ev["train_end_day"]))
    end = int(ev.get("test_end_day", 10**9))
    if start < int(ev["train_end_day"]):
        raise ValueError("test window must not overlap the training days")
    return start, end


def run(cfg: Config, con, *, with_supervised: bool = True, boot: bool = True) -> dict:
    ev = cfg["evaluation"]
    T = int(ev["train_end_day"])
    start, end = test_window(cfg)
    frame = load_features(con)                      # active user-days only, no labels
    in_test = ((frame.day >= start) & (frame.day < end)).to_numpy()
    train, test = frame[frame.day < T], frame[in_test].reset_index(drop=True)

    labels = load_labels(con)
    lab = test[["entity", "day"]].merge(labels, how="left", on=["entity", "day"])
    y = lab["y"].fillna(0).astype(int).to_numpy()
    # Includes any positive in the window that has no feature row (counted as a miss).
    total_pos = int(((labels.day >= start) & (labels.day < end)).sum())
    n_days = test["day"].nunique()

    scores = {}
    timings = {}
    for det in unsupervised_detectors(cfg):
        t0 = time.perf_counter()
        det.fit(train.copy())                       # a copy: nothing the detector does leaks back
        scores[det.name] = det.score(test)
        timings[det.name] = round(time.perf_counter() - t0, 1)
    if with_supervised:
        t0 = time.perf_counter()
        y_all = frame[["entity", "day"]].merge(labels, how="left", on=["entity", "day"])["y"].fillna(0).astype(int).to_numpy()
        scores["supervised_ceiling"] = supervised_ceiling(frame, y_all, in_test, cfg)
        timings["supervised_ceiling"] = round(time.perf_counter() - t0, 1)

    day, entity = test["day"].to_numpy(), test["entity"].to_numpy()
    results = {name: summarize(y, s, day, entity, total_pos=total_pos, n_days=n_days, ev=ev,
                               seed=cfg.seed, boot=boot)
               for name, s in scores.items()}
    meta = {
        "source": cfg["data"]["source"], "feature_set": feature_set(cfg), "train_days": f"< {T}",
        "test_days": f"{start}-{min(end, int(frame.day.max()) + 1) - 1}",
        "supervised_mode": ev.get("supervised_mode", "lodo"),
        "train_rows": len(train), "test_rows": len(test), "test_days_n": n_days,
        "test_positives_total": total_pos, "test_positives_scored": int(y.sum()),
        "prevalence": y.sum() / len(y), "fit_seconds": timings,
    }
    return {"meta": meta, "results": results, "scores": scores, "test": test[["entity", "day"]]}


def to_markdown(out: dict) -> str:
    m, res = out["meta"], out["results"]
    cols = ["pr_auc", "alerts_per_day@50", "alerts_per_day@80", "alerts_per_day@90",
            "recall@5/day", "recall@10/day", "recall@25/day", "recall@50/day"]
    cols = [c for c in cols if c in next(iter(res.values()))]
    lines = [
        f"Source: **{m['source']}**, features **{m['feature_set']}** · fit on days {m['train_days']} ({m['train_rows']:,} active user-days) · "
        f"tested on days {m['test_days']} ({m['test_rows']:,} user-days, {m['test_days_n']} days, "
        f"{m['test_positives_total']} malicious, prevalence {m['prevalence']:.3%})",
        "",
        "| model | " + " | ".join(cols) + " | PR-AUC 90% CI | alerts/day@80 90% CI |",
        "|---|" + "---|" * (len(cols) + 2),
    ]
    for name, r in res.items():
        def f(c):
            v = r[c]
            return "unreached" if v == float("inf") else (f"{v:.3f}" if c == "pr_auc" or c.startswith("recall") else f"{v:,.0f}")
        ci = lambda k: f"{r[k][0]:.3f}–{r[k][1]:.3f}" if k == "pr_auc_ci90" else f"{r[k][0]:,.0f}–{r[k][1]:,.0f}"
        extra = [ci("pr_auc_ci90") if "pr_auc_ci90" in r else "", ci("alerts_per_day@80_ci90") if "alerts_per_day@80_ci90" in r else ""]
        lines.append(f"| {name} | " + " | ".join(f(c) for c in cols) + " | " + " | ".join(extra) + " |")
    return "\n".join(lines) + "\n"


def save(out: dict, con, cfg: Config) -> None:
    src = f"{cfg['data']['source']}_{feature_set(cfg)}"
    rep = REPO_ROOT / "reports"
    rep.mkdir(exist_ok=True)
    clean = lambda v: None if isinstance(v, float) and not np.isfinite(v) else v
    payload = {"meta": out["meta"],
               "results": {k: {kk: clean(vv) for kk, vv in r.items()} for k, r in out["results"].items()}}
    (rep / f"metrics_{src}.json").write_text(json.dumps(payload, indent=2, default=float), encoding="utf-8")
    (rep / f"metrics_{src}.md").write_text(to_markdown(out), encoding="utf-8")
    long = pd.concat([out["test"].assign(model=k, score=v) for k, v in out["scores"].items()])
    con.execute("CREATE SCHEMA IF NOT EXISTS scores")
    con.register("long_scores", long)
    con.execute(f"CREATE OR REPLACE TABLE scores.user_day_{feature_set(cfg)} AS SELECT * FROM long_scores")
    con.execute("DROP TABLE IF EXISTS scores.user_day")  # pre-feature-set name
    con.unregister("long_scores")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=None)
    ap.add_argument("--source", choices=["synthetic", "lanl"], default=None)
    ap.add_argument("--db", default=None)
    ap.add_argument("--no-supervised", action="store_true")
    ap.add_argument("--freeze", default=None, help="refuse to run unless the method matches this freeze file")
    ap.add_argument("--feature-set", choices=["v1", "v2"], default=None, help="override models.feature_set")
    args = ap.parse_args(argv)
    ov = {"data.source": args.source, "models.feature_set": args.feature_set}
    cfg = load_config(args.config, overrides={k: v for k, v in ov.items() if v})
    if args.freeze:
        from threatdet.freeze import verify
        verify(args.freeze)
    with connect(cfg, args.db) as con:
        out = run(cfg, con, with_supervised=not args.no_supervised)
        save(out, con, cfg)
    print(to_markdown(out))
    print("fit seconds:", out["meta"]["fit_seconds"])


if __name__ == "__main__":
    main()
