"""Score v3 detectors against v2 references on one window (README "v3: host-level ...").

    python -m hostrisk.run --window dev     --w 14   # days 8-14  (validation)
    python -m hostrisk.run --window posthoc --w 14   # days 15-29 (post-hoc: design informed by its labels)

Both windows use data/lanl30.duckdb (days 0-14 are identical to the 15-day DB, checked earlier).
Detectors are fitted on days 0-7 and never see labels; labels are read only in `evaluate_window`.
Output: reports/hostrisk_<window>_w<W>.{json,md}
"""

from __future__ import annotations

import argparse
import json

import duckdb
import numpy as np
import pandas as pd

from hostrisk.features import NEW_FEATURES, PRIMARY_W, attach
from threatdet.config import REPO_ROOT, load_config
from threatdet.evaluate import load_labels, summarize
from threatdet.metrics import daily_budget_recall
from threatdet.models.detectors import (
    IsolationForestDetector, RuleBaseline, TwoStageDetector, _assert_label_free, design_matrix, load_features,
)

WINDOWS = {"dev": (8, 15), "posthoc": (15, 30)}
DB = REPO_ROOT / "data" / "lanl30.duckdb"
CONFIG = REPO_ROOT / "config" / "holdout_lanl30.toml"


class IForestV3:
    name = "iforest_v3"

    def __init__(self, cfg):
        self.p, self.seed = cfg["models"]["iforest"], cfg.seed

    def matrix(self, frame):
        X, names = design_matrix(frame, "v2")
        extra = np.log1p(frame[NEW_FEATURES].to_numpy(float))
        return np.column_stack([X, extra]), names + [f"log1p_{c}" for c in NEW_FEATURES]

    def fit(self, frame):
        from sklearn.ensemble import IsolationForest
        X, self.feature_names = self.matrix(frame)
        self.model = IsolationForest(n_estimators=int(self.p["n_estimators"]),
                                     max_samples=min(int(self.p["max_samples"]), len(X)),
                                     random_state=self.seed, n_jobs=-1).fit(X)
        return self

    def score(self, frame):
        return -self.model.score_samples(self.matrix(frame)[0])


class HostFanout:
    """Primary: rank by src_fanout_max, ties broken by the v2 Isolation Forest (lexicographic)."""

    name = "host_fanout"

    def __init__(self, cfg):
        self.tiebreak = IsolationForestDetector(cfg)

    def fit(self, frame):
        _assert_label_free(frame)
        self.tiebreak.fit(frame)
        return self

    def score(self, frame):
        _assert_label_free(frame)
        f, t = frame["src_fanout_max"].to_numpy(float), self.tiebreak.score(frame)
        order = np.lexsort((t, f))                 # last key is primary
        rank = np.empty(len(f)); rank[order] = np.arange(len(f))
        return rank                                # unique, monotone in (fanout, iforest)


def detectors(cfg):
    return [RuleBaseline(cfg), IsolationForestDetector(cfg), TwoStageDetector(cfg), IForestV3(cfg), HostFanout(cfg)]


def top_k_flags(score, day, k, seed):
    """Boolean mask of the top-k per day; exact ties broken by a seeded random order."""
    rnd = np.random.default_rng(seed).random(len(score))
    flag = np.zeros(len(score), bool)
    for d in np.unique(day):
        idx = np.flatnonzero(day == d)
        order = idx[np.lexsort((rnd[idx], -score[idx]))]
        flag[order[:k]] = True
    return flag


def account_metrics(test, score, labels_w, k, seed):
    flag = top_k_flags(score, test["day"].to_numpy(), k, seed)
    hits = test.loc[flag, ["entity", "day"]].merge(labels_w, on=["entity", "day"])
    first_mal = labels_w.groupby("entity")["day"].min()
    first_hit = hits.groupby("entity")["day"].min()
    delay = (first_hit - first_mal.reindex(first_hit.index)).to_numpy()
    return {f"accounts_caught@{k}/day": len(first_hit) / len(first_mal),
            "accounts_caught_n": int(len(first_hit)), "accounts_total": int(len(first_mal)),
            "median_days_to_first_catch": float(np.median(delay)) if len(delay) else None}


def host_view(con, w, start, end):
    """Rank source hosts by fan-out per day; positive host-day = any red-team event from it that day."""
    hd = con.execute(f"SELECT src_comp, day, fanout FROM hostrisk.host_day_w{w} WHERE day >= {start} AND day < {end}").df()
    pos = con.execute(f"SELECT DISTINCT src_comp, day, 1 AS y FROM labels.redteam_events "
                      f"WHERE day >= {start} AND day < {end}").df()
    m = hd.merge(pos, how="left", on=["src_comp", "day"])
    y = m["y"].fillna(0).astype(int).to_numpy()
    out = {"positive_host_days": len(pos), "distinct_attacker_hosts": int(pos["src_comp"].nunique())}
    for k in (1, 5, 10):
        out[f"host_recall@{k}/day"] = daily_budget_recall(y, m["fanout"].to_numpy(), m["day"].to_numpy(), k, len(pos))
    return out


def evaluate_window(window: str, w: int = PRIMARY_W, db=DB) -> dict:
    cfg = load_config(CONFIG)
    start, end = WINDOWS[window]
    ev = cfg["evaluation"]
    with duckdb.connect(str(db), read_only=True) as con:
        frame = attach(load_features(con), con, w)
        train = frame[frame.day < int(ev["train_end_day"])]
        test = frame[(frame.day >= start) & (frame.day < end)].reset_index(drop=True)
        scores = {}
        for det in detectors(cfg):
            det.fit(train.copy())
            scores[det.name] = det.score(test)
        # ---- labels from here on (evaluation only)
        labels = load_labels(con)
        hv = host_view(con, w, start, end)
    labels_w = labels[(labels.day >= start) & (labels.day < end)][["entity", "day"]]
    y = test[["entity", "day"]].merge(labels, how="left", on=["entity", "day"])["y"].fillna(0).astype(int).to_numpy()
    total_pos, n_days = len(labels_w), test["day"].nunique()
    day, ent = test["day"].to_numpy(), test["entity"].to_numpy()
    results = {}
    for name, s in scores.items():
        r = summarize(y, s, day, ent, total_pos=total_pos, n_days=n_days, ev=ev, seed=cfg.seed)
        r.update(account_metrics(test, s, labels_w, 50, cfg.seed))
        results[name] = r
    pos = test[y == 1]
    meta = {"window": window, "days": f"{start}-{end - 1}", "W": w, "test_rows": len(test),
            "positives_total": total_pos, "positives_scored": int(y.sum()),
            "positives_with_remote_from_fanout_host": int((pos["src_fanout_max"] > 0).sum()),
            "post_hoc": window == "posthoc"}
    return {"meta": meta, "results": results, "host_view": hv}


def to_markdown(out: dict) -> str:
    m = out["meta"]
    cols = ["pr_auc", "alerts_per_day@80", "recall@10/day", "recall@50/day", "accounts_caught@50/day",
            "median_days_to_first_catch"]
    lines = [f"Window **{m['window']}** (days {m['days']}), W = {m['W']}, {m['test_rows']:,} user-days, "
             f"{m['positives_total']} malicious" + (" — **post-hoc**" if m["post_hoc"] else ""), "",
             "| detector | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for name, r in out["results"].items():
        def f(c):
            v = r.get(c)
            if v is None:
                return "–"
            if v == float("inf"):
                return "unreached"
            return f"{v:,.0f}" if c.startswith("alerts") else (f"{v:.1f}" if c.startswith("median") else f"{v:.3f}")
        lines.append(f"| {name} | " + " | ".join(f(c) for c in cols) + " |")
    lines += ["", "Host view: " + ", ".join(f"{k} = {v:.3f}" if isinstance(v, float) else f"{k} = {v}"
                                            for k, v in out["host_view"].items())]
    return "\n".join(lines) + "\n"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--window", choices=list(WINDOWS), required=True)
    ap.add_argument("--w", type=int, default=PRIMARY_W)
    a = ap.parse_args(argv)
    out = evaluate_window(a.window, a.w)
    stem = REPO_ROOT / "reports" / f"hostrisk_{a.window}_w{a.w}"
    clean = lambda v: None if isinstance(v, float) and not np.isfinite(v) else v
    payload = {**out, "results": {k: {kk: clean(vv) for kk, vv in r.items()} for k, r in out["results"].items()}}
    stem.with_suffix(".json").write_text(json.dumps(payload, indent=2, default=float), encoding="utf-8")
    stem.with_suffix(".md").write_text(to_markdown(out), encoding="utf-8")
    print(to_markdown(out))


if __name__ == "__main__":
    main()
