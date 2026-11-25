"""Run the host fan-out rule (detections/host_fanout_rule.sql) and score it (post-hoc).

    python -m detections.rule                 # tune on days 1-7 (label-free), score days 8-14 and 15-29

The threshold is chosen without labels: the smallest fan-out at which the rule would have fired at
most BUDGET times a day, on average, over training days 1-7 (day 0 is all cold start). Labels are read
only after every rule table is built. Output: reports/detection_rule.{json,md}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb
import numpy as np

from hostrisk.features import PRIMARY_W
from threatdet.config import REPO_ROOT
from threatdet.evaluate import load_labels

SQL = Path(__file__).with_name("host_fanout_rule.sql")
DB = REPO_ROOT / "data" / "lanl30.duckdb"
TRAIN_DAYS = (1, 8)          # [start, end)
WINDOWS = {"days 8-14": (8, 15), "days 15-29": (15, 30)}
PARAMS = {"w": PRIMARY_W, "min_new": 3, "watch_days": 30, "budget": 1.0}


def sql_text(w: int, threshold: float, min_new: int, watch_days: int) -> str:
    return SQL.read_text(encoding="utf-8").format(
        w=int(w), threshold=float(threshold), min_new=int(min_new), watch_days=int(watch_days))


def choose_threshold(con, w: int, min_new: int, budget: float, days=TRAIN_DAYS) -> float:
    """Smallest fan-out with mean triggers/day over `days` <= budget. Unlabelled data only."""
    v = con.execute(f"SELECT fanout FROM hostrisk.host_day_w{int(w)} WHERE day >= ? AND day < ? "
                    f"AND n_recent_new_users >= ?", [days[0], days[1], int(min_new)]).df()["fanout"].to_numpy()
    n_days = days[1] - days[0]
    for t in np.unique(v):
        if (v >= t).sum() / n_days <= budget:
            return float(t)
    return float(v.max()) + 1e-9 if len(v) else 0.0


def build(con, w=PARAMS["w"], min_new=PARAMS["min_new"], watch_days=PARAMS["watch_days"],
          budget=PARAMS["budget"], threshold=None) -> float:
    if threshold is None:
        threshold = choose_threshold(con, w, min_new, budget)
    con.execute(sql_text(w, threshold, min_new, watch_days))
    return threshold


def score(con, start: int, end: int) -> dict:
    """Labels from here on. Host view: red-team source host-days; user view: malicious user-days."""
    n_days = end - start
    q = lambda s: con.execute(s, [start, end]).df()
    hosts = q("SELECT src_comp, day, is_trigger_day FROM detections.fanout_host_alerts WHERE day >= ? AND day < ?")
    users = q("SELECT entity, day FROM detections.fanout_user_alerts WHERE day >= ? AND day < ?")
    trig = q("SELECT src_comp, day FROM detections.fanout_triggers WHERE day >= ? AND day < ?")
    pos_h = q("SELECT DISTINCT src_comp, day FROM labels.redteam_events WHERE day >= ? AND day < ?")
    lab = load_labels(con)
    pos_u = lab[(lab.day >= start) & (lab.day < end) & (lab.y == 1)][["entity", "day"]]
    hit_h = pos_h.merge(hosts, on=["src_comp", "day"])
    hit_u = pos_u.merge(users, on=["entity", "day"])
    return {
        "days": n_days,
        "triggers_per_day": len(trig) / n_days,
        "host_alerts_per_day": len(hosts) / n_days,
        "user_alerts_per_day": len(users) / n_days,
        "attacker_host_days": len(pos_h),
        "attacker_host_days_caught": len(hit_h),
        "attacker_hosts": int(pos_h["src_comp"].nunique()),
        "attacker_hosts_caught": int(hit_h["src_comp"].nunique()),
        "malicious_user_days": len(pos_u),
        "malicious_user_days_caught": len(hit_u),
        "user_recall": len(hit_u) / len(pos_u) if len(pos_u) else None,
        "accounts": int(pos_u["entity"].nunique()),
        "accounts_caught": int(hit_u["entity"].nunique()),
        "user_precision": len(hit_u) / len(users) if len(users) else None,
    }


def per_day(con, src: str) -> list[dict]:
    return con.execute("SELECT day, fanout, n_recent_new_users, n_established_users FROM hostrisk.host_day_w14 "
                       "WHERE src_comp = ? ORDER BY day", [src]).df().to_dict("records")


def to_markdown(rep: dict) -> str:
    p = rep["params"]
    lines = [f"Host fan-out rule — **post-hoc** (the watch list was designed after the days 15–29 diagnosis).",
             "", f"Parameters: W = {p['w']}, min_new = {p['min_new']}, watch_days = {p['watch_days']}, "
             f"threshold = {p['threshold']:.3f} (label-free: <= {p['budget']:g} trigger/day on days 1–7).", "",
             "| window | triggers/day | host alerts/day | user alerts/day | attacker host-days caught | "
             "malicious user-days caught | accounts caught | user precision |",
             "|---|---|---|---|---|---|---|---|"]
    for name, r in rep["windows"].items():
        lines.append(f"| {name} | {r['triggers_per_day']:.1f} | {r['host_alerts_per_day']:.1f} | "
                     f"{r['user_alerts_per_day']:.1f} | {r['attacker_host_days_caught']}/{r['attacker_host_days']} | "
                     f"{r['malicious_user_days_caught']}/{r['malicious_user_days']} ({r['user_recall']:.1%}) | "
                     f"{r['accounts_caught']}/{r['accounts']} | {r['user_precision']:.1%} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(DB))
    ap.add_argument("--watch-days", type=int, default=PARAMS["watch_days"])
    ap.add_argument("--out", default="detection_rule")
    a = ap.parse_args(argv)
    con = duckdb.connect(":memory:")
    con.execute(f"ATTACH '{Path(a.db).as_posix()}' AS src (READ_ONLY)")
    for t in ("auth_events",):
        con.execute(f"CREATE VIEW {t} AS SELECT * FROM src.main.{t}")
    con.execute("CREATE SCHEMA hostrisk")
    for t in ("pairs", f"host_day_w{PARAMS['w']}"):
        con.execute(f"CREATE VIEW hostrisk.{t} AS SELECT * FROM src.hostrisk.{t}")
    params = {**PARAMS, "watch_days": a.watch_days}
    thr = build(con, params["w"], params["min_new"], params["watch_days"], params["budget"])
    con.execute("CREATE SCHEMA labels")
    for t in con.execute("SELECT table_name FROM duckdb_tables() WHERE database_name='src' AND schema_name='labels'").fetchall():
        con.execute(f"CREATE VIEW labels.{t[0]} AS SELECT * FROM src.labels.{t[0]}")
    rep = {"params": {**params, "threshold": thr}, "post_hoc": True,
           "windows": {name: score(con, s, e) for name, (s, e) in WINDOWS.items()}}
    out = REPO_ROOT / "reports" / a.out
    out.with_suffix(".json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    out.with_suffix(".md").write_text(to_markdown(rep), encoding="utf-8")
    print(to_markdown(rep))


if __name__ == "__main__":
    main()
