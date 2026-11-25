"""Score the stateless Sigma rule (sigma/host_many_accounts.yml) on LANL, for comparison.

The Sigma rule counts distinct accounts logging on remotely from one source host per day. Sigma
correlations hold no history, so the rule can't tell new accounts from a server's usual crowd.
This scores that count rule with a threshold chosen like the fan-out rule's (label-free: <= 1 host
alert a day on training days 1-7), plus lower thresholds, to show the cost of having no baseline.

    python -m detections.count_rule     -> reports/detection_count_rule.{json,md}
"""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import numpy as np

from threatdet.config import REPO_ROOT

DB = REPO_ROOT / "data" / "lanl30.duckdb"
WINDOWS = {"days 8-14": (8, 15), "days 15-29": (15, 30)}

HOST_DAY_SQL = """
CREATE OR REPLACE TEMP TABLE count_host_day AS
SELECT src_comp, day, count(DISTINCT src_user) AS n_users
FROM auth_events
WHERE logon_type = 'Network' AND dst_comp IS DISTINCT FROM src_comp AND src_comp IS NOT NULL
GROUP BY ALL
"""


def choose_threshold(con, budget: float = 1.0, days=(1, 8)) -> int:
    v = con.execute("SELECT n_users FROM count_host_day WHERE day >= ? AND day < ?", list(days)).df()["n_users"].to_numpy()
    n_days = days[1] - days[0]
    for t in np.unique(v):
        if (v >= t).sum() / n_days <= budget:
            return int(t)
    return int(v.max()) + 1


def score(con, t: int, start: int, end: int) -> dict:
    """Labels from here on."""
    alerts = con.execute("SELECT count(*) FROM count_host_day WHERE n_users >= ? AND day >= ? AND day < ?",
                         [t, start, end]).fetchone()[0]
    pos, caught = con.execute("""
        SELECT count(*), count(*) FILTER (WHERE h.n_users >= ?)
        FROM (SELECT DISTINCT src_comp, day FROM labels.redteam_events WHERE day >= ? AND day < ?) r
        LEFT JOIN count_host_day h USING (src_comp, day)""", [t, start, end]).fetchone()
    return {"host_alerts_per_day": alerts / (end - start), "attacker_host_days": pos,
            "attacker_host_days_caught": caught}


def main() -> None:
    con = duckdb.connect(str(DB), read_only=True)
    con.execute(HOST_DAY_SQL)
    t0 = choose_threshold(con)
    rows = []
    for t in sorted({t0, 50, 25, 15}, reverse=True):
        rows.append({"threshold": t, "label_free": t == t0,
                     **{name: score(con, t, s, e) for name, (s, e) in WINDOWS.items()}})
    rep = {"rule": "distinct accounts per source host per day (remote logons)", "post_hoc": True, "rows": rows}
    lines = ["Stateless count rule (the Sigma version) on LANL. Threshold row marked * is label-free "
             "(<= 1 alert/day on days 1–7); the others are shown for comparison.", "",
             "| threshold | days 8–14 host alerts/day | attacker host-days caught | days 15–29 host alerts/day "
             "| attacker host-days caught |", "|---|---|---|---|---|"]
    for r in rows:
        a, b = r["days 8-14"], r["days 15-29"]
        lines.append(f"| {r['threshold']}{'*' if r['label_free'] else ''} | {a['host_alerts_per_day']:.1f} | "
                     f"{a['attacker_host_days_caught']}/{a['attacker_host_days']} | {b['host_alerts_per_day']:.1f} | "
                     f"{b['attacker_host_days_caught']}/{b['attacker_host_days']} |")
    md = "\n".join(lines) + "\n"
    out = REPO_ROOT / "reports" / "detection_count_rule"
    out.with_suffix(".json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    out.with_suffix(".md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
