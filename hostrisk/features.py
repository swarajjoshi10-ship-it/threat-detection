"""Host fan-out and recently-new-source features. Reads only `auth_events`, never `labels.*`.

Tables (schema `hostrisk`, one set per window W):
    pairs              (src_user, src_comp, first_day, is_new)  user-host pairs; is_new = not cold start
    host_day_w{W}      (src_comp, day, n_recent_new_users, n_established_users, fanout)
    user_day_w{W}      (entity, day, n_recent_new_src_remote, src_fanout_max, src_recent_new_users_max)

Every value on day d uses only events from days <= d (pairs first seen after d are excluded by the
joins), so truncating the future never changes the past (tested).
"""

from __future__ import annotations

import duckdb
import pandas as pd

NEW_FEATURES = ["n_recent_new_src_remote", "src_fanout_max", "src_recent_new_users_max"]
WINDOWS = (7, 14, 28)
PRIMARY_W = 14

_REMOTE = "logon_type = 'Network' AND dst_comp IS DISTINCT FROM src_comp AND src_comp IS NOT NULL"

PAIRS_SQL = """
CREATE SCHEMA IF NOT EXISTS hostrisk;
CREATE OR REPLACE TABLE hostrisk.pairs AS
WITH pf AS (
    SELECT src_user, src_comp, min(day) AS first_day FROM auth_events WHERE src_comp IS NOT NULL GROUP BY ALL
), uf AS (
    SELECT src_user, min(day) AS first_day FROM auth_events GROUP BY ALL
)
-- A pair first seen on the user's own first day is cold start, not novelty (same rule as v2).
SELECT pf.src_user, pf.src_comp, pf.first_day, pf.first_day > uf.first_day AS is_new
FROM pf JOIN uf USING (src_user);
"""

HOST_DAY_SQL = """
CREATE OR REPLACE TABLE hostrisk.host_day_w{w} AS
WITH hd AS (SELECT DISTINCT src_comp, day FROM auth_events WHERE {remote})
SELECT
    hd.src_comp, hd.day,
    count(*) FILTER (WHERE p.is_new AND p.first_day > hd.day - {w})          AS n_recent_new_users,
    count(*) FILTER (WHERE NOT p.is_new OR p.first_day <= hd.day - {w})      AS n_established_users,
    n_recent_new_users / (1.0 + n_established_users)                         AS fanout
FROM hd JOIN hostrisk.pairs p ON p.src_comp = hd.src_comp AND p.first_day <= hd.day
GROUP BY ALL;
"""

USER_DAY_SQL = """
CREATE OR REPLACE TABLE hostrisk.user_day_w{w} AS
WITH ud AS (
    SELECT src_user, day, src_comp, count(*) AS n_remote FROM auth_events WHERE {remote} GROUP BY ALL
)
SELECT
    ud.src_user                                                                     AS entity,
    ud.day,
    coalesce(sum(ud.n_remote) FILTER (WHERE p.is_new AND p.first_day > ud.day - {w}), 0)
                                                                                    AS n_recent_new_src_remote,
    max(h.fanout)                                                                   AS src_fanout_max,
    arg_max(h.n_recent_new_users, h.fanout)                                         AS src_recent_new_users_max
FROM ud
JOIN hostrisk.pairs p ON p.src_user = ud.src_user AND p.src_comp = ud.src_comp
JOIN hostrisk.host_day_w{w} h ON h.src_comp = ud.src_comp AND h.day = ud.day
GROUP BY ALL;
"""


def sql_texts(w: int) -> list[str]:
    return [PAIRS_SQL, HOST_DAY_SQL.format(w=int(w), remote=_REMOTE), USER_DAY_SQL.format(w=int(w), remote=_REMOTE)]


def build(con: duckdb.DuckDBPyConnection, windows=WINDOWS) -> dict:
    con.execute(PAIRS_SQL)
    out = {"pairs": con.execute("SELECT count(*) FROM hostrisk.pairs").fetchone()[0]}
    for w in windows:
        con.execute(HOST_DAY_SQL.format(w=int(w), remote=_REMOTE))
        con.execute(USER_DAY_SQL.format(w=int(w), remote=_REMOTE))
        out[f"host_days_w{w}"] = con.execute(f"SELECT count(*) FROM hostrisk.host_day_w{w}").fetchone()[0]
    return out


def attach(frame: pd.DataFrame, con: duckdb.DuckDBPyConnection, w: int) -> pd.DataFrame:
    """features.user_day rows + the three v3 columns (0 when the user had no remote logon that day)."""
    extra = con.execute(f"SELECT * FROM hostrisk.user_day_w{int(w)}").df()
    out = frame.merge(extra, how="left", on=["entity", "day"], validate="one_to_one")
    out[NEW_FEATURES] = out[NEW_FEATURES].fillna(0).astype(float)
    return out


def main(argv=None) -> None:
    import argparse
    ap = argparse.ArgumentParser(description="build hostrisk.* tables")
    ap.add_argument("--db", required=True)
    a = ap.parse_args(argv)
    with duckdb.connect(a.db) as con:
        print(build(con))


if __name__ == "__main__":
    main()
