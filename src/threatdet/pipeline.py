"""Ingestion + feature pipeline (DuckDB).

    python -m threatdet.pipeline all       [--config ...] [--db ...]
    python -m threatdet.pipeline ingest
    python -m threatdet.pipeline features

Tables produced:
    auth_events                  normalized events (user principals only, unless configured)
    labels.redteam_events        red-team rows           -- evaluation only
    labels.redteam_match         red-team rows + whether they were found in auth_events
    labels.user_day              (entity, day) is_malicious  -- evaluation only
    features.user_day_base       per (entity, day) aggregates
    features.user_day_dense      dense grid, zero-filled counts + ratios
    features.user_day_baseline   + rolling 7-day baseline mean / z-scores
    features.peer_groups         per-user frozen peer assignment (own warm-up, usable from peer_from)
    features.user_day            final modelling table (no label columns); peer_group is per day
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import duckdb

from threatdet.config import Config, load_config
from threatdet.sqlrun import run_sql_file, sql_literal_path

SECONDS_PER_DAY = 86_400

# Counts are zero-filled on inactive days.
COUNT_FEATURES = [
    "n_events", "n_fail", "n_dst_hosts", "n_src_hosts", "n_new_dst_hosts", "n_new_src_hosts",
    "n_remote_dst_hosts", "n_off_hours", "n_ntlm", "n_auth_types", "n_logon_types", "n_active_hours",
]
# v2 event-level novelty counts (pre-registered before scoring; see README "Novelty features").
NOVELTY_FEATURES = ["n_new_src_remote", "n_new_src_ntlm", "n_new_dst_remote", "n_new_pair_events"]
COUNT_FEATURES += NOVELTY_FEATURES
RATIO_FEATURES = ["fail_ratio", "off_hours_ratio", "new_dst_ratio"]

# feature -> std floor. The floor stops a perfectly regular user (std ~ 0) from turning a
# +1 change into z = 1e9; it is part of the method and is reported in the README.
BASELINE_METRICS: dict[str, float] = {
    "n_events": 1.0, "n_fail": 1.0, "n_dst_hosts": 1.0, "n_src_hosts": 1.0,
    "n_new_dst_hosts": 1.0, "n_remote_dst_hosts": 1.0, "n_off_hours": 1.0, "n_ntlm": 1.0,
    "fail_ratio": 0.05, "off_hours_ratio": 0.05,
}
# feature -> floor on 1.4826 * MAD
PEER_METRICS: dict[str, float] = {
    "n_events": 1.0, "n_dst_hosts": 1.0, "n_new_dst_hosts": 1.0, "n_remote_dst_hosts": 1.0,
    "n_off_hours": 1.0, "n_ntlm": 1.0, "fail_ratio": 0.05,
}

MODEL_FEATURES: list[str] = (
    COUNT_FEATURES + RATIO_FEATURES
    + [f"{m}_z" for m in BASELINE_METRICS]
    + [f"{m}_peer_z" for m in PEER_METRICS]
)
KEY_COLUMNS = ["entity", "day"]


def connect(cfg: Config, db: str | Path | None = None) -> duckdb.DuckDBPyConnection:
    path = Path(db) if db else cfg.path("db_path")
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    return duckdb.connect(str(path))


def ingest(con: duckdb.DuckDBPyConnection, cfg: Config, source_dir: Path | None = None) -> dict:
    src = Path(source_dir or cfg.source_dir)
    auth, redteam = src / "auth.txt.gz", src / "redteam.txt.gz"
    if not auth.exists():
        raise FileNotFoundError(f"{auth} not found - see README 'Getting the data'")
    max_time = int(cfg["data"]["max_days"]) * SECONDS_PER_DAY
    run_sql_file(con, "01_ingest_auth.sql", {
        "auth_path": sql_literal_path(auth),
        "max_time": max_time,
        "include_machine_accounts": "TRUE" if cfg["features"]["include_machine_accounts"] else "FALSE",
    })
    if redteam.exists():
        run_sql_file(con, "02_ingest_labels.sql", {"redteam_path": sql_literal_path(redteam), "max_time": max_time})
    else:
        print(f"warning: {redteam} missing; no labels ingested", file=sys.stderr)
    return ingest_summary(con)


def ingest_summary(con: duckdb.DuckDBPyConnection) -> dict:
    n_events, n_users, n_days = con.execute(
        "SELECT count(*), count(DISTINCT src_user), count(DISTINCT day) FROM auth_events").fetchone()
    out = {"events": n_events, "users": n_users, "days": n_days}
    has_labels = con.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='labels' AND table_name='redteam_match'"
    ).fetchone()[0]
    if has_labels:
        n_rt, n_matched, n_mal = con.execute(
            "SELECT count(*), count(*) FILTER (WHERE matched_in_auth), "
            "(SELECT count(*) FROM labels.user_day) FROM labels.redteam_match").fetchone()
        out.update(redteam_events=n_rt, redteam_matched=n_matched, malicious_user_days=n_mal)
    return out


def _zero_filled_counts() -> str:
    return ",\n    ".join(f"coalesce(b.{c}, 0) AS {c}" for c in COUNT_FEATURES)


def _baseline_columns(min_days: int) -> str:
    cols = []
    for m, floor in BASELINE_METRICS.items():
        cols.append(f"avg({m}) OVER w AS {m}_base_mean")
        cols.append(
            f"CASE WHEN count({m}) OVER w >= {min_days} "
            f"THEN ({m} - avg({m}) OVER w) / greatest(coalesce(stddev_samp({m}) OVER w, 0), {floor}) "
            f"END AS {m}_z"
        )
    return ",\n    ".join(cols)


def _peer_stats() -> str:
    return ", ".join(
        f"median(CAST({m} AS DOUBLE)) AS {m}_peer_med, mad(CAST({m} AS DOUBLE)) AS {m}_peer_mad"
        for m in PEER_METRICS)


def _peer_columns(min_size: int) -> str:
    return ",\n    ".join(
        f"CASE WHEN s.peer_n >= {min_size} "
        f"THEN (j.{m} - s.{m}_peer_med) / greatest(1.4826 * coalesce(s.{m}_peer_mad, 0), {floor}) "
        f"END AS {m}_peer_z"
        for m, floor in PEER_METRICS.items())


def build_features(con: duckdb.DuckDBPyConnection, cfg: Config) -> dict:
    f = cfg["features"]
    run_sql_file(con, "10_user_day_base.sql", {"off_hours": ", ".join(str(int(h)) for h in f["off_hours"])})
    run_sql_file(con, "11_user_day_baseline.sql", {
        "window": int(f["baseline_window_days"]),
        "min_baseline_days": int(f["min_baseline_days"]),
        "zero_filled_counts": _zero_filled_counts(),
        "baseline_columns": _baseline_columns(int(f["min_baseline_days"])),
    })
    run_sql_file(con, "12_peer_groups.sql", {
        "warmup_days": int(f["warmup_days"]),
        "max_host_user_frac": float(f["max_host_user_frac"]),
        "min_peer_group_size": int(f["min_peer_group_size"]),
        "peer_stats": _peer_stats(),
        "peer_columns": _peer_columns(int(f["min_peer_group_size"])),
    })
    rows, entities = con.execute("SELECT count(*), count(DISTINCT entity) FROM features.user_day").fetchone()
    kinds = dict(con.execute("SELECT peer_kind, count(*) FROM features.peer_groups GROUP BY 1").fetchall())
    groups, covered = con.execute(
        "SELECT count(DISTINCT peer_group) FILTER (WHERE peer_group <> 'unassigned'), "
        "avg(CAST(n_events_peer_z IS NOT NULL AS DOUBLE)) FROM features.user_day WHERE is_active").fetchone()
    return {"user_day_rows": rows, "entities": entities, "peer_kinds": kinds, "peer_groups": groups,
            "active_rows_with_peer_z": round(covered or 0.0, 4)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="DuckDB ingestion + feature pipeline")
    ap.add_argument("step", choices=["ingest", "features", "all"])
    ap.add_argument("--config", default=None)
    ap.add_argument("--source", choices=["synthetic", "lanl"], default=None, help="override data.source")
    ap.add_argument("--db", default=None, help="override paths.db_path")
    args = ap.parse_args(argv)
    cfg = load_config(args.config, overrides={"data.source": args.source} if args.source else None)
    with connect(cfg, args.db) as con:
        if args.step in ("ingest", "all"):
            print("ingest:", ingest(con, cfg))
        if args.step in ("features", "all"):
            print("features:", build_features(con, cfg))


if __name__ == "__main__":
    main()
