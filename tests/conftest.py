from __future__ import annotations

import gzip
from pathlib import Path

import duckdb
import pytest

from threatdet.config import load_config
from threatdet.pipeline import build_features, connect, ingest

DAY = 86_400


def ev(day: int, hour: int, user: str = "U1", src: str = "C100", dst: str = "C10", auth: str = "Kerberos",
       logon: str = "Network", orient: str = "LogOn", ok: bool = True, sec: int = 0) -> str:
    """One LANL-format auth line."""
    t = day * DAY + hour * 3600 + sec
    u = f"{user}@DOM1"
    return f"{t},{u},{u},{src},{dst},{auth},{logon},{orient},{'Success' if ok else 'Fail'}"


def write_gz(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # LANL files are time-sorted; keep fixtures realistic.
    lines = sorted(lines, key=lambda s: int(s.split(",", 1)[0]))
    with gzip.open(path, "wt", newline="\n") as f:
        f.writelines(line + "\n" for line in lines)


@pytest.fixture
def cfg_factory():
    def make(**overrides):
        base = {
            "data.max_days": 60,
            "features.min_baseline_days": 2,
            "features.warmup_days": 2,
            "features.min_peer_group_size": 1,
            "features.max_host_user_frac": 1.0,
        }
        base.update(overrides)
        return load_config(overrides=base)
    return make


@pytest.fixture
def run_pipeline(tmp_path):
    """Write fixture lines, ingest + build features in an in-memory DuckDB, return the connection."""
    counter = {"n": 0}

    def run(cfg, auth_lines: list[str], redteam_lines: list[str] | None = None,
            features: bool = True) -> duckdb.DuckDBPyConnection:
        counter["n"] += 1
        src = tmp_path / f"src{counter['n']}"
        write_gz(src / "auth.txt.gz", auth_lines)
        if redteam_lines is not None:
            write_gz(src / "redteam.txt.gz", redteam_lines)
        con = connect(cfg, ":memory:")
        ingest(con, cfg, source_dir=src)
        if features:
            build_features(con, cfg)
        return con

    return run
