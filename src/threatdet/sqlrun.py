"""Render and execute the SQL files in sql/.

Placeholders are `{{name}}`. Rendering fails loudly on a missing or unused parameter so a typo
can't silently produce a different query.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import duckdb

from threatdet.config import SQL_DIR

_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def sql_literal_path(p: str | Path) -> str:
    """Path for use inside a single-quoted SQL string."""
    return Path(p).resolve().as_posix().replace("'", "''")


def render(sql: str, params: dict[str, Any]) -> str:
    used = set(_PLACEHOLDER.findall(sql))
    missing = used - params.keys()
    if missing:
        raise KeyError(f"missing SQL parameters: {sorted(missing)}")
    unused = params.keys() - used
    if unused:
        raise KeyError(f"unused SQL parameters (typo?): {sorted(unused)}")
    return _PLACEHOLDER.sub(lambda m: str(params[m.group(1)]), sql)


def run_sql_file(con: duckdb.DuckDBPyConnection, name: str, params: dict[str, Any] | None = None,
                 sql_dir: Path = SQL_DIR) -> None:
    sql = (sql_dir / name).read_text(encoding="utf-8")
    con.execute(render(sql, params or {}))
