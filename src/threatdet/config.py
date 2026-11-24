"""Config loading. TOML (stdlib tomllib) keeps the dependency list short."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SQL_DIR = REPO_ROOT / "sql"
DEFAULT_CONFIG = REPO_ROOT / "config" / "default.toml"


@dataclass(frozen=True)
class Config:
    raw: dict[str, Any]

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    @property
    def seed(self) -> int:
        return int(self.raw["seed"])

    def path(self, key: str) -> Path:
        p = Path(self.raw["paths"][key])
        return p if p.is_absolute() else REPO_ROOT / p

    @property
    def source_dir(self) -> Path:
        return self.path("raw_dir") / self.raw["data"]["source"]


def load_config(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Config:
    with open(path or DEFAULT_CONFIG, "rb") as f:
        raw = tomllib.load(f)
    for dotted, value in (overrides or {}).items():
        node = raw
        *parents, leaf = dotted.split(".")
        for p in parents:
            node = node.setdefault(p, {})
        node[leaf] = value
    return Config(raw)
