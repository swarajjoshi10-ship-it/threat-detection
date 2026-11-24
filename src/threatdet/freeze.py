"""Freeze the method before a holdout is scored.

    python -m threatdet.freeze write reports/holdout_freeze.json   # before any holdout label is read
    python -m threatdet.evaluate --config config/holdout_lanl30.toml --freeze reports/holdout_freeze.json

`write` records a SHA-256 of every file that can change a score (Python source, SQL, configs).
`evaluate --freeze` recomputes them and refuses to run if anything differs, so the holdout number
is produced by exactly the method that was frozen. There are no git commits to point at yet,
so the hashes are the record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from threatdet.config import REPO_ROOT

PATTERNS = ("src/threatdet/**/*.py", "sql/*.sql", "config/*.toml")


def fingerprint(root: Path = REPO_ROOT) -> dict[str, str]:
    files = sorted({p for pat in PATTERNS for p in root.glob(pat) if "__pycache__" not in p.parts})
    # Normalize line endings so a checkout on another OS gives the same hash.
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            for p in files}


def write(path: Path, note: str = "") -> dict:
    rec = {"frozen_unix": int(time.time()), "note": note, "files": fingerprint()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec


def verify(path: Path, root: Path = REPO_ROOT) -> None:
    frozen = json.loads(Path(path).read_text(encoding="utf-8"))["files"]
    now = fingerprint(root)
    changed = sorted(k for k in frozen.keys() | now.keys() if frozen.get(k) != now.get(k))
    if changed:
        raise SystemExit(f"method changed since freeze ({path}); refusing to score: {changed}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="freeze / verify the scoring method")
    ap.add_argument("action", choices=["write", "verify"])
    ap.add_argument("path")
    ap.add_argument("--note", default="")
    a = ap.parse_args(argv)
    if a.action == "write":
        print(f"froze {len(write(Path(a.path), a.note)['files'])} files -> {a.path}")
    else:
        verify(Path(a.path))
        print("method unchanged since freeze")


if __name__ == "__main__":
    main()
