"""Fetch a laptop-sized subset of the LANL "Comprehensive, Multi-Source Cyber-Security Events" data.

The full auth.txt.gz is ~7.6 GB compressed (58 days, ~1B events). It is sorted by time, so only a
prefix of the compressed file is needed for the first N days.

How the download works, and why:
* The LANL server throttles each connection (~50 KB/s measured) and drops long-lived connections
  (the first attempt died at ~day 2.4). So the file is fetched as fixed-size byte-range SEGMENTS
  by several workers in parallel (4 connections measured ~4x the throughput of 1).
* Each segment resumes independently after a dropped connection (HTTP Range from its last byte).
* A single reader decompresses completed segments in order and stops scheduling new segments as
  soon as it sees an event at/after day N.
* Segments live in `auth_segments/`; re-running the same command reuses everything on disk.
* The prefix is then trimmed to exactly `day < N` and re-compressed as `auth.txt.gz`.

LANL gates the files behind a short form on https://csr.lanl.gov/data/cyber1/ (email + intended
use, plus the dataset terms). Fill it in yourself, then pass the resulting links -- or local
copies -- to --auth-file / --redteam-file (both accept a URL or a path):

    python -m threatdet.data.download_lanl --days 15 --auth-file "<auth.txt.gz link>" --redteam-file "<redteam.txt.gz link>"
    python -m threatdet.data.download_lanl --days 15 --auth-file D:/lanl/auth.txt.gz --redteam-file D:/lanl/redteam.txt.gz
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import math
import shutil
import sys
import threading
import time as _time
import urllib.error
import urllib.request
import zlib
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import IO, Callable, Iterator

from threatdet.config import load_config

BASE_URL = "https://csr.lanl.gov/data/cyber1"
SECONDS_PER_DAY = 86_400
USER_AGENT = "threatdet-research-downloader/0.1"
SEGMENT_SIZE = 32 << 20

# Transient failures worth retrying. URLError/TimeoutError/ConnectionResetError are OSErrors;
# IncompleteRead is an HTTPException. HTTP 4xx (e.g. an expired signed link) is fatal.
_RETRYABLE = (OSError, http.client.HTTPException)

Opener = Callable[[str, int, int], IO[bytes]]


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _open_source(url_or_path: str) -> IO[bytes]:
    if url_or_path.startswith(("http://", "https://")):
        req = urllib.request.Request(url_or_path, headers={"User-Agent": USER_AGENT})
        return urllib.request.urlopen(req, timeout=60)  # noqa: S310 - fixed https host
    return open(url_or_path, "rb")


def _redact(url_or_path: str) -> str:
    """LANL links carry a signed access token in the path; never persist it."""
    if url_or_path.startswith(("http://", "https://")):
        return f"{BASE_URL}/{url_or_path.rsplit('/', 1)[-1]} (signed link, token redacted)"
    return url_or_path


def _range_open(url: str, start: int, end: int) -> IO[bytes]:
    """Open bytes [start, end] (inclusive). The response must be 206 with a Content-Range."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": f"bytes={start}-{end}"})
    resp = urllib.request.urlopen(req, timeout=120)  # noqa: S310
    if resp.status != 206:
        resp.close()
        raise RuntimeError(f"server ignored the Range request (HTTP {resp.status}); cannot download in segments")
    return resp


def total_size(url: str, opener: Opener = _range_open, *, sleep: Callable[[float], None] = _time.sleep,
               max_retries: int = 30) -> int:
    for attempt in range(1, max_retries + 2):
        try:
            with opener(url, 0, 0) as r:
                content_range = r.headers.get("Content-Range", "")  # "bytes 0-0/7626505158"
            return int(content_range.rsplit("/", 1)[1])
        except urllib.error.HTTPError as e:
            if e.code < 500:
                raise
            err: BaseException = e
        except _RETRYABLE as e:
            err = e
        sleep(min(60, 2 ** attempt))
    raise RuntimeError(f"could not get file size after {max_retries} retries") from err


# ---------------------------------------------------------------------------- prefix detection
class PrefixScanner:
    """Runs compressed bytes through a single zlib stream and notices when the time-sorted
    content passes `max_time`. It only inspects the last complete line of each chunk."""

    def __init__(self, max_time: int):
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._tail = b""
        self.max_time = max_time
        self.last_time = 0
        self.done = False

    def feed(self, chunk: bytes) -> None:
        data = self._d.decompress(chunk)
        if self._d.eof:  # whole file is inside the window
            self.done = True
        buf = self._tail + data
        nl = buf.rfind(b"\n")
        if nl < 0:
            self._tail = buf
            return
        complete, self._tail = buf[:nl], buf[nl + 1:]
        last = complete[complete.rfind(b"\n") + 1:]
        comma = last.find(b",")
        if comma > 0:
            self.last_time = int(last[:comma])
            if self.last_time >= self.max_time:
                self.done = True


def iter_prefix_lines(raw: IO[bytes], max_time: int) -> Iterator[bytes]:
    """Yield gz-decompressed lines whose leading integer timestamp is < max_time, stopping at the
    first line at/after max_time (the file is time-sorted). Works on a truncated gzip prefix as
    long as that prefix extends past max_time."""
    with gzip.GzipFile(fileobj=raw) as gz:
        for line in gz:
            comma = line.find(b",")
            if comma <= 0:
                continue
            if int(line[:comma]) >= max_time:
                return
            yield line


# ---------------------------------------------------------------------------- segmented fetch
class _Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reconnects = 0

    def reconnect(self) -> None:
        with self.lock:
            self.reconnects += 1


def fetch_range(url: str, path: Path, start: int, end: int, *, opener: Opener, sleep: Callable[[float], None],
                stop: threading.Event, stats: _Stats, max_retries: int = 30, chunk_size: int = 1 << 20) -> bool:
    """Make `path` hold exactly bytes [start, end] of `url`, resuming from whatever is already in
    it. Returns False if stopped early via `stop`."""
    need = end - start + 1
    have = path.stat().st_size if path.exists() else 0
    if have > need:
        raise RuntimeError(f"{path.name} is larger than its byte range; delete it and re-run")
    failures = 0
    with open(path, "ab") as out:
        while have < need:
            if stop.is_set():
                return False
            try:
                with opener(url, start + have, end) as resp:
                    while have < need:
                        if stop.is_set():
                            return False
                        c = resp.read(min(chunk_size, need - have))
                        if not c:
                            raise ConnectionError("server closed the stream early")
                        out.write(c)
                        have += len(c)
                        failures = 0
                continue
            except urllib.error.HTTPError as e:
                if e.code < 500:
                    raise  # 403/404: expired or wrong link; retrying won't help
                err: BaseException = e
            except _RETRYABLE as e:
                err = e
            failures += 1
            if failures > max_retries:
                raise RuntimeError(f"{path.name}: giving up after {max_retries} consecutive failures") from err
            out.flush()
            stats.reconnect()
            sleep(min(60, 2 ** failures))
    return True


def seed_segments(raw: Path, seg_dir: Path, segment_size: int) -> int:
    """Split an existing sequential partial download into segment files (keeps earlier progress)."""
    seeded = 0
    with open(raw, "rb") as f:
        i = 0
        while chunk := f.read(segment_size):
            p = seg_dir / f"seg_{i:05d}.bin"
            if not p.exists() or p.stat().st_size < len(chunk):
                p.write_bytes(chunk)
            seeded += len(chunk)
            i += 1
    return seeded


def fetch_prefix_segments(url: str, seg_dir: Path, max_time: int, *, workers: int = 6,
                          segment_size: int = SEGMENT_SIZE, opener: Opener = _range_open,
                          sleep: Callable[[float], None] = _time.sleep, max_retries: int = 30,
                          lookahead: int | None = None) -> tuple[list[Path], dict]:
    """Download consecutive segments until the decompressed content passes `max_time`.
    Returns the ordered segment files that make up the needed prefix."""
    seg_dir.mkdir(parents=True, exist_ok=True)
    size = total_size(url, opener, sleep=sleep, max_retries=max_retries)
    n_segs = math.ceil(size / segment_size)
    lookahead = lookahead or workers * 2

    def seg(i: int) -> Path:
        return seg_dir / f"seg_{i:05d}.bin"

    def bounds(i: int) -> tuple[int, int]:
        return i * segment_size, min(size, (i + 1) * segment_size) - 1

    scanner, stop, stats = PrefixScanner(max_time), threading.Event(), _Stats()
    t0, scanned = _time.time(), 0
    futures: dict[int, Future] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        try:
            nxt = 0
            while not scanner.done and scanned < n_segs:
                while nxt < n_segs and nxt < scanned + lookahead:
                    s, e = bounds(nxt)
                    futures[nxt] = ex.submit(fetch_range, url, seg(nxt), s, e, opener=opener, sleep=sleep,
                                             stop=stop, stats=stats, max_retries=max_retries)
                    nxt += 1
                futures.pop(scanned).result()  # re-raises fatal errors from the worker
                with open(seg(scanned), "rb") as f:
                    while not scanner.done and (c := f.read(1 << 20)):
                        scanner.feed(c)
                scanned += 1
                _log(f"  {scanned * segment_size / 1e6:,.0f} MB, day {scanner.last_time / SECONDS_PER_DAY:.2f}, "
                     f"{_time.time() - t0:.0f}s, reconnects {stats.reconnects}")
        finally:
            stop.set()
            for f in futures.values():
                f.cancel()
    return [seg(i) for i in range(scanned)], {"total_bytes": size, "segments": scanned,
                                              "prefix_bytes": scanned * segment_size,
                                              "reconnects": stats.reconnects}


# ---------------------------------------------------------------------------- outputs
def write_prefix(src: str, dest: Path, max_days: int, progress_every: int = 20_000_000) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    max_time = max_days * SECONDS_PER_DAY
    n = 0
    sha = hashlib.sha256()
    with _open_source(src) as raw, gzip.open(tmp, "wb", compresslevel=6) as out:
        for line in iter_prefix_lines(raw, max_time):
            out.write(line)
            sha.update(line)
            n += 1
            if n % progress_every == 0:
                _log(f"  trimmed {n:,} lines, day {int(line.split(b',', 1)[0]) / SECONDS_PER_DAY:.2f}")
    tmp.replace(dest)
    return {"source": _redact(src), "lines": n, "max_days": max_days, "sha256_uncompressed": sha.hexdigest()}


def download_whole(src: str, dest: Path) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with _open_source(src) as raw, open(tmp, "wb") as out:
        shutil.copyfileobj(raw, out)
    tmp.replace(dest)
    return {"source": _redact(src), "bytes": dest.stat().st_size}


def concat(parts: list[Path], dest: Path) -> None:
    with open(dest, "wb") as out:
        for p in parts:
            with open(p, "rb") as f:
                shutil.copyfileobj(f, out, 1 << 20)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None)
    ap.add_argument("--days", type=int, default=None, help="keep events with day < DAYS (default: config data.max_days)")
    ap.add_argument("--out", type=Path, default=None, help="default: <raw_dir>/lanl")
    ap.add_argument("--auth-file", default=None, help="URL or local path of the full auth.txt.gz")
    ap.add_argument("--redteam-file", default=None, help="URL or local path of redteam.txt.gz")
    ap.add_argument("--workers", type=int, default=6, help="parallel range connections (default 6)")
    ap.add_argument("--keep-raw", action="store_true", help="keep downloaded segments after success")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    days = args.days or int(cfg["data"]["max_days"])
    out = args.out or cfg.path("raw_dir") / "lanl"
    out.mkdir(parents=True, exist_ok=True)

    manifest: dict = {"retrieved_unix": int(_time.time())}
    redteam_dest = out / "redteam.txt.gz"
    if redteam_dest.exists():
        _log(f"redteam: {redteam_dest} already present")
        manifest["redteam"] = {"bytes": redteam_dest.stat().st_size}
    else:
        _log(f"redteam -> {redteam_dest}")
        manifest["redteam"] = download_whole(args.redteam_file or f"{BASE_URL}/redteam.txt.gz", redteam_dest)

    auth_src = args.auth_file or f"{BASE_URL}/auth.txt.gz"
    _log(f"auth (days < {days}) -> {out / 'auth.txt.gz'}")
    if auth_src.startswith(("http://", "https://")):
        seg_dir = out / "auth_segments"
        seg_dir.mkdir(exist_ok=True)
        legacy = out / "auth.txt.gz.download"  # progress from the older sequential downloader
        if legacy.exists():
            _log(f"  seeded {seed_segments(legacy, seg_dir, SEGMENT_SIZE) / 1e6:,.0f} MB from {legacy.name}")
            legacy.unlink()
        parts, info = fetch_prefix_segments(auth_src, seg_dir, days * SECONDS_PER_DAY, workers=args.workers)
        raw = out / "auth.prefix.raw.gz"
        concat(parts, raw)
        _log(f"  fetched {info}; trimming to days < {days}")
        manifest["auth"] = write_prefix(str(raw), out / "auth.txt.gz", days) | info
        manifest["auth"]["source"] = _redact(auth_src)
        raw.unlink()
        if not args.keep_raw:
            shutil.rmtree(seg_dir)
    else:
        manifest["auth"] = write_prefix(auth_src, out / "auth.txt.gz", days)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
