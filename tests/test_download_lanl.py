"""Downloader logic tested offline against a local LANL-format file (no network)."""

import gzip
import io

import pytest

from threatdet.data.download_lanl import (
    PrefixScanner, concat, fetch_prefix_segments, iter_prefix_lines, seed_segments, write_prefix,
)
from tests.conftest import DAY, ev, write_gz


def test_prefix_stops_at_max_day():
    lines = [ev(d, h) for d in range(4) for h in (1, 12)]
    buf = io.BytesIO(gzip.compress(("\n".join(lines) + "\n").encode()))
    kept = list(iter_prefix_lines(buf, max_time=2 * 86_400))
    assert len(kept) == 4
    assert all(int(line.split(b",")[0]) < 2 * 86_400 for line in kept)


def test_write_prefix_from_local_file(tmp_path):
    src = tmp_path / "full" / "auth.txt.gz"
    write_gz(src, [ev(d, 3) for d in range(10)])
    info = write_prefix(str(src), tmp_path / "out" / "auth.txt.gz", max_days=3)
    assert info["lines"] == 3
    with gzip.open(tmp_path / "out" / "auth.txt.gz", "rt") as f:
        assert len(f.read().splitlines()) == 3
    assert not (tmp_path / "out" / "auth.txt.gz.part").exists()


# ---------------------------------------------------------------- resumable fetch
def _gz_blob(n_days=20, per_day=400):
    lines = [ev(d, h % 24, sec=i) for d in range(n_days) for i, h in enumerate(range(per_day))]
    lines.sort(key=lambda s: int(s.split(",", 1)[0]))
    return gzip.compress(("\n".join(lines) + "\n").encode(), compresslevel=1), lines


class FlakyServer:
    """Honours byte ranges [start, end]; each connection dies after `drop_after` bytes (if set);
    the first `fail_first` connection attempts are refused."""

    def __init__(self, blob, drop_after=None, fail_first=0):
        self.blob, self.drop_after, self.fail_first = blob, drop_after, fail_first
        self.calls = []

    def __call__(self, url, start, end):
        self.calls.append((start, end))
        if len(self.calls) <= self.fail_first:
            raise ConnectionResetError("refused")
        stop = end + 1 if self.drop_after is None else min(end + 1, start + self.drop_after)
        return _Resp(self.blob[start:stop], truncated=stop < end + 1,
                     headers={"Content-Range": f"bytes {start}-{end}/{len(self.blob)}"})


class _Resp(io.BytesIO):
    def __init__(self, data, truncated, headers):
        super().__init__(data)
        self.truncated, self.headers = truncated, headers

    def read(self, n=-1):
        c = super().read(n)
        if not c and self.truncated:
            raise ConnectionResetError("dropped")
        return c


def _fetch(tmp_path, server, max_days, **kw):
    kw = {"workers": 3, "segment_size": 4_000, "opener": server, "sleep": lambda s: None} | kw
    return fetch_prefix_segments("https://x/auth.txt.gz", tmp_path / "segs", max_days * DAY, **kw)


def _trim(tmp_path, parts, max_days):
    concat(parts, tmp_path / "raw.gz")
    write_prefix(str(tmp_path / "raw.gz"), tmp_path / "auth.txt.gz", max_days=max_days)
    with gzip.open(tmp_path / "auth.txt.gz", "rt") as f:
        return f.read().splitlines()


@pytest.mark.parametrize("drop_after", [None, 1_500, 333])
def test_segmented_fetch_survives_drops_and_output_is_exact(tmp_path, drop_after):
    blob, lines = _gz_blob()
    server = FlakyServer(blob, drop_after=drop_after, fail_first=2)
    parts, info = _fetch(tmp_path, server, max_days=12)
    joined = b"".join(p.read_bytes() for p in parts)
    assert joined == blob[: len(joined)], "segments reassemble into an exact byte prefix"
    assert len(joined) < len(blob), "stopped early, did not fetch the whole file"
    if drop_after is not None:
        assert info["reconnects"] >= 1
    assert _trim(tmp_path, parts, 12) == [l for l in lines if int(l.split(",", 1)[0]) < 12 * DAY]


def test_whole_file_inside_window(tmp_path):
    blob, lines = _gz_blob(n_days=3)
    parts, info = _fetch(tmp_path, FlakyServer(blob), max_days=100)
    assert b"".join(p.read_bytes() for p in parts) == blob
    assert _trim(tmp_path, parts, 100) == lines


def test_rerun_reuses_segments_on_disk(tmp_path):
    blob, _ = _gz_blob()
    parts, _ = _fetch(tmp_path, FlakyServer(blob), max_days=8)
    server = FlakyServer(blob)
    _fetch(tmp_path, server, max_days=8)
    needed_end = len(parts) * 4_000
    refetched = [c for c in server.calls if c != (0, 0) and c[0] < needed_end]
    assert not refetched, "needed segments already complete on disk must not be downloaded again"


def test_seed_from_sequential_partial_download(tmp_path):
    blob, lines = _gz_blob()
    legacy = tmp_path / "auth.txt.gz.download"
    legacy.write_bytes(blob[:9_500])  # older downloader died here: 2 full segments + a partial one
    (tmp_path / "segs").mkdir()
    seed_segments(legacy, tmp_path / "segs", 4_000)
    server = FlakyServer(blob)
    parts, _ = _fetch(tmp_path, server, max_days=12)
    segment_calls = [c for c in server.calls if c != (0, 0)]  # (0, 0) is the size probe
    assert not [c for c in segment_calls if c[0] < 8_000], "the 2 complete seeded segments are not re-fetched"
    assert (9_500, 11_999) in segment_calls, "the partial seeded segment resumes from its last byte"
    assert _trim(tmp_path, parts, 12) == [l for l in lines if int(l.split(",", 1)[0]) < 12 * DAY]


def test_gives_up_after_max_retries(tmp_path):
    blob, _ = _gz_blob()

    class Dead(FlakyServer):
        def __call__(self, url, start, end):
            if (start, end) == (0, 0):
                return super().__call__(url, start, end)
            raise ConnectionResetError("down")

    with pytest.raises(RuntimeError, match="giving up"):
        _fetch(tmp_path, Dead(blob), max_days=1, max_retries=3)


def test_scanner_detects_whole_file_inside_window():
    blob, _ = _gz_blob(n_days=3)
    s = PrefixScanner(max_time=100 * DAY)
    s.feed(blob)
    assert s.done
