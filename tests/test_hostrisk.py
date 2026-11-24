import duckdb
import pandas as pd
import pytest

from hostrisk.features import NEW_FEATURES, attach, build, sql_texts


def con_with(rows):
    """rows: (day, user, src, dst[, logon]) -> in-memory auth_events with the columns hostrisk reads."""
    con = duckdb.connect(":memory:")
    df = pd.DataFrame([r if len(r) == 5 else (*r, "Network") for r in rows],
                      columns=["day", "src_user", "src_comp", "dst_comp", "logon_type"])
    con.register("df", df)
    con.execute("CREATE TABLE auth_events AS SELECT * FROM df")
    return con


ROWS = [
    (0, "A", "H", "S1"), (0, "B", "WB", "S1"), (0, "C", "WC", "S1"),   # day 0: everyone's cold start
    (5, "B", "H", "S2"), (5, "B", "H", "S3"), (5, "C", "H", "S2"),     # B, C reach H for the first time
    (5, "D", "H", "S2"),                                                # D's own first day: cold start
    (10, "B", "H", "S2"),                                               # repeat visit inside W
    (25, "B", "H", "S2"),                                               # repeat visit after W
    (25, "A", "H", "H", "Network"),                                     # local, not remote
]


def table(con, name):
    return con.execute(f"SELECT * FROM hostrisk.{name} ORDER BY ALL").df()


def test_host_fanout_by_hand():
    con = con_with(ROWS)
    build(con, windows=(14,))
    h = table(con, "host_day_w14").set_index(["src_comp", "day"])
    # day 5: recent-new {B, C}; established {A (cold start, day 0), D (cold start, day 5)}
    assert h.loc[("H", 5), "n_recent_new_users"] == 2 and h.loc[("H", 5), "n_established_users"] == 2
    assert h.loc[("H", 5), "fanout"] == pytest.approx(2 / 3)
    # day 25: B and C first reached H on day 5 <= 25 - 14, so they are established now
    assert h.loc[("H", 25), "n_recent_new_users"] == 0 and h.loc[("H", 25), "fanout"] == 0


def test_repeat_visits_count_until_the_window_ends():
    con = con_with(ROWS)
    build(con, windows=(14,))
    u = table(con, "user_day_w14").set_index(["entity", "day"])
    assert u.loc[("B", 5), "n_recent_new_src_remote"] == 2
    assert u.loc[("B", 10), "n_recent_new_src_remote"] == 1, "a revisit inside W still counts (v2 missed this)"
    assert u.loc[("B", 25), "n_recent_new_src_remote"] == 0
    assert u.loc[("B", 5), "src_fanout_max"] == pytest.approx(2 / 3) and u.loc[("B", 5), "src_recent_new_users_max"] == 2
    assert u.loc[("D", 5), "n_recent_new_src_remote"] == 0, "cold start is not novelty"


def test_no_lookahead():
    full, cut = con_with(ROWS), con_with([r for r in ROWS if r[0] <= 10])
    for c in (full, cut):
        build(c, windows=(14,))
    for name in ("host_day_w14", "user_day_w14"):
        a, b = table(full, name), table(cut, name)
        pd.testing.assert_frame_equal(a[a.day <= 10].reset_index(drop=True), b.reset_index(drop=True))


def test_label_free_sql_and_attach_fills_zeros():
    assert not any("label" in s.lower() or "redteam" in s.lower() for w in (7, 14, 28) for s in sql_texts(w))
    con = con_with(ROWS)
    build(con, windows=(14,))
    frame = pd.DataFrame({"entity": ["B", "A"], "day": [5, 0]})
    out = attach(frame, con, 14)
    assert out.loc[out.entity == "A", NEW_FEATURES].eq(0).all(axis=None)
    assert out.loc[out.entity == "B", "src_fanout_max"].item() == pytest.approx(2 / 3)


def test_hostrisk_is_outside_the_freeze():
    from threatdet.freeze import fingerprint
    assert not any(p.startswith("hostrisk/") for p in fingerprint())
