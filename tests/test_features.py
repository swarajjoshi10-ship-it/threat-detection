import math

import numpy as np
import pandas as pd
import pytest

from threatdet.config import load_config
from threatdet.data.synthetic import generate
from threatdet.pipeline import MODEL_FEATURES
from tests.conftest import DAY, ev


def user_day(con) -> pd.DataFrame:
    return con.execute("SELECT * FROM features.user_day ORDER BY entity, day").df().set_index(["entity", "day"])


# ---------------------------------------------------------------- hand-computed values
@pytest.fixture
def tiny(cfg_factory, run_pipeline):
    lines = [
        # day 0 (first day for U1): 2 events to C10, one failed
        ev(0, 9), ev(0, 10, ok=False),
        # day 1: C10 again + a NEW host C11 at 02:00 (off-hours), NTLM
        ev(1, 9), ev(1, 2, dst="C11", auth="NTLM"),
        # day 2: inactive
        # day 3: new src workstation C200, dst C10
        ev(3, 11, src="C200"),
    ]
    return user_day(run_pipeline(cfg_factory(), lines))


def test_daily_aggregates(tiny):
    d0, d1, d2, d3 = (tiny.loc[("U1", d)] for d in range(4))
    assert (d0.n_events, d0.n_fail, d0.fail_ratio, d0.n_dst_hosts) == (2, 1, 0.5, 1)
    assert d0.n_new_dst_hosts == 0 and d0.is_first_day, "first day is cold start, not novelty"
    assert (d1.n_new_dst_hosts, d1.n_off_hours, d1.n_ntlm, d1.n_dst_hosts) == (1, 1, 1, 2)
    assert d1.new_dst_ratio == 0.5 and d1.off_hours_ratio == 0.5
    assert (d3.n_new_src_hosts, d3.n_new_dst_hosts) == (1, 0)


def test_event_level_novelty_counts(cfg_factory, run_pipeline):
    lines = [
        ev(0, 9),                                                          # day 0: cold start
        ev(1, 9, src="C200", auth="NTLM"), ev(1, 10, src="C200", auth="NTLM"),  # new src, remote, NTLM
        ev(1, 11, src="C200", dst="C200", logon="Interactive"),           # new src + new dst, but local
        ev(1, 12, dst="C11"),                                              # new remote dst from old src
        ev(2, 9, src="C200", auth="NTLM"),                                 # nothing new any more
    ]
    df = user_day(run_pipeline(cfg_factory(), lines)).loc["U1"]
    cols = ["n_new_src_remote", "n_new_src_ntlm", "n_new_dst_remote", "n_new_pair_events"]
    assert df.loc[0, cols].tolist() == [0, 0, 0, 0], "first day is cold start"
    assert df.loc[1, cols].tolist() == [2, 2, 1, 4]
    assert df.loc[2, cols].tolist() == [0, 0, 0, 0]


def test_dense_grid_zero_fills_inactive_days(tiny):
    d2 = tiny.loc[("U1", 2)]
    assert not d2.is_active and d2.n_events == 0 and d2.n_dst_hosts == 0
    assert pd.isna(d2.fail_ratio), "ratios are undefined (NULL) on inactive days"


def test_baseline_requires_min_history(tiny):
    # min_baseline_days = 2 in the test config
    assert list(tiny.loc["U1"].baseline_days) == [0, 1, 2, 3]
    assert tiny.loc["U1"].n_events_z.isna().tolist() == [True, True, False, False]


def test_zscore_matches_manual_computation(cfg_factory, run_pipeline):
    counts = [3, 5, 4, 6, 2, 5, 4, 7, 3, 20]  # spike on day 9
    lines = [ev(d, 9, sec=i) for d, c in enumerate(counts) for i in range(c)]
    df = user_day(run_pipeline(cfg_factory(), lines)).loc["U1"]
    for d in range(2, len(counts)):
        prev = np.array(counts[max(0, d - 7):d], float)
        expected = (counts[d] - prev.mean()) / max(prev.std(ddof=1), 1.0)
        assert math.isclose(df.loc[d, "n_events_z"], expected, rel_tol=1e-9), d
    assert df.loc[9, "n_events_z"] > 5


def test_zscore_std_floor_prevents_blowup(cfg_factory, run_pipeline):
    lines = [ev(d, 9, sec=i) for d in range(5) for i in range(4)] + [ev(5, 9, sec=i) for i in range(5)]
    df = user_day(run_pipeline(cfg_factory(), lines)).loc["U1"]
    assert df.loc[5, "n_events_z"] == pytest.approx(1.0)  # std 0 -> floor 1, not inf


# ---------------------------------------------------------------- peer groups
def test_peer_z_uses_same_day_median_and_mad(cfg_factory, run_pipeline):
    # U1..U5 share anchor host C10 in warm-up. On day 3 their n_events are 1,2,3,4,30.
    lines = [ev(d, 9, user=f"U{u}") for u in range(1, 6) for d in range(2)]
    for u, n in zip(range(1, 6), [1, 2, 3, 4, 30]):
        lines += [ev(3, 9, user=f"U{u}", sec=i) for i in range(n)]
    con = run_pipeline(cfg_factory(), lines)
    df = user_day(con)
    assert set(df.xs(3, level="day").peer_group) == {"peer_C10"}
    # median 3, MAD 1 -> scale 1.4826
    assert df.loc[("U5", 3), "n_events_peer_z"] == pytest.approx((30 - 3) / 1.4826)
    assert df.loc[("U3", 3), "n_events_peer_z"] == pytest.approx(0.0)


def test_infrastructure_hosts_do_not_define_peers(cfg_factory, run_pipeline):
    # Everyone hits the DC (C1); only the department server distinguishes A from B.
    lines = []
    for u in range(1, 5):
        lines += [ev(0, 9, user=f"U{u}", dst="C1", sec=i) for i in range(10)]
        lines += [ev(0, 10, user=f"U{u}", dst="CA" if u <= 2 else "CB")]
    con = run_pipeline(cfg_factory(**{"features.max_host_user_frac": 0.6}), lines)
    got = dict(con.execute("SELECT entity, anchor FROM features.peer_groups").fetchall())
    assert got == {"U1": "CA", "U2": "CA", "U3": "CB", "U4": "CB"}


def test_fallback_groups_for_users_without_an_anchor(cfg_factory, run_pipeline):
    lines = []
    for u in range(1, 4):
        lines += [ev(0, 9, user=f"U{u}", dst="C1", sec=i) for i in range(5)]  # everyone: DC only
    lines += [ev(0, 9, user="U3", dst="CA")]                                  # U3 also: a dept server
    lines += [ev(0, 9, user="U4", logon="Interactive", dst="C100")]           # U4: local logons only
    lines += [ev(3, 9, user=f"U{u}") for u in range(1, 5)]
    con = run_pipeline(cfg_factory(**{"features.max_host_user_frac": 0.6}), lines)
    kinds = dict(con.execute("SELECT entity, peer_kind FROM features.peer_groups").fetchall())
    assert kinds == {"U1": "infra_only", "U2": "infra_only", "U3": "anchored", "U4": "no_remote"}
    df = user_day(con).xs(3, level="day")
    assert df.loc[["U1", "U2"], "peer_group"].tolist() == ["infra_only"] * 2
    assert df.loc["U1", "peer_n"] == 2 and not pd.isna(df.loc["U1", "n_events_peer_z"])


def test_late_arrival_gets_group_after_own_warmup(cfg_factory, run_pipeline):
    # warmup_days = 2. U1, U2 from day 0; U3 appears on day 5 and uses the same department server.
    lines = [ev(d, 9, user=u, dst="C10") for u in ("U1", "U2") for d in range(10)]
    lines += [ev(d, 9, user="U3", dst="C10") for d in range(5, 10)]
    con = run_pipeline(cfg_factory(), lines)
    p = con.execute("SELECT * FROM features.peer_groups WHERE entity='U3'").df().iloc[0]
    assert (p.first_day, p.peer_from, p.anchor) == (5, 7, "C10")
    df = user_day(con)
    assert df.loc[("U3", 6), "peer_group"] == "unassigned" and pd.isna(df.loc[("U3", 6), "n_events_peer_z"])
    assert df.loc[("U3", 7), "peer_group"] == "peer_C10" and df.loc[("U3", 7), "peer_n"] == 3
    assert df.loc[("U1", 1), "peer_group"] == "unassigned", "no peer z inside the user's own warm-up"


def test_small_anchor_groups_pool_into_other_until_big_enough(cfg_factory, run_pipeline):
    lines = [ev(d, 9, user="U1", dst="C10") for d in range(10)]
    lines += [ev(d, 9, user="U2", dst="C20") for d in range(10)]
    lines += [ev(d, 9, user="U3", dst="C10") for d in range(4, 10)]  # second C10 user, peer_from = 6
    df = user_day(run_pipeline(cfg_factory(**{"features.min_peer_group_size": 2}), lines))
    assert df.loc[("U1", 5), "peer_group"] == "other" and df.loc[("U1", 5), "peer_n"] == 2
    assert df.loc[("U1", 6), "peer_group"] == "peer_C10"
    assert df.loc[("U2", 6), "peer_group"] == "other" and df.loc[("U2", 6), "peer_n"] == 1
    assert pd.isna(df.loc[("U2", 6), "n_events_peer_z"]), "groups below min size give no peer z"


def test_peer_groups_frozen_after_warmup(cfg_factory, run_pipeline):
    base = [ev(d, 9, user=u, dst="C10") for u in ("U1", "U2") for d in range(2)]
    later = [ev(5, 9, user="U1", dst="C99", sec=i) for i in range(50)]  # heavy post-warm-up change
    a = run_pipeline(cfg_factory(), base + [ev(5, 9, user="U2")])
    b = run_pipeline(cfg_factory(), base + [ev(5, 9, user="U2")] + later)
    q = "SELECT * FROM features.peer_groups ORDER BY entity"
    assert a.execute(q).fetchall() == b.execute(q).fetchall()


# ---------------------------------------------------------------- leakage guards
@pytest.fixture(scope="module")
def synthetic_lines():
    out = generate(load_config(overrides={
        "synthetic.n_users": 50, "synthetic.n_days": 10, "synthetic.attack_days": [6, 8],
        "synthetic.n_compromised_users": 3, "synthetic.n_admin_users": 2}))
    auth = [",".join(map(str, r)) for r in out.auth]
    redteam = [",".join(map(str, r)) for r in out.redteam]
    return auth, redteam


def test_no_lookahead(cfg_factory, run_pipeline, synthetic_lines):
    """Features for day d must not change when data after day d is removed."""
    auth, redteam = synthetic_lines
    cut = 6
    full = user_day(run_pipeline(cfg_factory(), auth, redteam))
    trunc = user_day(run_pipeline(cfg_factory(), [l for l in auth if int(l.split(",", 1)[0]) < cut * DAY], redteam))
    past = full[full.index.get_level_values("day") < cut]
    pd.testing.assert_frame_equal(past[MODEL_FEATURES], trunc.loc[past.index, MODEL_FEATURES])


def test_no_lookahead_with_late_arrivals(cfg_factory, run_pipeline):
    """Users arriving later (and the 'other' pool they may graduate from) must not change past peer z."""
    lines = [ev(d, 9, user=f"U{u}", dst="C10", sec=s) for u in range(1, 4) for d in range(12) for s in range(u + d % 3)]
    lines += [ev(d, 9, user=f"L{u}", dst="C10", sec=s) for u in range(1, 4) for d in range(4 + u, 12) for s in range(5)]
    cfg = cfg_factory(**{"features.min_peer_group_size": 4})
    full = user_day(run_pipeline(cfg, lines))
    for cut in (5, 7, 9):
        trunc = user_day(run_pipeline(cfg, [l for l in lines if int(l.split(",", 1)[0]) < cut * DAY]))
        past = full[full.index.get_level_values("day") < cut]
        cols = MODEL_FEATURES + ["peer_group", "peer_n"]
        pd.testing.assert_frame_equal(past[cols], trunc.loc[past.index, cols])
    # L1 arrives day 5 -> assigned day 7 = 4th C10 member; before that U1..U3 sit in the 'other' pool.
    assert full.loc[("U1", 7), "peer_group"] == "peer_C10"
    assert full.loc[("U1", 6), "peer_group"] == "other"


def test_labels_cannot_influence_features(cfg_factory, run_pipeline, synthetic_lines):
    auth, redteam = synthetic_lines
    with_labels = user_day(run_pipeline(cfg_factory(), auth, redteam))
    without = user_day(run_pipeline(cfg_factory(), auth, None))
    pd.testing.assert_frame_equal(with_labels, without)
    banned = ("malicious", "redteam", "label", "attack")
    assert not [c for c in with_labels.columns if any(b in c for b in banned)]


def test_feature_sql_never_reads_label_schema():
    from threatdet.config import SQL_DIR
    for f in SQL_DIR.glob("1*.sql"):
        assert "labels." not in f.read_text().lower(), f.name


def test_model_features_exist_and_are_finite(cfg_factory, run_pipeline, synthetic_lines):
    auth, redteam = synthetic_lines
    df = user_day(run_pipeline(cfg_factory(), auth, redteam))
    assert set(MODEL_FEATURES) <= set(df.columns)
    vals = df[MODEL_FEATURES].astype(float).to_numpy()
    assert not np.isinf(vals).any()
