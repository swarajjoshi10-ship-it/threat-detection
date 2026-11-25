import re

from detections.rule import build, choose_threshold, sql_text
from hostrisk.features import build as build_features
from tests.test_hostrisk import con_with

U = ["U1", "U2", "U3", "U4"]
ROWS = ([(0, "A", "H", "S1")] + [(0, u, f"W{u}", "S1") for u in U]   # day 0: cold start everywhere
        + [(5, u, "H", "S2") for u in U]                             # day 5: four users reach H for the first time
        + [(25, "U1", "H", "S2"), (25, "A", "H", "S2")])             # day 25: a suspect user and an old user


def rule_con(rows=ROWS, watch_days=30):
    con = con_with(rows)
    build_features(con, windows=(14,))
    build(con, w=14, min_new=3, watch_days=watch_days, threshold=1.5)
    return con


def q(con, sql):
    return con.execute(sql).fetchall()


def test_trigger_on_fanout():
    con = rule_con()
    # day 5: 4 recent-new users, 1 established (A) -> fanout 4 / 2 = 2 >= 1.5
    assert q(con, "SELECT src_comp, day FROM detections.fanout_triggers") == [("H", 5)]


def test_watch_list_keeps_suspects_after_the_window():
    con = rule_con()
    # plain W=14 fan-out has forgotten U1 by day 25 (first seen day 5 <= 25 - 14) ...
    assert q(con, "SELECT n_recent_new_users FROM hostrisk.host_day_w14 WHERE src_comp='H' AND day=25") == [(0,)]
    # ... the watch list has not: U1 is still a suspect, A (baseline) never is
    assert q(con, "SELECT entity, day FROM detections.fanout_user_alerts ORDER BY day, entity") == \
        [(u, 5) for u in U] + [("U1", 25)]
    assert q(con, "SELECT n_suspect_users, n_baseline_users FROM detections.fanout_host_alerts WHERE day=25") == [(4, 1)]


def test_watch_expires():
    con = rule_con(watch_days=10)
    assert q(con, "SELECT count(*) FROM detections.fanout_user_alerts WHERE day = 25") == [(0,)]


def test_no_lookahead_and_label_free():
    full, cut = rule_con(), rule_con([r for r in ROWS if r[0] <= 5])
    for t in ("fanout_triggers", "fanout_host_alerts", "fanout_user_alerts"):
        a = q(full, f"SELECT * FROM detections.{t} WHERE day <= 5 ORDER BY ALL")
        assert a == q(cut, f"SELECT * FROM detections.{t} ORDER BY ALL")
    code = re.sub(r"--[^\n]*", "", sql_text(14, 1.5, 3, 30)).lower()   # comments may mention labels
    assert "label" not in code and "redteam" not in code


def test_threshold_is_chosen_from_unlabelled_training_days():
    con = con_with(ROWS)
    build_features(con, windows=(14,))
    # only one qualifying host-day in days 1-7 (H, day 5, fanout 2): budget 1/7 per day admits it
    assert choose_threshold(con, 14, 3, budget=1 / 7) == 2.0
    assert choose_threshold(con, 14, 3, budget=0.0) > 2.0
