from tests.conftest import DAY, ev


def test_normalization(cfg_factory, run_pipeline):
    lines = [
        ev(0, 9, sec=5),
        ev(1, 23, ok=False, auth="?", dst="?"),
    ]
    con = run_pipeline(cfg_factory(), lines, features=False)
    rows = con.execute(
        "SELECT ts, day, hour, src_user, src_domain, dst_comp, auth_type, success FROM auth_events ORDER BY ts"
    ).fetchall()
    assert rows[0] == (9 * 3600 + 5, 0, 9, "U1", "DOM1", "C10", "Kerberos", True)
    assert rows[1] == (DAY + 23 * 3600, 1, 23, "U1", "DOM1", None, None, False)


def test_max_days_filter(cfg_factory, run_pipeline):
    con = run_pipeline(cfg_factory(**{"data.max_days": 2}), [ev(d, 1) for d in range(5)], features=False)
    assert con.execute("SELECT max(day), count(*) FROM auth_events").fetchone() == (1, 2)


def test_machine_and_anonymous_principals(cfg_factory, run_pipeline):
    lines = [ev(0, 1), ev(0, 2, user="C55$"), ev(0, 3, user="ANONYMOUS LOGON")]
    con = run_pipeline(cfg_factory(), lines, features=False)
    assert con.execute("SELECT list(src_user) FROM auth_events").fetchone()[0] == ["U1"]
    con = run_pipeline(cfg_factory(**{"features.include_machine_accounts": True}), lines, features=False)
    got = dict(con.execute("SELECT src_user, is_machine OR is_anonymous FROM auth_events").fetchall())
    assert got == {"U1": False, "C55$": True, "ANONYMOUS LOGON": True}


def test_redteam_labels_and_match_rate(cfg_factory, run_pipeline):
    auth = [ev(2, 3, user="U7", src="C1", dst="C9", sec=11), ev(2, 4)]
    redteam = [
        f"{2 * DAY + 3 * 3600 + 11},U7@DOM1,C1,C9",   # present in auth
        f"{4 * DAY},U8@DOM1,C2,C3",                   # absent -> unmatched, still labelled
    ]
    con = run_pipeline(cfg_factory(), auth, redteam, features=False)
    assert con.execute("SELECT count(*) FILTER (WHERE matched_in_auth), count(*) FROM labels.redteam_match").fetchone() == (1, 2)
    labelled = con.execute("SELECT entity, day FROM labels.user_day ORDER BY entity").fetchall()
    assert labelled == [("U7", 2), ("U8", 4)]
