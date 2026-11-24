import gzip

import pytest

from threatdet.config import load_config
from threatdet.data.synthetic import SECONDS_PER_DAY, generate, write

SMALL = {
    "synthetic.n_users": 60, "synthetic.n_days": 10, "synthetic.attack_days": [7, 8, 9],
    "synthetic.n_compromised_users": 3, "synthetic.n_admin_users": 3, "synthetic.p_admin_sweep_per_day": 0.5,
}


@pytest.fixture(scope="module")
def small_out():
    return generate(load_config(overrides=SMALL))


def test_deterministic_given_seed(small_out):
    again = generate(load_config(overrides=SMALL))
    assert again.auth == small_out.auth and again.redteam == small_out.redteam
    other = generate(load_config(overrides={**SMALL, "seed": 7}))
    assert other.auth != small_out.auth


def test_lanl_format_and_ordering(small_out):
    times = [r[0] for r in small_out.auth]
    assert times == sorted(times)
    assert all(len(r) == 9 for r in small_out.auth)
    assert all(r[8] in ("Success", "Fail") for r in small_out.auth)
    assert max(times) < SMALL["synthetic.n_days"] * SECONDS_PER_DAY, "events must stay inside n_days"


def test_every_redteam_event_is_a_successful_auth_event(small_out):
    successes = {(r[0], r[1], r[3], r[4]) for r in small_out.auth if r[8] == "Success"}
    assert small_out.redteam, "attack days configured, so there must be labels"
    assert all(rt in successes for rt in small_out.redteam)


def test_attacks_only_on_attack_days(small_out):
    days = {t // SECONDS_PER_DAY for t, *_ in small_out.redteam}
    assert days <= set(SMALL["synthetic.attack_days"])


def test_scenarios_include_benign_anomalies(small_out):
    kinds = {s["type"] for s in small_out.truth}
    assert "benign_admin_sweep" in kinds
    assert kinds & {"attack_noisy", "attack_stealthy"}


def test_write_roundtrip(small_out, tmp_path):
    write(small_out, tmp_path)
    with gzip.open(tmp_path / "auth.txt.gz", "rt") as f:
        lines = f.read().splitlines()
    assert len(lines) == len(small_out.auth)
    assert lines[0].count(",") == 8
    assert (tmp_path / "scenarios.json").exists()
