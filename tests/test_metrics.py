import itertools
import math

import numpy as np
import pytest

from threatdet.metrics import (
    alerts_at_recall, average_precision, cluster_bootstrap, daily_budget_recall, recall_at_budget,
)


def test_alerts_at_recall_without_ties():
    y, s = [1, 0, 1, 0], [4, 3, 2, 1]
    assert alerts_at_recall(y, s, 0.5) == 1
    assert alerts_at_recall(y, s, 1.0) == 3
    assert alerts_at_recall(y, s, 0.0) == 0


def test_alerts_at_recall_ties_equal_brute_force_expectation():
    # One tied group of 5 holding 2 positives: average over every placement of the positives.
    n, q = 5, 2
    for need, r in ((1, 0.5), (2, 1.0)):
        exp = np.mean([sorted(c)[need - 1] + 1 for c in itertools.combinations(range(n), q)])
        assert alerts_at_recall([1, 1, 0, 0, 0], [7] * 5, r) == pytest.approx(exp)
    # Ties ignore row order: an adversarial order gives the same answer.
    assert alerts_at_recall([0, 0, 0, 1, 1], [7] * 5, 0.5) == pytest.approx(2.0)


def test_alerts_at_recall_counts_unscored_positives_as_misses():
    assert alerts_at_recall([1, 0], [2, 1], 0.5, total_pos=2) == 1
    assert math.isinf(alerts_at_recall([1, 0], [2, 1], 1.0, total_pos=2))


def test_recall_at_budget_splits_tied_group_by_expectation():
    y, s = [1, 0, 1, 0, 0, 1], [9, 5, 5, 5, 5, 1]
    assert recall_at_budget(y, s, 1) == 1
    assert recall_at_budget(y, s, 3) == pytest.approx(1 + 1 * 2 / 4)
    assert recall_at_budget(y, s, 6) == 3


def test_daily_budget_recall_is_per_day():
    y = np.array([1, 0, 0, 1])
    s = np.array([0.1, 0.9, 0.5, 0.2])
    day = np.array([0, 0, 1, 1])
    assert daily_budget_recall(y, s, day, 1) == 0.0
    assert daily_budget_recall(y, s, day, 2) == 1.0


def test_average_precision_matches_sklearn():
    sk = pytest.importorskip("sklearn.metrics")
    rng = np.random.default_rng(0)
    y = (rng.random(500) < 0.05).astype(int)
    for s in (rng.random(500) + y * 0.3, rng.integers(0, 4, 500).astype(float) + y):  # continuous, tied
        assert average_precision(y, s) == pytest.approx(sk.average_precision_score(y, s))


def test_average_precision_hand_case_and_unscored_positives():
    assert average_precision([1, 0, 1, 0], [4, 3, 2, 1]) == pytest.approx((1 + 2 / 3) / 2)
    assert average_precision([1, 0], [2, 1], total_pos=2) == pytest.approx(0.5)


def test_cluster_bootstrap_resamples_whole_entities():
    entity = np.repeat(["a", "b", "c", "d"], 3)
    n = len(entity)
    sizes = cluster_bootstrap(np.zeros(n), np.zeros(n), np.zeros(n), entity,
                              lambda y, s, d: len(y), n_boot=50, seed=1)
    assert set(sizes) == {12.0}  # 4 entities drawn, each with all 3 rows
    counts = cluster_bootstrap(np.r_[np.ones(3), np.zeros(9)], np.zeros(n), np.zeros(n), entity,
                               lambda y, s, d: y.sum(), n_boot=200, seed=1)
    assert set(counts) <= {0.0, 3.0, 6.0, 9.0, 12.0}
