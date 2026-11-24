"""Ranking metrics for alert queues. Pure numpy, tie-aware.

Rule scores are heavily tied (many user-days fire "1 rule"). Breaking ties by row order would let a
detector look better or worse by accident, so every metric here uses the *expected* value under a
uniformly random order within tied scores, which is what an analyst working a queue gets.
"""

from __future__ import annotations

import math

import numpy as np


def _groups(y: np.ndarray, s: np.ndarray):
    """Yield (group_size, group_positives) for equal-score groups, highest score first."""
    order = np.argsort(-s, kind="stable")
    s_sorted, y_sorted = s[order], y[order]
    if len(s) == 0:
        return
    breaks = np.flatnonzero(np.diff(s_sorted)) + 1
    starts = np.r_[0, breaks]
    ends = np.r_[breaks, len(s)]
    pos = np.r_[0, np.cumsum(y_sorted)]
    for a, b in zip(starts, ends):
        yield b - a, int(pos[b] - pos[a])


def alerts_at_recall(y, s, recall: float, total_pos: int | None = None) -> float:
    """Expected number of alerts an analyst must review, top-down, to reach `recall`.

    `total_pos` lets positives that were never scored (e.g. dropped rows) count as misses.
    Returns inf if the recall is unreachable.
    """
    y, s = np.asarray(y, int), np.asarray(s, float)
    P = int(total_pos if total_pos is not None else y.sum())
    need = math.ceil(recall * P - 1e-9)
    if need <= 0:
        return 0.0
    n0 = p0 = 0
    for g, q in _groups(y, s):
        if p0 + q >= need:
            j = need - p0
            # Expected position of the j-th positive among g items holding q positives, random order.
            return n0 + j * (g + 1) / (q + 1)
        n0, p0 = n0 + g, p0 + q
    return math.inf


def recall_at_budget(y, s, k: int) -> float:
    """Expected positives captured in the top-k of ONE queue (one day). Returns a count."""
    y, s = np.asarray(y, int), np.asarray(s, float)
    taken = captured = 0.0
    for g, q in _groups(y, s):
        if taken >= k:
            break
        room = min(g, k - taken)
        captured += q * room / g
        taken += room
    return captured


def daily_budget_recall(y, s, day, k: int, total_pos: int | None = None) -> float:
    """Recall when the analyst reviews the top-k user-days of each day."""
    y, s, day = np.asarray(y, int), np.asarray(s, float), np.asarray(day)
    P = total_pos if total_pos is not None else y.sum()
    got = sum(recall_at_budget(y[day == d], s[day == d], k) for d in np.unique(day))
    return got / P if P else float("nan")


def average_precision(y, s, total_pos: int | None = None) -> float:
    """Tie-aware average precision (area under the PR curve, step interpolation).

    Within a tied group every positive gets the group's precision at its end, i.e. the group is
    one threshold, the same convention as sklearn.metrics.average_precision_score. Unscored
    positives (total_pos > y.sum()) contribute precision 0.
    """
    y, s = np.asarray(y, int), np.asarray(s, float)
    P = int(total_pos if total_pos is not None else y.sum())
    if P == 0:
        return float("nan")
    n = p = 0
    ap = 0.0
    for g, q in _groups(y, s):
        n, p = n + g, p + q
        if q:
            ap += (q / P) * (p / n)
    return ap


def cluster_bootstrap(y, s, day, entity, stat, n_boot: int, seed: int) -> np.ndarray:
    """Resample *entities* with replacement (an attacker's user-days are correlated)."""
    y, s, day, entity = map(np.asarray, (y, s, day, entity))
    codes = np.unique(entity, return_inverse=True)[1]
    order = np.argsort(codes, kind="stable")
    bounds = np.r_[0, np.flatnonzero(np.diff(codes[order])) + 1, len(codes)]
    blocks = [order[a:b] for a, b in zip(bounds[:-1], bounds[1:])]
    rng = np.random.default_rng(seed)
    out = np.empty(n_boot)
    for i in range(n_boot):
        pick = rng.integers(0, len(blocks), len(blocks))
        idx = np.concatenate([blocks[j] for j in pick])
        out[i] = stat(y[idx], s[idx], day[idx])
    return out
