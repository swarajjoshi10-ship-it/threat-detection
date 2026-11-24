"""Label-free detectors over the (user, day) feature table.

Every detector has ``fit(frame) -> self`` and ``score(frame) -> np.ndarray`` (higher = more
suspicious). ``frame`` is a slice of ``features.user_day``; it never contains labels, and
``_assert_label_free`` refuses any frame that looks like it does.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from threatdet.config import Config
from threatdet.pipeline import BASELINE_METRICS, COUNT_FEATURES, NOVELTY_FEATURES, PEER_METRICS, RATIO_FEATURES

FEATURE_SETS = ("v1", "v2")  # v1 = first pass (no event-level novelty); v2 = + NOVELTY_FEATURES

Z_COLUMNS = [f"{m}_z" for m in BASELINE_METRICS] + [f"{m}_peer_z" for m in PEER_METRICS]
_BANNED = ("malicious", "redteam", "label", "attack", "is_mal")


def load_features(con, active_only: bool = True) -> pd.DataFrame:
    """The modelling table. Reads only the `features` schema."""
    where = "WHERE is_active" if active_only else ""
    return con.execute(f"SELECT * FROM features.user_day {where} ORDER BY day, entity").df()


def _assert_label_free(frame: pd.DataFrame) -> None:
    bad = [c for c in frame.columns if any(b in c.lower() for b in _BANNED)]
    if bad:
        raise ValueError(f"unsupervised detectors must not see label columns: {bad}")


def _signed_log(x: np.ndarray) -> np.ndarray:
    # z-scores have heavy tails (peer z of 500 is common for scanners); compress them but keep sign.
    return np.sign(x) * np.log1p(np.abs(x))


def feature_set(cfg: Config) -> str:
    fs = cfg["models"].get("feature_set", "v2")
    if fs not in FEATURE_SETS:
        raise ValueError(f"models.feature_set must be one of {FEATURE_SETS}, got {fs!r}")
    return fs


def design_matrix(frame: pd.DataFrame, fset: str = "v2") -> tuple[np.ndarray, list[str]]:
    """Numeric matrix used by the learned detectors (and SHAP later).

    counts -> log1p; ratios as is; z-scores -> signed log; missing z (cold start, no peer group)
    -> 0 plus an explicit indicator so the model can tell "normal" from "unknown".
    """
    _assert_label_free(frame)
    counts = COUNT_FEATURES if fset == "v2" else [c for c in COUNT_FEATURES if c not in NOVELTY_FEATURES]
    cols, names = [], []
    for c in counts:
        cols.append(np.log1p(frame[c].to_numpy(float))); names.append(f"log1p_{c}")
    for c in RATIO_FEATURES:
        cols.append(frame[c].fillna(0).to_numpy(float)); names.append(c)
    for c in Z_COLUMNS:
        cols.append(_signed_log(frame[c].fillna(0).to_numpy(float))); names.append(f"slog_{c}")
    cols.append(frame["n_events_z"].isna().to_numpy(float)); names.append("no_self_baseline")
    cols.append(frame["n_events_peer_z"].isna().to_numpy(float)); names.append("no_peer_group")
    return np.column_stack(cols), names


# --------------------------------------------------------------------------- baselines
class RuleBaseline:
    """Sigma-style rules; score = number of rules that fire (0-4). Heavily tied by design: the
    evaluation breaks ties by expectation under random order, as an analyst queue would."""

    name = "rules"

    def __init__(self, cfg: Config):
        self.p, self.fset = cfg["models"]["rules"], feature_set(cfg)

    def fit(self, frame: pd.DataFrame) -> "RuleBaseline":
        _assert_label_free(frame)
        return self

    def fired(self, frame: pd.DataFrame) -> pd.DataFrame:
        p = self.p
        out = pd.DataFrame(index=frame.index)
        out["new_dst_hosts"] = frame["n_new_dst_hosts"] >= p["min_new_dst_hosts"]
        out["failures"] = frame["n_fail"] >= p["min_failures"]
        if p["ntlm_when_baseline_zero"]:
            out["new_ntlm"] = (frame["n_ntlm"] > 0) & (frame["n_ntlm_base_mean"].fillna(0) == 0)
        out["new_off_hours"] = (frame["n_off_hours"] >= p["min_off_hours"]) & (
            frame["n_off_hours_base_mean"].fillna(0) == 0)
        if self.fset == "v2":
            # TEST-INFORMED (added after the v1 miss analysis looked at days 8-14 labels): NTLM from a
            # source host new to the user, the classic pass-the-hash pattern. Reported as such.
            out["ntlm_from_new_src"] = frame["n_new_src_ntlm"] >= p["min_new_src_ntlm"]
        return out

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        _assert_label_free(frame)
        return self.fired(frame).sum(axis=1).to_numpy(float)


class ZScoreMax:
    """Largest upward deviation from self or peers. No fitting: the baselines are the model."""

    name = "zscore_max"

    def fit(self, frame: pd.DataFrame) -> "ZScoreMax":
        _assert_label_free(frame)
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        _assert_label_free(frame)
        return frame[Z_COLUMNS].fillna(0).clip(lower=0).max(axis=1).to_numpy(float)


# --------------------------------------------------------------------------- learned
class IsolationForestDetector:
    name = "iforest"

    def __init__(self, cfg: Config):
        self.p, self.seed, self.fset = cfg["models"]["iforest"], cfg.seed, feature_set(cfg)

    def fit(self, frame: pd.DataFrame) -> "IsolationForestDetector":
        from sklearn.ensemble import IsolationForest
        X, self.feature_names = design_matrix(frame, self.fset)
        self.model = IsolationForest(
            n_estimators=int(self.p["n_estimators"]), max_samples=min(int(self.p["max_samples"]), len(X)),
            random_state=self.seed, n_jobs=-1).fit(X)
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        X, _ = design_matrix(frame, self.fset)
        return -self.model.score_samples(X)


class AutoencoderDetector:
    """MLP autoencoder; score = mean squared reconstruction error in standardized units."""

    name = "autoencoder"

    def __init__(self, cfg: Config):
        self.p, self.seed, self.fset = cfg["models"]["autoencoder"], cfg.seed, feature_set(cfg)

    def _net(self, d: int):
        import torch.nn as nn
        h = [int(x) for x in self.p["hidden"]]
        enc, prev = [], d
        for w in h:
            enc += [nn.Linear(prev, w), nn.ReLU()]; prev = w
        dec = []
        for w in list(reversed(h[:-1])) + [d]:
            dec += [nn.Linear(prev, w), nn.ReLU()]; prev = w
        return nn.Sequential(*enc, *dec[:-1])  # linear output layer

    def fit(self, frame: pd.DataFrame) -> "AutoencoderDetector":
        import torch
        X, self.feature_names = design_matrix(frame, self.fset)
        self.mu = X.mean(0)
        self.sd = np.where(X.std(0) > 1e-6, X.std(0), 1.0)
        Xt = torch.tensor((X - self.mu) / self.sd, dtype=torch.float32)
        torch.manual_seed(self.seed)
        gen = torch.Generator().manual_seed(self.seed)
        self.net = self._net(X.shape[1])
        opt = torch.optim.Adam(self.net.parameters(), lr=float(self.p["lr"]), weight_decay=float(self.p["weight_decay"]))
        bs = int(self.p["batch_size"])
        self.loss_curve = []
        self.net.train()
        for _ in range(int(self.p["epochs"])):
            perm, total = torch.randperm(len(Xt), generator=gen), 0.0
            for i in range(0, len(Xt), bs):
                xb = Xt[perm[i:i + bs]]
                loss = ((self.net(xb) - xb) ** 2).mean()
                opt.zero_grad(); loss.backward(); opt.step()
                total += loss.item() * len(xb)
            self.loss_curve.append(total / len(Xt))
        self.net.eval()
        return self

    def reconstruction_error(self, frame: pd.DataFrame) -> np.ndarray:
        """Per-feature squared error (rows x features), for explanations."""
        import torch
        X, _ = design_matrix(frame, self.fset)
        Xs = torch.tensor((X - self.mu) / self.sd, dtype=torch.float32)
        with torch.no_grad():
            return ((self.net(Xs) - Xs) ** 2).numpy()

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return self.reconstruction_error(frame).mean(1)


class NoveltyCount:
    """v2 addendum: rank by one event-level novelty count (remote logons from a source host new to
    the user). Added after a days 0-7 check, before days 8-14 were scored (README)."""

    name = "new_src_remote"

    def fit(self, frame: pd.DataFrame) -> "NoveltyCount":
        _assert_label_free(frame)
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        _assert_label_free(frame)
        return frame["n_new_src_remote"].to_numpy(float)


class TwoStageDetector:
    """Gate, then rank: user-days passing the novelty gate (n_new_src_remote >= 1) come first,
    ordered by the Isolation Forest; the rest follow, also ordered by the forest. Pre-registered in
    the README ("Two-stage gate + ranker") before scoring days 8-14."""

    name = "two_stage"

    def __init__(self, cfg: Config):
        self.ranker = IsolationForestDetector(cfg)

    def fit(self, frame: pd.DataFrame) -> "TwoStageDetector":
        self.ranker.fit(frame)
        return self

    def gate(self, frame: pd.DataFrame) -> np.ndarray:
        _assert_label_free(frame)
        return frame["n_new_src_remote"].to_numpy() >= 1

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        s = self.ranker.score(frame)
        # -score_samples lies in (0, 1], so an offset of 2 puts every gated row above every other.
        assert s.min() > 0 and s.max() <= 1
        return np.where(self.gate(frame), 2.0, 0.0) + s


def unsupervised_detectors(cfg: Config) -> list:
    dets = [RuleBaseline(cfg), ZScoreMax(), IsolationForestDetector(cfg), AutoencoderDetector(cfg)]
    if feature_set(cfg) == "v2":
        dets.insert(2, NoveltyCount())
        dets.append(TwoStageDetector(cfg))
    return dets
