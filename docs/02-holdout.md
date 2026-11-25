# Frozen holdout (days 15–29)

*The holdout protocol, written before scoring, and the result: the v2 method does not hold.* Back to the [README](../README.md).

### Frozen holdout protocol (LANL days 15–29)

Set up on 2026-11-23, **before** any auth data after day 14 was downloaded:

* **Method frozen by hash.** [reports/holdout_freeze.json](../reports/holdout_freeze.json) records a SHA-256
  of every Python, SQL and config file. `evaluate --freeze` recomputes them and refuses to score if any
  differ. If a pipeline bug forces a change, it will be re-frozen and that will be reported here.
* **Config:** [config/holdout_lanl30.toml](../config/holdout_lanl30.toml) is identical to the default except
  for the data window (days 0–29), the database path, and the test window.
  * Unsupervised detectors are fitted on days 0–7 exactly as before.
  * Everything is scored on days 15–29.
  * The supervised reference is trained on labelled days < 15 (no leave-one-day-out into the holdout).
* **Scored once.** The result is reported whatever it is, next to the days 8–14 numbers.
* **Free consistency check on real data:** features for days 0–14 must be identical in the 15-day and
  30-day databases, because no feature may look ahead. Checked before scoring.
* **What had been seen of days 15–29 before scoring:** only the red-team event count per day (above).
  No features, scores, or label-to-feature joins. Result: [Holdout result](#holdout-result-lanl-days-1529).

### Holdout result (LANL days 15–29)

Scored once on 2026-11-24 with `evaluate --freeze` (the freeze check passed). Before scoring:
- all 30 days were downloaded (508,854,100 auth lines, SHA-256 in the manifest) and built into
  `data/lanl30.duckdb`;
- the no-lookahead check passed on real data: all **152,696 user-days of days 0–14 are identical**
  in the 15-day and 30-day databases, across 41 columns, peer groups and labels included.

Full table: [reports/metrics_lanl30_v2.md](../reports/metrics_lanl30_v2.md). There are 114,393 test
user-days and 47 malicious (prevalence 0.041%, a fifth of days 8–14's 0.21%).

| Detector | PR-AUC (90% CI), days 8–14 → **15–29** | Alerts/day @80% recall (90% CI), 8–14 → **15–29** | Recall, top 50/day, 8–14 → **15–29** |
|---|---|---|---|
| rules (test-informed) | 0.053 → **0.001** | 960 → **4,101** | 16.3% → **3.2%** |
| new_src_remote | 0.029 → **0.001** | 630 → **5,392** | 8.9% → **2.1%** |
| iforest | 0.057 → **0.003** (0.001–0.008) | 1,441 → **2,083** (1,503–3,114) | 19.0% → **6.4%** |
| autoencoder | 0.022 → **0.002** | 1,599 → **2,236** | 10.3% → **4.3%** |
| **two_stage** (pre-registered) | 0.095 → **0.002** (0.001–0.004) | 614 → **2,192** (917–3,156) | 25.0% → **0.0%** |
| supervised (trained on labelled days < 15) | 0.171 → **0.017** (0.005–0.041) | 1,207 → **7,116** | 45.7% → **31.9%** |

**The days 8–14 result does not generalise.** Every detector collapses, and the two-stage detector
goes from best to worst at a 50/day budget. The days 8–14 gains came from features fitted to one
attack phase. The test-informed rule and the gate were chosen after looking at days 8–14 errors, and
this is exactly the overfitting the frozen holdout was set up to catch.

**Why (post-hoc diagnosis, labels used; no method change follows from it in this report):**

| | days 8–14 positives | days 15–29 positives |
|---|---|---|
| Malicious user-days | 116 | 47 |
| User already malicious earlier ("repeat victim") | 5 (4%) | **39 (83%)** |
| Pass the gate (`n_new_src_remote >= 1`) | 81% | **34%** |
| NTLM from a source host new to the user | 83% | **23%** |
| Red-team events per malicious user-day | 5.3 | 1.8 |
| Main attacker source host | C17693 (585 of 613 events) | C17693 (74 of 86) |

- **Same attacker host, different phase.** Days 8–14 are the spread: C17693 reaches each user for
  the first time, which is exactly what "logon from a new source host" detects. In days 15–29,
  83% of malicious user-days are revisits to users already reached. C17693 is in their history by
  then, so the novelty features are silent by construction.
- **The first-time victims in the holdout still are not ranked.** 6 of the 8 first-time victims pass
  the gate (75%), but on weekdays 400–830 benign user-days pass it too, and the forest ranks them
  inside that pool: median rank 411 in their day, best rank 104. With a 50/day budget, a gate
  matched by roughly 700 benign users a day isn't enough on its own.
- **The supervised reference degrades least** (31.9% recall at 50/day), but it learned from the
  days 8–14 labels and still drops 10× in PR-AUC.
- **Small numbers:** 47 positives, 8 of them first-time victims. The CIs are wide, but even their
  upper ends are far below the days 8–14 point estimates.

**What this means for the project:**
- The headline from days 8–14 (614 alerts/day at 80% recall) should be read as "what is reachable
  once you know the attack phase", not as expected performance.
- The honest expected performance on unseen days is in the table above, and no detector here is
  deployable.
- Detecting **revisits** needs different signals from detecting first contact. Two ideas, neither
  run here:
  - entity-pair recency (a source host the user saw only during a short burst, then again);
  - host-level features on the attacker's source, since one host touching 39 users is visible from
    the host side even when each user sees "nothing new".
- Any such change is a new method, which needs fresh, unseen data to evaluate. LANL has no labelled
  days after 29 in this release, so it would have to be reported as exploratory.
