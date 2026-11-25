# First pass, v2 novelty features and the two-stage gate (days 8–14)

*Validation-window results, in the order they were pre-registered and run.* Back to the [README](../README.md).

## Results (first pass, LANL days 8–14)

`python -m threatdet.evaluate --source lanl --db data/lanl.duckdb --feature-set v1` (~3 min). Fit on 60,336 active
user-days (days 0–7); tested on 55,228 (days 8–14, ~7,900/day), **116 malicious, prevalence 0.21%**.

| Model | PR-AUC (90% CI) | Alerts/day @80% recall (90% CI) | @90% | Recall, top-10/day | top-50/day |
|---|---|---|---|---|---|
| rules | 0.019 (0.013–0.025) | 3,462 (2,420–4,367) | 5,676 | 0.6% | 5.2% |
| zscore_max | 0.004 (0.003–0.008) | 3,934 (3,192–4,343) | 5,088 | 1.7% | 5.2% |
| **iforest** | **0.040** (0.020–0.081) | **2,271** (1,494–2,692) | 3,379 | **6.0%** | **17.2%** |
| autoencoder | 0.011 (0.006–0.023) | 2,700 (2,220–2,882) | 3,674 | 3.4% | 8.6% |
| supervised ceiling | 0.085 (0.059–0.112) | 1,602 (385–2,795) | 2,834 | 10.9% | 34.3% |

**Read honestly:**

* **Nothing here is deployable.** The best unsupervised detector (Isolation Forest) is 19× better than
  random on PR-AUC, but reaching 80% recall still means ~2,300 alerts/day, about 29% of active users.
  With a realistic budget of 50 alerts/day it catches 17% of malicious user-days.
* **Where the model does not win:**
  * The autoencoder loses to Isolation Forest on every metric.
  * The plain z-score detector is the worst of all, *below the rules* on PR-AUC. Taking the max over
    17 z-scores mostly finds noisy accounts.
  * On synthetic data the rules beat Isolation Forest at 5 alerts/day; that does not carry over to LANL.
* **Even the label-trained ceiling is weak** (PR-AUC 0.085). The bottleneck is the representation,
  not the choice of unsupervised model.

**Why (miss analysis; this uses test labels, so it is diagnosis only, not a tuned result):**

* **The attack is a sliver of a busy day.** A malicious user-day has a median of 1,018 events, and
  red-team events are a median 0.36% of them (3 events). Whole-day counts and their z-scores barely
  move. Isolation Forest ranks the median positive 497th of ~9,200 in its day.
* **The signal is in combinations, which day-level counts lose.** 93% of malicious user-days have
  NTLM *and* a source host new to that user, against 9.6% of benign ones. The features record "some
  NTLM" and "some new source" separately, not "NTLM *from* a new source".
* **One host does almost all of it:** 585 of 613 red-team events in days 8–14 come from `C17693`, across
  85 users. A host-level entity view would see it; the user-day view cannot.

That combination was found **by looking at test labels**, so a detector built around it and scored on
days 8–14 would be leakage. The fix to evaluate next is principled, not fitted:

* event-level novelty features, counted per event and then aggregated per user-day (e.g. NTLM logons
  from a never-seen source, remote logons to never-seen destinations);
* stated before scoring, and checked first on the 13 positives in days 0–7.

The miss analysis above will be reported as having informed that change.

### Novelty features (v2): pre-registration

Written down on 2026-11-23, **before** any v2 score on days 8–14 was computed. Feature set `v2` =
`v1` + four per-user-day counts of *events* that combine novelty with a property. "New" means
first seen for this user on this day, with the user's first day as cold start (all 0).

| Feature | Counts events that are… | Why it is general (not fitted to C17693) |
|---|---|---|
| `n_new_src_remote` | remote network logons from a source host new to the user | credential use from an unfamiliar machine, any protocol |
| `n_new_src_ntlm` | NTLM authentications from a source host new to the user | pass-the-hash pattern; textbook, not specific to this red team |
| `n_new_dst_remote` | remote network logons to a destination new to the user | lateral spread, counted per event, not per distinct host |
| `n_new_pair_events` | events on a (source, destination) pair new to the user | new paths through the network |

What is fixed in advance, and what is not:

* **No thresholds and no model settings change.** The learned detectors simply get 4 more `log1p`
  columns. `zscore_max` is unchanged: it uses z-scores only.
* **The rules get one extra rule** (`ntlm_from_new_src`: ≥1 NTLM event from a new source). This rule
  *is* test-informed, because it encodes the combination the miss analysis found. So `rules` v2 is
  reported with that caveat and cannot count as an independent baseline.
* **Check on days 0–7 first**, using the 13 early positives, before scoring days 8–14.
* **Success criterion, set now:** v2 Isolation Forest PR-AUC above the v1 upper CI bound (0.081), and
  fewer alerts/day @80% than v1's lower CI bound (1,494). Anything less is reported as "no clear gain".

**Days 0–7 check (training-period labels only; days 8–14 still unscored):**

| | v1 | v2 |
|---|---|---|
| Isolation Forest PR-AUC (in-sample; fitted without labels) | 0.005 | 0.009 |
| Isolation Forest alerts needed for 80% recall (8 days total) | 17,000 | 9,597 |
| Rules PR-AUC | 0.001 | 0.002 |

Of the 13 early positives, 100% have `n_new_src_remote > 0`, against 8.9% of benign user-days. The
forest dilutes that one column among 41.

**Addendum (after the days 0–7 check, before days 8–14 were scored):** one extra v2 detector,
`new_src_remote`. Its score is the raw `n_new_src_remote` count, with no fitting and no threshold.
It tests whether one well-chosen count beats the learned models.

### v2 results (LANL days 8–14)

`python -m threatdet.evaluate --source lanl --db data/lanl.duckdb --feature-set v2`. Same split, same
seeds; the v1 run was repeated from the same code and reproduced the table above exactly.

| Model | PR-AUC v1 → **v2** (v2 90% CI) | Alerts/day @80% v1 → **v2** (v2 CI) | @90% v2 | Recall top-50/day v2 |
|---|---|---|---|---|
| rules ⚠ test-informed | 0.019 → **0.053** (0.037–0.069) | 3,462 → **960** (723–1,197) | 2,000 | 16.3% |
| zscore_max (unchanged) | 0.004 → 0.004 | 3,934 → 3,934 | 5,088 | 5.2% |
| `new_src_remote` (one count) | — → **0.029** (0.014–0.052) | — → **630** (609–2,035) | 4,103 | 8.9% |
| iforest | 0.040 → **0.057** (0.033–0.101) | 2,271 → **1,441** (1,103–1,806) | 2,618 | 19.0% |
| autoencoder | 0.011 → **0.022** (0.012–0.044) | 2,700 → **1,599** (1,419–1,949) | 2,438 | 10.3% |
| supervised ceiling | 0.085 → **0.171** (0.131–0.232) | 1,602 → **1,207** (178–2,282) | 3,545 | 45.7% |

**Against the pre-registered criterion:**

* The alerts criterion is met, narrowly: 1,441 alerts/day < 1,494.
* The PR-AUC criterion is **not met**: 0.057 is not above 0.081, and the two CIs overlap.
* So the verdict is "**alert volume down ~37%, ranking quality not clearly better**".

**Where the model does not win, again:**

* **A single unfitted count beats every model at 80% recall:** `new_src_remote` needs 630 alerts/day,
  against 1,441 for Isolation Forest and 1,207 for the label-trained ceiling.
* **It has a cliff after that.** About 10% of malicious user-days have no remote logon from a new
  source, and the count cannot rank those above anyone. It needs 4,103 alerts/day for 90%.
* **Its top of queue is poor:** PR-AUC 0.029, and 8.9% recall at 50 alerts/day. Many benign users
  also have one or two logons from a new machine, so the top scores are ties among them.
* **The forest is the better short queue (19% at 50/day); the count is the better wide net.** That
  points to a two-stage design: a novelty gate, then a ranker within it.
* **The test-informed rules improve most,** as expected; that number is not evidence.

**Still not deployable:** 630 alerts/day is ~8% of active users. The supervised ceiling doubled its
PR-AUC, which confirms the representation was the bottleneck, but its 0.171 shows user-day
features still lose most of the signal. The next lever is the entity, not the model:
one source host (`C17693`) logs on as 85 different users, which is trivial at host level.

On synthetic data v2 is mixed (Isolation Forest PR-AUC 0.543 → 0.552, autoencoder 0.644 → 0.613),
because the synthetic attacks mostly reuse a source host the user already had. That is a generator
choice, recorded in `reports/metrics_synthetic_v{1,2}.md`, not evidence either way.

### Two-stage gate + ranker: pre-registration

Written down on 2026-11-23, before any two-stage score on days 8–14 was computed. **One variant
only**, to avoid trying several gates and keeping the best:

* **Stage 1, gate:** `n_new_src_remote ≥ 1`, i.e. at least one remote logon from a source host new to
  the user. Unfitted, no labels.
* **Stage 2, ranker:** the v2 Isolation Forest score, unchanged (same fit on days 0–7, same seed).
* **Queue order:** all gated user-days first, ranked by the forest, then everything else, ranked by
  the forest. So the analyst never sees an ungated user-day before a gated one.
* **Success criterion, set now:** two-stage beats *both* parts on the metric each one is good at.
  * alerts/day @80% at or below `new_src_remote`'s 630;
  * recall at 50/day at or above the forest's 19.0%.
* **Disclosure:** this design was chosen *after* seeing v2 results on days 8–14. It is the third
  design decision informed by the test days, so its test numbers are optimistic. The clean check is
  data the project has never seen (see [02-holdout.md](02-holdout.md)).

**Days 0–7 check** (training-period labels; 13 positives; forest scored in-sample, fitted without labels):

| | PR-AUC | Alerts/day @80% | Recall top-50/day |
|---|---|---|---|
| `new_src_remote` | 0.006 | 639 | 7.7% |
| iforest | 0.009 | 1,200 | 30.8% |
| two_stage | **0.014** | **414** | **30.8%** |

**Days 8–14 result:**

| Model | PR-AUC (90% CI) | Alerts/day @80% (90% CI) | @90% | Recall top-10/day | top-50/day |
|---|---|---|---|---|---|
| `new_src_remote` (gate alone) | 0.029 (0.014–0.052) | 630 (609–2,035) | 4,103 | 2.6% | 8.9% |
| iforest v2 (ranker alone) | 0.057 (0.033–0.101) | 1,441 (1,103–1,806) | 2,618 | 6.9% | 19.0% |
| **two_stage** | **0.095** (0.060–0.140) | **614** (438–765) | **1,514** | **7.8%** | **25.0%** |
| supervised ceiling (labels) | 0.171 (0.131–0.232) | 1,207 (178–2,282) | 3,545 | 13.8% | 45.7% |

* **Both pre-registered criteria are met:** 614 ≤ 630 alerts/day at 80% recall, and 25.0% ≥ 19.0%
  recall at 50/day.
* **The gain over the parts comes from the 90% end and the short queue:**
  * At 90% recall it needs 1,514 alerts/day, against 4,103 for the count and 2,618 for the forest.
  * At 50/day it catches a quarter of malicious user-days, against a fifth for the forest.
  * Its PR-AUC is above the v1 forest's upper CI bound.
* **The model does not beat the labelled ceiling on short queues** (25% vs 46% at 50/day). It does beat
  it at 80% recall (614 vs 1,207), where the ceiling's CI is very wide.
* **Still ~8% of active users per day at 80% recall.** This is better triage, not a deployable
  detector.

**How much to trust it:**

* Days 8–14 have now informed three design decisions: the v2 features, the extra rule, and this
  gate. Each was pre-registered, and the days 0–7 check agreed every time. But the
  test days are no longer clean.
* **A clean holdout exists.** The red-team file has 86 more events on days 15–29 (days 15, 20–22,
  26–29), and none of that period has been ingested. Scoring days 15–29 with everything frozen
  as-is (features, config, seeds, the two-stage gate) is the honest estimate.
* Doing that needs `auth.txt.gz` up to day 30: roughly another 1.9 GB and ~1 h of download.
