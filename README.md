# Entity-Level Behavioral Anomaly Detection & Alert Triage

Detect compromised accounts in enterprise authentication telemetry by baselining each **user's own
behaviour** (and their peers'), then rank user-days for an analyst. The question this project answers
is operational: *at a fixed recall, how many alerts per day does an analyst have to look at, and does
a model beat a simple rule at that?*

> Status: **ingestion, features (v1 + pre-registered v2 novelty), seven detectors and the evaluation
> harness done and tested.** LANL results are in [Results](#results-first-pass-lanl-days-814) and
> [v2 results](#v2-results-lanl-days-814) and the [two-stage gate](#two-stage-gate--ranker-pre-registration):
> 614 alerts/day at 80% recall on days 8–14 (from 2,271 in the first pass). **On the frozen holdout
> (days 15–29) it does not hold: 2,192 alerts/day at 80% recall, PR-AUC 0.002, and none of the 47
> malicious user-days in the top 50/day** ([holdout result](#holdout-result-lanl-days-1529)). The
> novelty gate detects an attacker's first contact with a user; most holdout attacks are repeat visits.
> No detector is deployable. [SHAP evidence packs](#alert-explanations-shap) for the top alerts are done.
> [LLM triage](#llm-triage-results) with a local 7B model fails all pre-registered criteria on days
> 8–14 and on the holdout (0% fully faithful alerts across 1,100; it never dismisses, even when the
> whole queue is false).

## Design choices that differ from the usual "classify the flows" project

| Choice | Why |
|---|---|
| Unit of detection = **(user, day)**, not a single event/flow | Analysts triage accounts, not packets. Lateral movement is a *change in an entity's behaviour* (new hosts, NTLM, odd hours), which is invisible row by row. |
| **Rolling per-user baselines** (previous 7 days, today excluded) + **peer-group** deviation | "50 hosts" is normal for an admin and alarming for an accountant. |
| Headline metric = **alerts/day at 80/90% recall** + PR-AUC | Accuracy is meaningless at ~0.1% prevalence; alert volume is the analyst's real cost. |
| Rule/Sigma-style baseline is a first-class competitor | The README will report where the model does **not** win. |
| Labels physically separated (`labels` schema) and only used for evaluation | Unsupervised models must not see labels; tests enforce it. |

## Quick start

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev,models]"   # CPU torch: add --index-url https://download.pytorch.org/whl/cpu
.\run.ps1 pipeline      # synthetic data -> DuckDB -> features   (or: make pipeline)
.\run.ps1 evaluate      # fit on days 0-7, score days 8-14 -> reports/metrics_synthetic_v2.md (--feature-set v1 for the first pass)
.\run.ps1 test
```

Everything is driven by [config/default.toml](config/default.toml) (seed, paths, windows, thresholds).

## Getting the data

**Primary: LANL "Comprehensive, Multi-Source Cyber-Security Events"** (<https://csr.lanl.gov/data/cyber1/>),
`auth.txt.gz` + `redteam.txt.gz`. Read the dataset's terms on that page before downloading.

The files sit behind a short form on that page (email + intended use). Fill it in, then pass the
signed download links it reveals (or paths to files you downloaded by hand) — both options accept either:

```powershell
.\.venv\Scripts\python -m threatdet.data.download_lanl --days 15 --auth-file "<auth.txt.gz link>" --redteam-file "<redteam.txt.gz link>"
.\.venv\Scripts\python -m threatdet.data.download_lanl --days 15 --auth-file D:\lanl\auth.txt.gz --redteam-file D:\lanl\redteam.txt.gz
```

The full `auth.txt.gz` is 7.63 GB (58 days), time-sorted. Only the prefix covering `--days` is fetched.
The LANL server throttles each connection (~50 KB/s measured) and drops long connections (a first,
sequential attempt died at day 2.4 after 47 min). So the downloader:

* fetches 32 MB byte-range **segments over 6 parallel connections** (4 connections measured ~4x one);
* resumes each segment from its last byte after a drop, with exponential back-off; fails fast on 4xx
  (an expired signed link);
* decompresses segments in order and **stops scheduling at the first event on/after `--days`**;
* reuses segments already on disk if re-run, then trims to exactly `day < N` and deletes the segments.

Reference run (15 days): 55 segments = 1.85 GB of 7.63 GB, 0 reconnects, ~50 min →
**259,576,822 events**. Output: `data/raw/lanl/{auth.txt.gz, redteam.txt.gz, manifest.json}` (the
manifest records line count + SHA-256 of the kept events, with the signed token redacted).

```powershell
.\.venv\Scripts\python -m threatdet.pipeline all --source lanl --db data/lanl.duckdb
```

### What the 15-day LANL subset looks like

Ingest + features take ~5 min on a 16 GB laptop (`data/lanl.duckdb`, 1.1 GB).

| | |
|---|---|
| Events kept (user principals only; machine accounts + ANONYMOUS LOGON dropped) | 88,445,963 of 259,576,822 (34%) |
| Users | 11,243 |
| Active user-days | 115,564 (152,696 rows in the dense grid) |
| Red-team events in days 0–14 | 663, of which **649 (97.9%) match an auth event** |
| Malicious user-days / users | **129 / 90 → prevalence 0.112%** |

* **Label noise, measured:** all 14 unmatched red-team rows have an auth event at the same second, same
  user, same source (C17693), NTLM network logon, but a *different destination host*. The red-team
  file and auth log disagree on the target. Labels are per user-day, so these still count.
* **Attacks are concentrated:** 116 of 129 malicious user-days fall on days 8, 9, 12, 13, 14
  (day 8: 43, day 12: 39). Days 1–2 hold 6 malicious user-days with no baseline history (cold start).
  → Planned split: fit/tune on days 0–7, **evaluate on days 8–14** (116 positives).
* **Weekly cycle:** days 3–4 and 10–11 have ~55% of weekday users (weekends). No attacks fall on them.
* **Off-hours** were set from the global hourly volume (no labels used): 0–5 and 19–23 are the overnight
  floor (~2.6M events/h vs ~5M at peak). The floor is half the peak, so many "user" accounts are
  automated — a reason not to over-trust off-hours alone.
* **Peer-group coverage (fixed):** the first version assigned groups only from a global day 0–2
  warm-up, which left 54% of users without a group. Of those, 2,528 touched only infrastructure
  hosts, 2,164 first appeared after day 2, and 1,336 had no remote logons. Now every user gets an
  assignment from their *own* first 3 days (see [Features](#features-per-user-per-day)):

  | Peer kind | Users | Median group size on days 8–14 |
  |---|---|---|
  | anchored (101 department-server groups) | 6,277 | 214 |
  | infra_only (remote logons, but only to DCs/shared servers) | 3,048 | 2,983 |
  | no_remote (no remote network logons) | 1,918 | 1,732 |
  | `other` pool (anchor group still < 5 members) | — | 356 |

  75% of active user-days have a peer z-score; the other 25% are users inside their own warm-up.
  On the evaluation days (8–14), **114 of 116 malicious user-days** have peer z-scores (the 2 that
  don't belong to users still in their warm-up). One measurement, not used to design anything: 26 of
  those 116 sit in the small `other` pool (1,980 user-days), so the pool is ~10× over-represented.
  `peer_group` is not a model feature, but this deserves a look in the miss analysis.

**Synthetic (development only):** [src/threatdet/data/synthetic.py](src/threatdet/data/synthetic.py)
writes byte-compatible LANL-format files, so the real pipeline runs unchanged. It includes benign
anomalies (admin sweeps, some in a late maintenance window; users on an unfamiliar workstation) and two
attack styles (noisy NTLM bursts to many new hosts vs. stealthy 2-3 host Kerberos moves in office hours).
`scenarios.json` records which is which for error analysis. **Synthetic results are sanity checks, not
evidence**; they are easy by construction.

## Pipeline

```
auth.txt.gz ─▶ sql/01_ingest_auth.sql    ─▶ auth_events                (normalized; '?' -> NULL)
redteam.txt.gz ▶ sql/02_ingest_labels.sql ─▶ labels.redteam_events / redteam_match / user_day
auth_events ─▶ sql/10_user_day_base.sql  ─▶ features.user_day_base     (per user-day aggregates)
            ─▶ sql/11_user_day_baseline.sql ▶ features.user_day_dense / user_day_baseline
            ─▶ sql/12_peer_groups.sql    ─▶ features.peer_groups, features.user_day  (model table)
```

Orchestrated by [src/threatdet/pipeline.py](src/threatdet/pipeline.py); SQL placeholders (`{{name}}`)
are rendered by [sqlrun.py](src/threatdet/sqlrun.py), which fails on any missing *or unused* parameter.

### Features (per user, per day)

* **Volume / failure:** events, failures, failure ratio.
* **Spread:** distinct destination and source hosts, distinct remote (network-logon) destinations.
* **Novelty:** destination/source hosts never seen for this user before today (the user's first observed
  day is cold start and counts as 0, not "everything is new").
* **Timing:** off-hours events and ratio, distinct active hours.
* **Protocol:** NTLM count, distinct auth types / logon types.
* **Self-baseline z-scores:** `(x − mean₇) / max(std₇, floor)` over the previous 7 calendar days,
  today excluded; inactive days count as zero; NULL until 3 days of history. The std floor (1 for
  counts, 0.05 for ratios) stops perfectly regular users from producing infinite z-scores.
* **Peer z-scores:** robust `(x − median) / max(1.4826·MAD, floor)` against the same-day peer group;
  NULL if fewer than 5 group members that day.
  * **Assignment:** from the user's *own* first 3 days (starting on their first active day), usable
    from the day after that warm-up ends, then frozen. A late arrival gets a group 3 days after they
    appear, never earlier and never from future data.
  * **Anchored:** peers share the most-used *non-infrastructure* remote host. Infrastructure = hosts used
    by >20% of users in the global day 0–2 warm-up (e.g. domain controllers); fixed after that.
  * **Fallbacks:** users whose warm-up had remote logons only to infrastructure → `infra_only`; users
    with no remote network logons → `no_remote`.
  * **Small anchors:** an anchor group counts on day *d* only once ≥5 users with that anchor have been
    assigned by *d*; until then its members are pooled into `other`. Because group size is evaluated
    per day from past assignments only, `peer_group` is a per-day column.

### Leakage controls (all enforced by tests)

| Risk | Control | Test |
|---|---|---|
| Future data in features | windows end at `1 PRECEDING`; "new host" uses first-seen ≤ today | `test_no_lookahead` recomputes on data truncated at day 6 and requires identical features for days < 6 |
| Labels in features | labels live in a separate schema; feature SQL never references it | `test_labels_cannot_influence_features` (features identical with/without redteam file), `test_feature_sql_never_reads_label_schema` |
| Attack moving a user's peer group | peer anchor frozen after the user's own warm-up | `test_peer_groups_frozen_after_warmup` |
| Late arrivals / group sizes leaking the future | assignment usable only from `peer_from`; group size counted from assignments made by day *d* | `test_no_lookahead_with_late_arrivals` (truncates at days 5, 7, 9 incl. `peer_group`, `peer_n`) |
| Silent SQL parameter typos | renderer rejects missing/unused params | `test_sqlrun.py` |

Tests were also mutation-checked by hand: letting the baseline window include the current day fails
3 tests; removing the cold-start rule fails 1; using a peer assignment before `peer_from` fails 3.

## Detectors

All detectors rank active user-days; [src/threatdet/models/detectors.py](src/threatdet/models/detectors.py).

| Detector | What it is | Fitted on |
|---|---|---|
| `rules` | Sigma-style: score = number of rules firing (≥3 new remote hosts; ≥5 failures; NTLM by a user with no NTLM in their 7-day baseline; off-hours activity by a user with none in their baseline). Thresholds set from domain knowledge, not labels. | nothing |
| `zscore_max` | Largest upward self or peer z-score | nothing |
| `iforest` | Isolation Forest (300 trees) on the design matrix | days 0–7, no labels |
| `autoencoder` | PyTorch MLP 37→32→8→32→37; score = reconstruction MSE | days 0–7, no labels |
| `supervised_ceiling` | Gradient boosting **with labels**, leave-one-day-out. A reference, not a deliverable: the same attacker accounts appear on other days, so it is optimistic. | all other days, with labels |

Design matrix: counts `log1p`, ratios as is, z-scores signed-log (`sign·log1p|z|`, they reach the
hundreds), missing z → 0 plus `no_self_baseline` / `no_peer_group` indicators.

**Metrics** ([src/threatdet/metrics.py](src/threatdet/metrics.py)): PR-AUC; alerts/day needed to
reach 50/80/90% recall over the test days (one global threshold); recall when an analyst reviews the
top-k user-days *of each day*. Rule scores tie heavily, so every metric takes the **expected value
under random order within ties** (exact formula, tested against brute force), never a lucky row order.
90% CIs come from a **cluster bootstrap over users** (300 resamples), because one attacker's user-days
are correlated.

**Label isolation is tested behaviourally:** `test_run_end_to_end_and_unsupervised_scores_ignore_labels`
scrambles `labels.user_day` and requires every unsupervised score to be bit-identical, and the
supervised one to change. Detectors also refuse frames with label-like columns.

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
  data the project has never seen (see below).

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

### Frozen holdout protocol (LANL days 15–29)

Set up on 2026-11-23, **before** any auth data after day 14 was downloaded:

* **Method frozen by hash.** [reports/holdout_freeze.json](reports/holdout_freeze.json) records a SHA-256
  of every Python, SQL and config file. `evaluate --freeze` recomputes them and refuses to score if any
  differ. If a pipeline bug forces a change, it will be re-frozen and that will be reported here.
* **Config:** [config/holdout_lanl30.toml](config/holdout_lanl30.toml) is identical to the default except
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

Full table: [reports/metrics_lanl30_v2.md](reports/metrics_lanl30_v2.md). There are 114,393 test
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

## Alert explanations (SHAP)

`python -m triage.explain --source lanl` writes one **evidence pack** per alert for the top 50
two-stage alerts of each test day ([reports/evidence_lanl_v2.jsonl](reports/evidence_lanl_v2.jsonl),
summary in [reports/explanations_lanl_v2.md](reports/explanations_lanl_v2.md)). These packs are what
the LLM triage step will read, so they contain no labels (tested).

**Why it lives in `triage/`, not `src/threatdet/`:** the scoring method is frozen for the holdout, and
the freeze hashes everything under `src/threatdet/`. The explainer only reads the fitted forest, so
keeping it outside the frozen tree means the holdout is scored by exactly the frozen code (a test
checks that `triage/` is not in the fingerprint).

**How an explanation maps onto the score.** The gate is a single fact (`n_new_src_remote >= 1`) and
is reported with its raw count. The ranker is explained with TreeSHAP, which is exact for an
Isolation Forest: the score is `2^(-E[h]/c(ψ))`, and SHAP splits the expected path length `E[h]`
additively over features. Each factor's **push** is `-φ`, so a positive push means the feature made
the user-day isolate faster (look more anomalous). Each factor carries the raw values behind it: the
count, the user's own 7-day mean, the z-score, and the peer group and its size.

**Checks (LANL days 8–14, 350 alerts):**

| Check | Result |
|---|---|
| SHAP reconstruction of the forest score, max abs error | 1.0e-15 |
| Refit reproduces the two_stage scores stored by `evaluate` | yes (atol 1e-9) |
| Deletion check: reset the top-k SHAP features to the training median vs k random features | k=1: score drop 0.021 vs 0.0025, top beats random on 99.4% of alerts; k=3: 0.054 vs 0.008, 100%; k=5: 0.080 vs 0.014, 100% |

The deletion check sets one column of a correlated pair (for example `log1p_n_ntlm` and its z-score)
without the other, which creates off-manifold points. So the absolute drops are only indicative; the
comparison with random features is the point.

**What the explanations show (labels used for this paragraph only):**
- Of the 350 alerts, 29 are true. Every one of the 350 passed the gate, as expected at 50 alerts/day.
- `n_new_src_ntlm` (NTLM logons from a source host new to the user) is the leading factor for 23 of
  the 29 true alerts, but also for 150 of the 321 false ones. The forest mostly re-ranks *inside* the
  gate by how much new-source NTLM there is, so it can't separate attackers from busy admins.
- The top-ranked false alert (U1718, day 8) is led by a 94% failure ratio. The same pack shows the
  user's own 7-day mean failure ratio is 98%: normal for that account, which looks like a service
  account. The forest doesn't weigh "usual for this user" strongly enough, but the evidence for
  dismissing the alert is in the pack.
- That is the case for an LLM triage step: read the pack and check each anomaly against the user's
  own baseline before escalating. Whether that helps is the next experiment, measured at a fixed
  alert budget and with a faithfulness check on every claim the LLM makes.

**Bug caught on the first run:** `--source lanl` alone did not move `db_path`, so the explainer silently
read the synthetic database and labelled the output "lanl". This was caught because the numbers
didn't fit: 300 users/day, a 6-day window, and a refit that didn't match the stored scores. The CLI
now picks `data/lanl.duckdb` for `--source lanl` and refuses a LANL run on a database with fewer than
1,000 users. A second "mismatch" was the explainer rounding scores to 4 decimals before comparing
them; that is fixed too.

## LLM triage: pre-registration

Written on 2026-11-24, **before any LLM call**. Code: [triage/llm.py](triage/llm.py), offline tests in
[tests/test_llm.py](tests/test_llm.py) (fake client, no API calls).

**What the model does.**
- Model and settings: `claude-opus-5-5`, effort `medium` (the model's default, not tuned), structured
  JSON output, one alert per request.
- Input: the alert's evidence pack flattened into a fact table (`key = value`). There are no labels,
  no other alerts, and no detector queue rank, so it can't anchor on the detector's order.
- Output: a verdict (`escalate` / `investigate` / `dismiss`), a 0–100 risk, a short summary, a benign
  reading if there is one, next steps, and 2–6 **claims**. Each claim cites one fact key, copies its
  value, and may say whether it is above, below or similar to another fact key.
- Prompt fingerprint: SHA-256 of the system prompt `2ada62d18942cc74…`, of the output schema
  `655bd13dbbfe7e59…`; prompt version `v1`. Any change to either is a new version and is reported
  as such.

**Test-informed content in the prompt (disclosed).** The `escalate` definition names "remote or NTLM
logons from source hosts new to the user". That is textbook lateral movement, but I wrote it after
the days 8–14 miss analysis found exactly that pattern. On days 8–14 it may help the LLM in a way
that wouldn't carry over to unseen data, and the holdout shows that pattern largely disappears.

**Faithfulness is checked mechanically, with no LLM judge.** For every claim, the checker verifies:
- the cited key exists;
- the copied value matches, allowing only the rounding the model used (for example 0.94 or 94% for
  0.9369, but not 0.95);
- any stated above/below/similar relation actually holds;
- every number in the free text appears among the facts. Derived numbers ("5x the usual") count as
  unfaithful, and the prompt forbids them.

An alert is **fully faithful** only if all of this passes and it has at least one claim.

**Workflow.**
1. **Pilot:** 20 alerts from days 1–7. Those days are in-sample for the forest; they're used only to
   check the output format and faithfulness. Pilot labels are not looked at. If the pilot shows a
   format or schema bug, it is fixed and becomes prompt `v2`, with the change listed here.
2. **Run once:** days 8–14 (350 alerts, top 50/day of `two_stage`) and days 15–29 (750 alerts),
   through the Batch API. Responses are cached, so the evaluation is reproducible without new calls.

**Criteria, fixed now:**

| Question | Data | Criterion |
|---|---|---|
| Is it faithful? | all 1,100 alerts | ≥ 90% of alerts fully faithful, and ≥ 97% of claims with a correct value |
| Does triage reorder the queue usefully? | days 8–14 (29 of the 116 positives are in the queue) | recall at 10/day after triage beats the detector's own order (7.8%) by at least 3 more true alerts in the top 10/day, **and** at most 2 of the 29 true alerts are dismissed |
| How much of a false queue can it clear? | days 15–29 (the top-50/day queue contains **0** of the 47 positives, known before any call) | reported as the share of alerts dismissed and the share escalated; no recall claim is possible here |

**Deviation, recorded 2026-11-24 before any LLM call: local model instead of Claude.**
- **Why:** no paid API is used, so the run is free and fully local.
- **Model:** `qwen2.5:7b` (Qwen2.5 7B Instruct, 4-bit, about 4.7 GB) served by Ollama 0.32.5 on a
  laptop RTX 4050.
- **Settings:** greedy decoding (`temperature 0`, `seed 42`), context 8,192 tokens.
- **What stays the same:** the system prompt, fact table and JSON schema (Ollama constrains decoding
  to the schema), the faithfulness checker, and all the criteria above.
- **Run mode:** requests go one at a time locally instead of through the Batch API.
- **Expectation, stated in advance:** a 7B model will triage worse and make more unfaithful claims
  than a frontier model. The point of the experiment shifts towards whether the checker catches
  those errors.
- **Claude path:** the Claude backend remains in the code (`--backend anthropic`) for anyone with an
  API key.

**Pilot (v1) result and the one allowed revision (v2), recorded before v2 ran.** The v1 pilot (20
alerts, days 1–7, 38 s per alert) parsed 20 of 20 responses. **0 of 20 alerts were fully faithful,
and 37% of claims had a correct value.** Every cited key existed. The failures were:
- **invented arithmetic:** for example `log1p(0.9772) = 5.3486`, which is also wrong;
- **decorated values:** `"= 304"`, `"{165}"`, `">=395"`;
- **comparisons between unrelated quantities:** for example a host count "above" a failure ratio.
  These passed my numeric relation check, so that check was too weak;
- **risk on the wrong scale:** 2–6 on a 0–100 scale.

**v2 changes (prompt SHA `ed87fe04669f015c…`; the schema is unchanged):**
- the prompt now spells out the value format, the only allowed comparison pairs (a value and its
  own `_base_mean`, or path length and expected path length), forbids transforms, and anchors the
  risk scale;
- the checker is **stricter**: a relation only counts between those pairs;
- the strict value check stays the primary metric, and a diagnostic now counts values that would
  match once decoration like `=` or braces is stripped, to separate formatting noise from wrong
  numbers;
- context is cut to 4,096 tokens so the model fits on the GPU; with greedy decoding this doesn't
  change outputs that fit.

**v2 is final whatever its pilot shows.** There is no v3 tuning on the pilot; the full run uses v2.

The days 8–14 baseline order gives recall 4.3% at 5/day, 7.8% at 10/day and 14.7% at 25/day; triage
can only reorder within the top 50, so recall at 50/day stays 25.0%. The results get reported
against these criteria whichever way they come out.

## LLM triage: results

**v2 pilot (20 alerts, days 1–7):**
- 0% of alerts were fully faithful.
- 8% of claim values were correct, and another 40% were wrong only in format.
- 26% of relations compared an allowed pair.
- Every alert was escalated (15) or investigated (5); median risk was 98.
- Each alert took about 30 s.

Per the pre-registration, the full run went ahead on v2 unchanged.

**Days 8–14 (350 alerts, run once):** all 350 responses parsed. Evaluation file:
[reports/triage/eval_evidence_lanl_v2__qwen2.5-7b__v2.json](reports/triage/eval_evidence_lanl_v2__qwen2.5-7b__v2.json).

| Criterion | Target | Result | Verdict |
|---|---|---|---|
| Alerts fully faithful | ≥ 90% | **0%** | fail |
| Claims with a correct value | ≥ 97% | **20.0%** (another 24.6% wrong only by decoration such as `>=304`) | fail |
| Recall at 10/day after triage vs detector order | +3 true alerts over 7.8% | **6.0%** (2 fewer true alerts) | fail |
| True alerts dismissed | ≤ 2 of 29 | 0, but nothing was dismissed at all | vacuous |

What the model did:
- **It never dismisses.** It marked 188 alerts escalate and 162 investigate, with a median risk of
  87. Re-ordering by verdict and risk lowered recall at 5/day (4.3% → 2.6%), 10/day (7.8% → 6.0%) and
  25/day (14.7% → 10.3%).
- **It separates true from false alerts only weakly.** It escalated 19 of 29 true alerts (66%) and
  169 of 321 false ones (53%).
- **It cites real fields but gets most values and comparisons wrong.** 99.2% of claims name a key
  that exists. Only 20% copy its value correctly, and 25% of relations compare an allowed pair.
- **It rarely invents numbers in free text.** Only 0.9% of alerts contain an ungrounded number.

**Conclusion:** a 7B local model is not a usable triage layer here; it fails every pre-registered
criterion. The deterministic faithfulness checker is the reusable part: it catches every failure
mode found in the pilot automatically and without an LLM judge.

**Days 15–29 holdout (750 alerts, run once):** all 750 responses parsed. Evaluation file:
[reports/triage/eval_evidence_lanl30_v2__qwen2.5-7b__v2.json](reports/triage/eval_evidence_lanl30_v2__qwen2.5-7b__v2.json).
The queue contains none of the 47 malicious user-days, so every alert here is false and the
correct action is dismiss.

| Metric | Result |
|---|---|
| Alerts fully faithful | **0%** |
| Claims with a correct value | **22.4%** (another 20.8% wrong only by decoration) |
| Relations comparing an allowed pair | 24.7% |
| Alerts with ungrounded numbers | 0.4% |
| Share of the all-false queue dismissed | **0%** |
| Share escalated | **49%** (368 of 750), median risk 75 |

**Both windows together (1,100 alerts, 4,326 claims):**
- 0% of alerts were fully faithful, against a target of at least 90%.
- 21.6% of claim values were correct, against a target of at least 97%.
- No alert was dismissed.

The holdout confirms what days 8–14 showed: the model's verdicts don't depend on whether the alert
is real. It escalates about half of any queue, true or false, so it adds no triage value. The
faithfulness checker flagged every alert, so none of these unfaithful outputs would reach an analyst
unmarked.

## Assumptions & limitations (so far)

* **Timezone:** LANL publishes no timezone; hours are on the dataset clock. `off_hours` was chosen from the
  global hourly volume profile (see above), not from labels.
* **Entity scope:** machine accounts (`C123$`) and `ANONYMOUS LOGON` are dropped at ingest to stay
  laptop-sized; red-team rows are attributed to user accounts. Host-level entities are future work.
* **Cold start:** "new host" only knows history inside the ingested window; early days overstate novelty
  for rarely-active users.
* **Label noise:** LANL red-team labels are a partial record of attacker activity; benign-looking days of
  a compromised user may be unlabelled (and vice versa). The match rate of red-team rows to auth rows is
  reported by `ingest` and must be checked on the real data.
* Peer groups from a 3-day warm-up are coarse. The fallback groups (`infra_only`, `no_remote`) are
  large and mixed, so their peer z-scores are weaker. The infrastructure host list is fixed from days
  0–2, so servers that only become shared later are missed.
* A late-arriving account whose first 3 days are already malicious gets anchored on the attacker's
  targets. The self-baseline has the same cold-start problem.

## Repository layout

```
config/       default.toml (single source of parameters)
sql/          ingestion + feature SQL (DuckDB)
src/threatdet/  config, sqlrun, pipeline, metrics, evaluate, freeze, models/detectors, data/{download_lanl, synthetic}
triage/       explain (SHAP evidence packs), llm (triage + faithfulness check); outside the frozen tree on purpose
tests/        pytest suite (95 tests, offline, ~1 min)
notebooks/    exploration (to come)
reports/      metrics_<source>_<v1|v2>.{json,md}, evidence_*.jsonl, explanations_*.{json,md}; figures + recommendations write-up (to come)
```

## Roadmap

1. ~~Ingest~~ · 2. ~~Features~~ · 3. ~~Models~~ (rules, z-score max, Isolation Forest, autoencoder,
   supervised ceiling; scikit-learn gradient boosting stands in for XGBoost to avoid a dependency) ·
   4. ~~Time split, PR-AUC, recall@k, alerts/day, bootstrap CIs~~; ~~event-level novelty (v2)~~; ~~two-stage gate~~; ~~frozen holdout days 15–29~~ (failed; see Holdout result); revisit detection; host-level entity,
   per-day/per-source breakdown, PR and alerts-vs-recall figures · 5. ~~SHAP for top
   alerts~~ · 6. ~~LLM triage with faithfulness evaluation~~ (run on 1,100 alerts; failed all criteria) · 7. 2-page recommendations.

## AI assistance

This repository was built with Claude Code (Anthropic) as a pair programmer. How it was verified:

* Every SQL feature has a hand-computed test on a tiny fixture (`tests/test_features.py`), including
  a z-score compared against an independent NumPy computation.
* Leakage properties are tested behaviourally (truncate the future / drop the label file and require
  identical features), not just by code review.
* The tests themselves were mutation-checked (see above).
* SHAP explanations are checked for exact additivity against the forest score, against a refit of
  the stored scores, and with a deletion test against random features; a wrong-database bug was
  caught by those cross-checks, not by reading the code (see Alert explanations).
* LLM outputs are never trusted as-is. Every claim is checked mechanically against the fact table,
  and the checker's own rules have unit tests built from real pilot failures.
* Synthetic data is labelled as such everywhere and not used for any performance claim.
