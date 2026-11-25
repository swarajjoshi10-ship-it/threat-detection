# Data, features, detectors and metrics

*How the LANL subset was fetched and what it looks like, the feature pipeline, leakage controls, the detectors and the metrics.* Back to the [README](../README.md).

## Downloading LANL: details

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

**Synthetic (development only):** [src/threatdet/data/synthetic.py](../src/threatdet/data/synthetic.py)
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

Orchestrated by [src/threatdet/pipeline.py](../src/threatdet/pipeline.py); SQL placeholders (`{{name}}`)
are rendered by [sqlrun.py](../src/threatdet/sqlrun.py), which fails on any missing *or unused* parameter.

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

All detectors rank active user-days; [src/threatdet/models/detectors.py](../src/threatdet/models/detectors.py).

| Detector | What it is | Fitted on |
|---|---|---|
| `rules` | Sigma-style: score = number of rules firing (≥3 new remote hosts; ≥5 failures; NTLM by a user with no NTLM in their 7-day baseline; off-hours activity by a user with none in their baseline). Thresholds set from domain knowledge, not labels. | nothing |
| `zscore_max` | Largest upward self or peer z-score | nothing |
| `iforest` | Isolation Forest (300 trees) on the design matrix | days 0–7, no labels |
| `autoencoder` | PyTorch MLP 37→32→8→32→37; score = reconstruction MSE | days 0–7, no labels |
| `supervised_ceiling` | Gradient boosting **with labels**, leave-one-day-out. A reference, not a deliverable: the same attacker accounts appear on other days, so it is optimistic. | all other days, with labels |

Design matrix: counts `log1p`, ratios as is, z-scores signed-log (`sign·log1p|z|`, they reach the
hundreds), missing z → 0 plus `no_self_baseline` / `no_peer_group` indicators.

**Metrics** ([src/threatdet/metrics.py](../src/threatdet/metrics.py)): PR-AUC; alerts/day needed to
reach 50/80/90% recall over the test days (one global threshold); recall when an analyst reviews the
top-k user-days *of each day*. Rule scores tie heavily, so every metric takes the **expected value
under random order within ties** (exact formula, tested against brute force), never a lucky row order.
90% CIs come from a **cluster bootstrap over users** (300 resamples), because one attacker's user-days
are correlated.

**Label isolation is tested behaviourally:** `test_run_end_to_end_and_unsupervised_scores_ignore_labels`
scrambles `labels.user_day` and requires every unsupervised score to be bit-identical, and the
supervised one to change. Detectors also refuse frames with label-like columns.
