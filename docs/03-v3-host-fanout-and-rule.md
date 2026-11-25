# v3 host fan-out and the detection rule (post-hoc)

*Designed after the holdout diagnosis, so every number here is post-hoc.* Back to the [README](../README.md).

## v3: host-level and recency signals (post-hoc): pre-registration

Written on 2026-11-24, **before any v3 feature was computed**.

**Status of the evidence: post-hoc, not a holdout.** The design comes from the
[holdout diagnosis](02-holdout.md#holdout-result-lanl-days-1529), which read the days 15–29 labels: repeat
victims, and one attacker host. Days 15–29 can therefore only show whether v3 fixes the diagnosed
failure, not that it generalises. No labelled LANL days remain (all 749 red-team events fall in days
0–29), so a true holdout would need another dataset.

Code: [hostrisk/](../hostrisk/), a new package outside the frozen tree. `freeze verify` on the v2
method keeps passing.

**Definitions.**
- A user–host pair is *new* on its first day, unless that day is also the user's own first day
  (the existing cold-start rule).
- It is *recently new* on day d if that first day falls in [d−13, d], so the window W is 14 days.
- *Remote* means a Network logon to another host, as in v2.

**New user-day features.**
1. `n_recent_new_src_remote`: today's remote logons from source hosts that this user first used
   within the last W days. This targets **repeat visits**: v2 only counted the first day.
2. `src_fanout_max`: the largest *fan-out* among today's remote-logon source hosts.
   - Fan-out of host h on day d = (users for whom h is recently new) / (1 + established users of h).
   - Established users are pairs first seen before the window, or at the user's cold start.
   - This targets **one host touching many accounts**: a workstation with one regular user that
     suddenly serves 30 scores about 15, while a terminal server with 500 regular users gaining 30
     scores about 0.06.
3. `src_recent_new_users_max`: the raw count of recently-new users behind that maximum.

The rarity weighting suggested earlier is **dropped**. A host used by an attacker becomes *more*
popular, so a rarity weight would down-weight exactly the signal in item 2.

**Detectors.** All are fitted on days 0–7, as before, and none sees labels.
- `host_fanout` (**primary**): ranks by `src_fanout_max`, with ties broken by the v2 Isolation
  Forest score.
- `iforest_v3` (secondary): the Isolation Forest on the v2 design matrix plus log1p of the three new
  features.
- References, recomputed in the same run: v2 `rules`, `iforest` and `two_stage`.

**Evaluation.** The same metrics as v2, plus two per-account metrics:
- *accounts caught*: the share of malicious accounts with at least one user-day in the top 50/day;
- *days to first catch*: the median, per caught account, from its first malicious day.

**Criteria for the primary detector, fixed now.**

| Window | Criterion | v2 reference |
|---|---|---|
| Days 8–14 (validation) | recall at 50/day ≥ 25%, i.e. no worse than v2 | two_stage 25.0% |
| Days 15–29 (post-hoc) | recall at 50/day ≥ 20% (at least 10 of 47) | two_stage 0%, iforest 6.4%, supervised 31.9% |

**Reported but not judged:**
- W = 7 and W = 28 (sensitivity);
- a host-level view: rank source hosts by fan-out each day; a host-day counts as positive if any
  red-team event came from it that day. This view is dominated by one attacker host (C17693), so it
  is reported, not claimed.

Everything is run once per window, and the results are reported here whichever way they fall.

### v3 results

The v3 code was hashed before scoring ([reports/hostrisk_freeze.json](../reports/hostrisk_freeze.json)).
Full tables are in `reports/hostrisk_{dev,posthoc}_w{7,14,28}.md`. In the same run, the v2 references
reproduce their earlier numbers exactly: two_stage 614 / 2,192 alerts/day, and iforest 1,441 / 2,083.

| Detector | Recall @50/day, 8–14 | Recall @50/day, **15–29 (post-hoc)** | Alerts/day @80%, 15–29 | Accounts caught @50/day, 15–29 |
|---|---|---|---|---|
| v2 two_stage | 25.0% | 0.0% | 2,192 | 0% |
| v2 iforest | 19.0% | 6.4% | 2,083 | 3% |
| iforest_v3 (secondary) | 30.2% | 10.6% | 1,563 | 8% |
| **host_fanout, W = 14 (primary)** | **82.8%** | **8.5%** (4 of 47) | 3,230 | 11% |
| host_fanout, W = 7 (sensitivity) | 30.2% | 2.1% | 2,507 | 3% |
| host_fanout, W = 28 (sensitivity) | 82.8% | **89.4%** (42 of 47) | **11** | **100%** |

**Against the pre-registered criteria, the primary detector passes on days 8–14 and fails on days
15–29.**
- **Days 8–14:** 82.8% recall at 50/day (target ≥ 25%), PR-AUC 0.617, and 22 alerts/day at 80% recall.
- **Days 15–29:** 8.5% (target ≥ 20%).

**Why W = 14 fails and W = 28 works** (post-hoc; labels used to explain, not to choose):
- Attacker host C17693 accounts for 41 of the 47 holdout positives. By days 8–14 it had reached 131
  users, and its fan-out was the highest of any host on 3 of those days.
- With W = 14, those users count as "established" two weeks after first contact. So C17693's fan-out
  falls from 16.4 on day 14 to 8.9, 5.7 and then 0.26–0.02 on days 26–29. By then 2,700–3,400 hosts
  rank above it.
- **The attacker's own persistence becomes the baseline.** This is baseline poisoning, the same
  failure as v2, in a different feature.
- W = 28 covers the whole campaign, so the host stays anomalous.

**How far W = 28 can be trusted:**
- **Not pre-registered as primary.** Picking it now would be choosing the winning variant after
  seeing the results. It is reported as a sensitivity result only.
- **On a 30-day dataset, W = 28 means "everything since day 1 is recent".** Over a longer period,
  benign hosts that slowly gain users would build up fan-out as well. The cost in false alerts is
  unmeasured, because LANL has no labelled days after 29.
- **Mostly one attacker host.** The result says "C17693's fan-out stays visible", not "catches
  attackers in general".

**What the result points to as a design:** don't let a flagged host's history decay into the
baseline. Keep *alert memory*: a host that once showed extreme fan-out stays on a watch list until
an analyst clears it, which is how a SOC works anyway. This would be a new method, and it needs
new labelled data to test honestly.

## Detection rule: host fan-out with a watch list (post-hoc)

[detections/host_fanout_rule.sql](../detections/host_fanout_rule.sql) turns the v3 signal into a
scheduled rule, with an analyst [runbook](../detections/RUNBOOK.md); tests are in
[tests/test_detection_rule.py](../tests/test_detection_rule.py).

**Status: post-hoc.** The watch list exists because of the days 15–29 diagnosis, so none of these
numbers is a holdout result.

**How it works:**
1. **Trigger:** a host fires when its 14-day fan-out is at least the threshold and it has at least 3
   recent-new users.
2. **Watch:** for `watch_days` after its latest trigger, the host's baseline stays frozen at its first
   trigger.
3. **User alert:** any user who first reached the host since then (minus W) raises an alert whenever
   they log on remotely from it.

**The threshold is chosen without labels:** it is the smallest fan-out with at most 1 trigger a day
on days 1–7, which gives 8.0. Labels are read only after the rule tables are built. `python -m
detections.rule` writes `reports/detection_rule.{json,md}`.

| watch_days | Window | Host alerts/day | User alerts/day | Attacker host-days caught | Malicious user-days caught | Accounts caught | User-alert precision |
|---|---|---|---|---|---|---|---|
| **30** | days 8–14 | 29.9 | 64.1 | 6/9 | 114/116 (98.3%) | 85/86 | 25.4% |
| **30** | days 15–29 | 68.9 | 85.5 | 6/12 | 41/47 (87.2%) | 36/37 | 3.2% |
| 14 | days 15–29 | 66.6 | 82.4 | 6/12 | 41/47 (87.2%) | 36/37 | 3.3% |
| 7 | days 15–29 | 45.3 | 55.9 | 2/12 | 14/47 (29.8%) | 14/37 | 1.7% |
| 0 (trigger days only) | days 15–29 | 19.1 | 25.6 | 1/12 | 12/47 (25.5%) | 12/37 | 3.1% |

**Reading it honestly:**
- **The watch list is what recovers the holdout attacks.** Without it (watch 0) the rule catches
  25.5%; with a watch of 14 days or more it catches 87.2%. C17693 last fires on day 15, so any watch of
  14 days or more covers the rest of the data.
- **It costs volume, and the cost grows.** Host alerts rise from about 30 to about 69 a day as
  triggered hosts pile up on the watch list. Precision on days 15–29 is 3%. The rule is meant to be
  triaged **per host** (69 a day, each explaining dozens of user alerts), not per user.
- **The threshold drifts.** It fired about 1 time a day on its training days and 19–30 times a day
  later, so it needs recalibrating (see the runbook).
- **This is still mostly one attacker host.** With a 28-day window instead of a watch list, the
  frozen-baseline score and the plain score match until day 28 (see the [figure in the README](../README.md#at-a-glance)). That's the
  same finding seen two ways, not an independent confirmation.

### SIEM ports: Splunk (stateful) and Sigma (stateless)

The rule also exists as Splunk saved searches
([detections/splunk/host_fanout.spl](../detections/splunk/host_fanout.spl)) and as a Sigma
correlation rule ([detections/sigma/host_many_accounts.yml](../detections/sigma/host_many_accounts.yml)).
[tests/test_siem_ports.py](../tests/test_siem_ports.py) checks that both use the SQL rule's
parameters.

- **Splunk** keeps history in lookups and carries the full logic: first-seen pairs, fan-out, the
  frozen-baseline watch list, and a suppression list. It is a hand translation and has not been run
  in Splunk.
- **Sigma** correlations keep no history, so the Sigma rule can only count distinct accounts per
  source host per day. pySigma 2.1.2 validates it and converts it to SPL. Scored the same way on LANL
  (`python -m detections.count_rule`, post-hoc), it shows what dropping the baseline costs:

| Distinct-account threshold | Days 8–14 host alerts/day | Attacker host-days caught | Days 15–29 host alerts/day | Attacker host-days caught |
|---|---|---|---|---|
| 86 (label-free, as shipped) | 0.4 | 0/9 | 0.8 | 0/12 |
| 50 | 5.6 | 2/9 | 5.5 | 0/12 |
| 25 | 10.9 | 3/9 | 10.0 | 1/12 |
| 15 | 17.9 | 4/9 | 15.1 | 3/12 |

The busiest source hosts are servers whose crowd is normal, so a plain count fires on them and not on
the attacker. Per host, the watch-list rule catches 6/9 and 6/12 attacker host-days, at 30 and 69
host alerts a day. Its larger advantage is per user: 41 of 47 malicious user-days on days 15–29.
