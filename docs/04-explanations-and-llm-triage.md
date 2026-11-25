# SHAP explanations and LLM triage

*SHAP evidence packs for top alerts, then LLM triage v2 and v3 with mechanical faithfulness checks.* Back to the [README](../README.md).

## Alert explanations (SHAP)

`python -m triage.explain --source lanl` writes one **evidence pack** per alert for the top 50
two-stage alerts of each test day ([reports/evidence_lanl_v2.jsonl](../reports/evidence_lanl_v2.jsonl),
summary in [reports/explanations_lanl_v2.md](../reports/explanations_lanl_v2.md)). These packs are what
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

Written on 2026-11-24, **before any LLM call**. Code: [triage/llm.py](../triage/llm.py), offline tests in
[tests/test_llm.py](../tests/test_llm.py) (fake client, no API calls).

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
[reports/triage/eval_evidence_lanl_v2__qwen2.5-7b__v2.json](../reports/triage/eval_evidence_lanl_v2__qwen2.5-7b__v2.json).

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
[reports/triage/eval_evidence_lanl30_v2__qwen2.5-7b__v2.json](../reports/triage/eval_evidence_lanl30_v2__qwen2.5-7b__v2.json).
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

## Triage v3 (LLM narrates, code fills values): pre-registration

Written on 2026-11-24, **before any v3 triage call**. Code: [triage/narrate.py](../triage/narrate.py),
tests in [tests/test_narrate.py](../tests/test_narrate.py). The v2 module is unchanged, so its results
stay reproducible.

**What the v2 run taught, and the design change:**
- The 7B model couldn't copy values (21.6% correct) or pick verdicts (it never dismissed).
- In v3 it does neither. It chooses **which fact keys matter**, optionally names an allowed reference
  key, and writes the summary, a benign reading and next steps.
- **Code** renders every value and computes every above/below/similar relation from the facts.
- The **verdict stays with the detector**, as the alert's place in the queue. No verdict or risk is
  asked of the model.

**Check, mechanical as before.** An alert is fully faithful when:
- every cited key exists;
- every named reference is an allowed pair;
- it has 2–6 claims;
- its free text contains **no digits at all**, since the prompt forbids numbers in prose.

**Model and settings:** the same `qwen2.5:7b` with greedy decoding and a 4,096-token context.
Prompt version `n1`.

**Workflow:** a 20-alert pilot on days 1–7, for format bugs only, with one allowed revision. Then
one run on the 350 days 8–14 alerts.

**Criterion, fixed now:** at least 90% of the 350 alerts fully faithful. The share of alerts with
digits in the text and with bad keys or references is reported either way. There's no usefulness
claim, because judging that needs analysts.

**n1 pilot result and the one allowed revision (n2), recorded before n2 ran.** The n1 pilot (20
alerts, 20 s per alert) parsed 20 of 20, but **0 of 20 were fully faithful**:
- **digits:** 75% of alerts wrote digits in the text despite the rule. The numbers were mostly
  correct copies, for example "304 remote logon events".
- **bad keys:** 5.7% of cited keys don't exist, for example `obs.new_dst_ratio = 1.0` or `n_ntlm`.
- **bad references:** 16% name a disallowed reference, for example `log1p_n_new_dst_remote`.
- **contradictory prose,** which n1 didn't check: "far above the user's usual failure rate" for 0.94
  against a usual 0.98.

**n2 changes (the system prompt changed; the schema is now built per alert):**
- **Keys are enforced in decoding.** Claim keys must come from this alert's own facts (a JSON-schema
  enum), and references must come from the allowed set. I checked that Ollama enforces the enum.
- **A no-digit pattern was tried and dropped.** Ollama accepted it, but generation then never
  finished.
- **The no-digit rule is dropped** in favour of v2's rule: every number in the text must appear in
  the facts. n1's rule was stricter than faithfulness needs, and v2 showed the model rarely invents
  numbers in prose (0.9% of alerts).
- **The checker gains a stricter test:** a claim's direction words ("above", "lower", "similar")
  must agree with the relation code computes.
- Generation is capped at 1,024 tokens.

**n2 is final whatever its pilot shows;** the 350-alert run uses it unchanged.

### Triage v3 results: fails the criterion (27.1% fully faithful, target 90%)

| | n1 pilot (20) | n2 pilot (20) | **n2, days 8–14 (350)** |
|---|---|---|---|
| Parsed | 100% | 100% | 100% |
| **Alerts fully faithful** | 0% | 55% | **27.1%** ✗ |
| Cited keys that exist | 94.3% | 100% | 100% |
| References that are an allowed pair | 84.3% | 93.0% | 78.3% |
| Direction words that agree with the computed relation | not checked | 90.1% | 77.2% |
| Alerts with a number not in the facts | (any digit) 75% | 5% | 16.9% |
| Median seconds per alert | 19.9 | 19.4 | 19.5 |

- **Keys are fixed by the schema enum:** no invented field names in 1,179 claims.
- **Pairing is not:** the reference enum lists every comparable key, so the model can still pair a
  key with the wrong reference (for example `obs.n_new_src_ntlm` against `obs.n_ntlm`). Of the 255
  unfaithful alerts, 203 have a bad pair; a direction word on a bad pair then fails too (222).
- **Ungrounded numbers are real errors:** computed percentages ("98.5%"), invented baselines ("their
  own historical average of 50%"), and clock times.
- **The pilot overstated it:** 55% on days 1–7 against 27.1% on days 8–14. The pilot alerts are
  simpler, which is a reason a 20-alert pilot is for format bugs only.
- **What would fix pairing:** let the model choose only a key, and have code attach the one allowed
  reference (`obs.X` → `obs.X_base_mean`). That is a third revision, so it would need a new
  pre-registration and fresh alerts; it is not done here.

What does hold: code-filled values are correct by construction, and the verdict never comes from the
model. The LLM's prose is still not trustworthy without the mechanical check, which is what the check
is for. Reports: `reports/triage/eval_evidence_lanl_v2__qwen2.5-7b__n2.json` and the pilot's.
