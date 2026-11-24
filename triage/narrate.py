"""Triage v3: the LLM explains, code supplies every number, the detector decides.

The v2 run (triage/llm.py) showed a 7B model cannot copy values or pick verdicts reliably. Here:
- the model only chooses WHICH fact keys matter (and optionally a comparable reference key) and
  writes prose; it outputs no values, no relations, no verdict and no risk;
- code renders each cited key's value and computes any above/below/similar relation;
- the verdict stays with the detector (the alert's place in the queue).

Faithfulness check: every cited key exists, every reference is a comparable pair, every number in the
free text appears in the facts, and a claim's direction words (above / below / similar) agree with
the relation code computes. Pre-registered in README "Triage v3" (n1 pilot and n2 revision recorded).

    python -m triage.narrate run      --packs reports/evidence_lanl_pilot_v2.jsonl --limit 20
    python -m triage.narrate evaluate --packs reports/evidence_lanl_v2.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, ValidationError

from triage.llm import (
    CACHE_DIR, GLOSSARY, OLLAMA_OPTIONS, _ollama_call, _ollama_record, _safe, _strict, comparable, facts,
    load_cache, load_packs, relation_holds, render_facts, request_key, ungrounded_numbers,
)

PROMPT_VERSION = "n2"  # n2 after the pilot: keys as a schema enum, grounded numbers, direction check
MODEL = "qwen2.5:7b"

SYSTEM = f"""\
You explain alerts from an authentication anomaly detector to a security analyst. Each alert is
one user account on one day. The detector has already queued it; you do not decide whether it is
malicious. You get only the facts listed; no other logs and no knowledge of the true outcome.

Write:
- summary: two or three sentences on what is unusual about this user-day.
- claims: the 2-6 facts that matter most, each as a fact key copied exactly from the list, plus a
  short plain-language meaning. If the fact has its own reference, you may name it in
  reference_key, and only these pairs are allowed: obs.X with obs.X_base_mean, or
  forest.path_length with forest.expected_path_length. Otherwise leave reference_key empty.
  Do NOT write the value: the system fills it in from the facts.
- benign_explanation: the most plausible legitimate reason, or an empty string if none fits.
- next_steps: 1-3 concrete checks an analyst could do.

Rules, checked mechanically:
1. Use only numbers that appear in the facts, as written there (you may round). Never compute
   anything: no ratios, differences, totals or logarithms.
2. In a claim's meaning, say "above", "below" or "similar" only if that is true of the key against
   its reference_key (similar = within 25%).
3. Do not guess at causes the facts cannot show (malware names, attacker identity, user roles).

Field glossary:
{GLOSSARY}"""


class NClaim(BaseModel):
    key: str
    reference_key: str = Field(description="empty, or the allowed reference for key")
    meaning: str


class Narrative(BaseModel):
    summary: str
    claims: Annotated[list[NClaim], Field(min_length=1, max_length=8)]
    benign_explanation: str
    next_steps: list[str]


SCHEMA = Narrative.model_json_schema()
OPTIONS = {**OLLAMA_OPTIONS, "num_predict": 1024}   # a hard stop: no runaway generations
_ABOVE = re.compile(r"\b(above|higher|exceed\w*|more than|elevated)\b", re.I)
_BELOW = re.compile(r"\b(below|lower|fewer|less than)\b", re.I)
_SIMILAR = re.compile(r"\b(similar|close to|in line with|consistent with (?:the|its|their) usual)\b", re.I)


def schema_for(f: dict) -> dict:
    """Constrained decoding: claim keys can only be this alert's fact keys (n2)."""
    s = _strict(SCHEMA)
    claim = s["properties"]["claims"]["items"]["properties"]
    claim["key"]["enum"] = sorted(f)
    claim["reference_key"]["enum"] = [""] + sorted(k for k in f if any(comparable(x, k) for x in f))
    return s


def ollama_params(pack: dict, model: str = MODEL) -> dict:
    f = facts(pack)
    return {"model": model, "stream": False, "options": OPTIONS, "format": schema_for(f),
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": "Alert facts:\n" + render_facts(f)}]}


def direction_ok(meaning: str, relation) -> bool:
    """Direction words in the prose must match the computed relation (none stated = fine)."""
    said = {r for r, rx in (("above", _ABOVE), ("below", _BELOW), ("similar", _SIMILAR)) if rx.search(meaning)}
    return not said or said == {relation}


def render_claims(n: Narrative, f: dict) -> list[dict]:
    """Values and relations come from the facts, never from the model."""
    out = []
    for c in n.claims:
        row = {"key": c.key, "value": f.get(c.key), "meaning": c.meaning}
        if c.reference_key:
            ref = f.get(c.reference_key)
            row["reference_key"], row["reference_value"] = c.reference_key, ref
            # "similar" first: 0.94 vs 0.98 is "similar", not "below"
            row["relation"] = next((r for r in ("similar", "above", "below")
                                    if comparable(c.key, c.reference_key) and relation_holds(r, f.get(c.key), ref)), None)
        out.append(row)
    return out


def check(n: Narrative, f: dict) -> dict:
    rendered = render_claims(n, f)
    claims = [{"key_exists": c.key in f,
               "reference_ok": (not c.reference_key) or (c.reference_key in f and comparable(c.key, c.reference_key)),
               "direction_ok": direction_ok(c.meaning, r.get("relation")) if c.reference_key else True}
              for c, r in zip(n.claims, rendered)]
    texts = [n.summary, n.benign_explanation, *n.next_steps, *(c.meaning for c in n.claims)]
    ungrounded = [x for t in texts for x in ungrounded_numbers(t, f)]
    ok = (2 <= len(claims) <= 6 and not ungrounded
          and all(c["key_exists"] and c["reference_ok"] and c["direction_ok"] for c in claims))
    return {"faithful": ok, "claims": claims, "n_claims": len(claims), "ungrounded_numbers": ungrounded[:5]}


def cache_path(packs_path: Path, model: str = MODEL) -> Path:
    return CACHE_DIR / f"{Path(packs_path).stem}__{_safe(model)}__{PROMPT_VERSION}.jsonl"


def run(packs: list[dict], cache_file: Path, model: str = MODEL, call=_ollama_call) -> int:
    cache = load_cache(cache_file)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(cache_file, "a", encoding="utf-8") as out:
        for i, p in enumerate(packs):
            params = ollama_params(p, model)
            key = request_key(params)
            if key in cache:
                continue
            t0 = time.perf_counter()
            rec = _ollama_record(key, p, model, call(params), time.perf_counter() - t0)
            out.write(json.dumps(rec) + "\n"); out.flush()
            n += 1
            if n % 25 == 0:
                print(f"  {i + 1}/{len(packs)} done", flush=True)
    return n


def rows(packs: list[dict], cache_file: Path, model: str = MODEL) -> list[dict]:
    cache = load_cache(cache_file)
    out = []
    for p in packs:
        rec = cache.get(request_key(ollama_params(p, model)))
        row = {"alert_id": p["alert_id"], "status": "missing"}
        if rec:
            row["seconds"] = rec.get("seconds")
            if rec["stop_reason"] != "end_turn":
                row["status"] = rec["stop_reason"]
            else:
                try:
                    n = Narrative.model_validate_json(rec["text"])
                except ValidationError:
                    row["status"] = "invalid_json"
                else:
                    f = facts(p)
                    row.update(status="ok", narrative=n.model_dump(), rendered=render_claims(n, f), check=check(n, f))
        out.append(row)
    return out


def summary(rs: list[dict]) -> dict:
    ok = [r for r in rs if r["status"] == "ok"]
    cl = [c for r in ok for c in r["check"]["claims"]]
    secs = sorted(r["seconds"] for r in rs if r.get("seconds"))
    statuses = {}
    for r in rs:
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    return {"alerts": len(rs), "status_counts": statuses,
            "alerts_fully_faithful": sum(r["check"]["faithful"] for r in ok) / len(rs) if rs else None,
            "claims": len(cl),
            "claim_key_exists": sum(c["key_exists"] for c in cl) / len(cl) if cl else None,
            "claim_reference_ok": sum(c["reference_ok"] for c in cl) / len(cl) if cl else None,
            "claim_direction_ok": sum(c["direction_ok"] for c in cl) / len(cl) if cl else None,
            "alerts_with_ungrounded_numbers": sum(bool(r["check"]["ungrounded_numbers"]) for r in ok) / len(ok) if ok else None,
            "alerts_with_2_to_6_claims": sum(2 <= r["check"]["n_claims"] <= 6 for r in ok) / len(ok) if ok else None,
            "median_seconds_per_alert": secs[len(secs) // 2] if secs else None}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="triage v3: LLM narrates, code fills values")
    ap.add_argument("action", choices=["run", "evaluate", "show"])
    ap.add_argument("--packs", required=True)
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args(argv)
    packs = load_packs(Path(a.packs), a.limit)
    cf = cache_path(Path(a.packs), a.model)
    if a.action == "run":
        print(f"{run(packs, cf, a.model)} new responses -> {cf}")
        return
    rs = rows(packs, cf, a.model)
    if a.action == "show":
        for r in rs:
            print(json.dumps(r, indent=1))
        return
    rep = {"packs": a.packs, "model": a.model, "prompt_version": PROMPT_VERSION, "settings": OPTIONS,
           "faithfulness": summary(rs)}
    out = CACHE_DIR / f"eval_{Path(a.packs).stem}__{_safe(a.model)}__{PROMPT_VERSION}.json"
    out.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
