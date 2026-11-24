"""LLM triage of SHAP evidence packs, with a deterministic faithfulness check.

    python -m triage.llm estimate --packs reports/evidence_lanl_v2.jsonl
    python -m triage.llm run      --packs reports/evidence_lanl_pilot_v2.jsonl --limit 20         # sync
    python -m triage.llm run      --packs reports/evidence_lanl_v2.jsonl --mode batch             # 50% price
    python -m triage.llm evaluate --packs reports/evidence_lanl_v2.jsonl --db data/lanl.duckdb
    python -m triage.llm run --backend ollama --model qwen2.5:7b --packs ...    # free, local GPU

Design (pre-registered in the README, "LLM triage: pre-registration"):

* The model sees ONE alert as a flat table of facts (``key = value``) built from the evidence pack.
  It never sees labels, other alerts, or the user's identity beyond the opaque entity id.
* It must answer in a fixed JSON schema (structured outputs): a verdict, a 0-100 risk, a short
  summary, and a list of *claims*. Each claim cites one fact key, copies its value, and may state
  a relation (above / below / similar) to another fact key.
* ``check_faithfulness`` verifies every claim mechanically against the facts: the key exists, the
  copied value matches (within the rounding the model used), the stated relation holds, and every
  number in the free text appears among the facts. No LLM judges the LLM.
* Responses are cached on disk keyed by a hash of the full request, so a rerun costs nothing and
  the evaluation is reproducible from the cache file.
"""

from __future__ import annotations

import argparse
import hashlib
import urllib.request
import json
import math
import re
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from threatdet.config import REPO_ROOT

MODEL = "claude-opus-5-5"
EFFORT = "medium"           # the model's default; pre-registered, not tuned
MAX_TOKENS = 16000
PROMPT_VERSION = "v2"  # v2 after the pilot: value format, comparable pairs, no transforms, risk scale
CACHE_DIR = REPO_ROOT / "reports" / "triage"
# $ per million tokens (input, output); batch is half. From the Claude API docs, Nov 2026.
PRICES = {"claude-opus-5-5": (4.0, 20.0), "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50)}
BACKENDS = ("anthropic", "ollama")
OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_OPTIONS = {"temperature": 0, "seed": 42, "num_ctx": 4096}  # greedy decoding: reproducible; 4096 fits the GPU

GLOSSARY = """\
All counts are for one user on one day. "New" means first time ever for this user (within the
ingested history). base_mean = the user's own mean over their previous 7 active days. A _z suffix
is a z-score against that self-baseline; _peer_z is a robust z-score against the user's peer group
on the same day (median / MAD), and peer_n is the group size. Missing (null) means "not enough
history", not zero.

n_events            authentication events
n_fail              failed authentications;  fail_ratio = n_fail / n_events
n_dst_hosts         distinct destination hosts;  n_src_hosts = distinct source hosts
n_new_dst_hosts     destination hosts never used by this user before;  new_dst_ratio = share of dst hosts that are new
n_new_src_hosts     source hosts never used by this user before
n_remote_dst_hosts  distinct hosts reached by network logon from a different machine
n_off_hours         events at 19:00-05:59 (dataset clock);  off_hours_ratio = share of events
n_ntlm              events using NTLM authentication
n_auth_types / n_logon_types / n_active_hours   variety of authentication types, logon types, active hours
n_new_src_remote    remote (network) logon events coming from a source host new to the user
n_new_src_ntlm      NTLM events coming from a source host new to the user
n_new_dst_remote    remote logon events to a destination host new to the user
n_new_pair_events   events on a (source, destination) pair new to the user

The detector: a gate (n_new_src_remote >= 1) puts the alert in the queue, then an Isolation Forest
ranks it. factorN.push is that feature's contribution to the anomaly score (TreeSHAP, in units of
isolation-path length; larger = more anomalous). forest.path_length below forest.expected_path_length
means the user-day was easy to isolate, i.e. unusual."""

SYSTEM = f"""\
You triage alerts from an authentication anomaly detector for a security operations team. Each
alert is one user account on one day. You get only the facts listed in the alert; you have no
other logs, no threat intelligence, and no knowledge of whether the alert is real.

Decide what an analyst should do with it:
- escalate: the facts look like credential misuse or lateral movement (for example remote or NTLM
  logons from source hosts new to the user, reaching many new hosts) that the user's own history
  and peer group do not explain.
- investigate: unusual, but the facts are not enough to tell misuse from legitimate work.
- dismiss: the anomaly is explained by the facts themselves, for example the "unusual" value is
  close to the user's own base_mean (a service or admin account that always behaves like this),
  or it is ordinary for the peer group.

Rules, because every statement you make is checked mechanically against the facts:
1. Every claim must cite exactly one fact key from the alert, spelled exactly as given, and copy
   its value. The value field holds only that value as written in the facts: digits with an
   optional minus sign and decimal point (you may round, e.g. 0.9369 -> 0.94, or write 94%), or
   true / false / null / a name. No "=", ">=", "~", braces, units, words or formulas.
2. A claim may compare a fact to its own reference, and only these pairs:
   obs.X against obs.X_base_mean (the user's usual value of the same quantity), and
   forest.path_length against forest.expected_path_length.
   Use relation "above", "below" or "similar" (within 25%) for such a pair; for every other claim
   use relation "none" and an empty reference_key.
3. Use only numbers that appear in the facts. Never compute anything: no ratios, differences,
   totals, logarithms. A feature named log1p_X or slog_X_z is described by the obs.X / obs.X_z facts;
   cite those, not a transformed number.
4. Do not guess at causes the facts cannot show (malware names, attacker identity, user roles).
   Say "consistent with" rather than asserting intent.
5. Give 2-6 claims, the ones that drove your verdict, including any that support a benign reading.
6. risk uses the whole 0-100 range: 0 = certainly benign, 50 = cannot tell, 100 = certainly misuse.

Field glossary:
{GLOSSARY}"""


class Claim(BaseModel):
    key: str = Field(description="a fact key, exactly as listed")
    value: str = Field(description="that fact's value, copied (rounding allowed)")
    relation: Literal["above", "below", "similar", "none"]
    reference_key: str = Field(description="the fact key compared against, or empty string")
    meaning: str = Field(description="one short sentence on why this matters")


class TriageDecision(BaseModel):
    verdict: Literal["escalate", "investigate", "dismiss"]
    risk: int = Field(description="0-100, how likely this needs action")
    summary: str = Field(description="at most 3 sentences for the analyst")
    claims: list[Claim]
    benign_explanation: str = Field(description="the most plausible benign reading, or empty string")
    next_steps: list[str] = Field(description="1-3 concrete checks for the analyst")


# --------------------------------------------------------------------------- facts
def facts(pack: dict) -> dict:
    """Flatten an evidence pack into the fact table the model sees (and the checker verifies)."""
    # The detector's queue rank is deliberately left out: the model should judge the facts, not
    # anchor on the detector's order (the rank only breaks ties after triage).
    f: dict = {"alert_id": pack["alert_id"], "day": pack["day"]}
    for k, v in pack["gate"].items():
        f[f"gate.{k}"] = v
    for k, v in pack["forest"].items():
        f[f"forest.{k}"] = v
    for k, v in pack["context"].items():
        f[f"context.{k}"] = v
    for i, fac in enumerate(pack["top_factors"], 1):
        f[f"factor{i}.feature"] = fac["feature"]
        f[f"factor{i}.push"] = fac["push"]
        for k, v in fac["evidence"].items():
            f.setdefault(f"obs.{k}", v)
    return f


def _fmt(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def render_facts(f: dict) -> str:
    return "\n".join(f"{k} = {_fmt(v)}" for k, v in f.items())


SCHEMA = TriageDecision.model_json_schema()


def _strict(schema: dict) -> dict:
    """Pydantic schema -> structured-outputs schema: inline $defs, closed objects, all required."""
    defs = schema.get("$defs", {})

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node:
                return walk(defs[node["$ref"].split("/")[-1]])
            out = {k: walk(v) for k, v in node.items() if k not in ("$defs", "title")}
            if out.get("type") == "object":
                out["additionalProperties"] = False
                out["required"] = list(out.get("properties", {}))
            return out
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(schema)


def request_params(pack: dict, model: str = MODEL, effort: str = EFFORT) -> dict:
    return {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": [{"type": "text", "text": SYSTEM, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": "Alert facts:\n" + render_facts(facts(pack))}],
        "output_config": {"effort": effort, "format": {"type": "json_schema", "schema": _strict(SCHEMA)}},
    }


def ollama_params(pack: dict, model: str) -> dict:
    """Same system prompt, facts and schema as the Claude path; Ollama enforces the schema via format."""
    return {
        "model": model, "stream": False, "options": OLLAMA_OPTIONS, "format": _strict(SCHEMA),
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": "Alert facts:\n" + render_facts(facts(pack))}],
    }


def params_for(pack: dict, backend: str, model: str) -> dict:
    if backend == "anthropic":
        return request_params(pack, model)
    if backend == "ollama":
        return ollama_params(pack, model)
    raise ValueError(f"backend must be one of {BACKENDS}")


def request_key(params: dict) -> str:
    return hashlib.sha256((PROMPT_VERSION + json.dumps(params, sort_keys=True)).encode()).hexdigest()[:20]


# --------------------------------------------------------------------------- faithfulness
_NUM = re.compile(r"(?<![\w.])-?\d+(?:,\d{3})*(?:\.\d+)?%?")


def _parse_num(s: str) -> tuple[float, float] | None:
    """'0.94' -> (0.94, 0.005); '94%' -> (0.94, 0.005); '1,018' -> (1018, 0.5). None if not a number."""
    s = s.strip()
    m = re.fullmatch(r"-?\d+(?:,\d{3})*(?:\.\d+)?%?", s)
    if not m:
        return None
    pct = s.endswith("%")
    body = s.rstrip("%").replace(",", "")
    dec = len(body.split(".")[1]) if "." in body else 0
    val, tol = float(body), 0.5 * 10 ** -dec
    return (val / 100, tol / 100) if pct else (val, tol)


def value_matches(claimed: str, actual) -> bool:
    if actual is None:
        return claimed.strip().lower() in ("null", "none", "missing", "n/a", "")
    if isinstance(actual, bool):
        return claimed.strip().lower() == ("true" if actual else "false")
    if isinstance(actual, (int, float)):
        p = _parse_num(claimed)
        return p is not None and abs(p[0] - actual) <= p[1] + 1e-9 * max(1.0, abs(actual))
    return claimed.strip().lower() == str(actual).lower()


def relation_holds(relation: str, a, b) -> bool:
    if relation == "none":
        return True
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (a, b)):
        return False
    if relation == "above":
        return a > b
    if relation == "below":
        return a < b
    return abs(a - b) <= 0.25 * max(abs(a), abs(b)) or a == b  # similar


def ungrounded_numbers(text: str, f: dict) -> list[str]:
    nums = [v for v in f.values() if isinstance(v, (int, float)) and not isinstance(v, bool)]
    bad = []
    for tok in _NUM.findall(text):
        p = _parse_num(tok)
        if p and not any(abs(p[0] - v) <= p[1] + 1e-9 * max(1.0, abs(v)) for v in nums):
            bad.append(tok)
    return bad


def comparable(key: str, ref: str) -> bool:
    """Only a value and its own reference may be compared (v2: the pilot showed comparisons of
    unrelated quantities, e.g. a host count 'above' a failure ratio, that pass a pure numeric test)."""
    if {key, ref} == {"forest.path_length", "forest.expected_path_length"}:
        return True
    base = key.removesuffix("_base_mean")
    return key.startswith("obs.") and key != ref and {key, ref} == {base, base + "_base_mean"}


_DECORATION = re.compile(r"^[\s=~{(\[<>≈]*|[\s})\]]*$")


def cosmetic_only(claimed: str, actual) -> bool:
    """Diagnostic only (not part of 'faithful'): would the value match once '=', braces etc. are
    stripped? Separates formatting noise from wrong numbers in the report."""
    return value_matches(_DECORATION.sub("", claimed), actual)


def check_faithfulness(d: TriageDecision, f: dict) -> dict:
    claims = []
    for c in d.claims:
        known = c.key in f
        has_rel = c.relation != "none"
        ref_ok = not has_rel or (c.reference_key in f and comparable(c.key, c.reference_key))
        value_ok = known and value_matches(c.value, f[c.key])
        claims.append({
            "key": c.key, "key_exists": known, "value_ok": value_ok,
            "value_cosmetic_only": known and not value_ok and cosmetic_only(c.value, f[c.key]),
            "relation": c.relation, "relation_comparable": ref_ok,
            "relation_ok": known and ref_ok and relation_holds(
                c.relation, f.get(c.key), f.get(c.reference_key) if has_rel else None),
        })
    loose = ungrounded_numbers(" ".join([d.summary, d.benign_explanation, *d.next_steps]), f)
    ok = bool(claims) and all(c["key_exists"] and c["value_ok"] and c["relation_ok"] for c in claims) and not loose
    return {"claims": claims, "ungrounded_numbers": loose, "risk_in_range": 0 <= d.risk <= 100,
            "faithful": ok and 0 <= d.risk <= 100}


# --------------------------------------------------------------------------- calls + cache
def load_packs(path: Path, limit: int | None = None) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        packs = [json.loads(line) for line in fh]
    return packs[:limit] if limit else packs


def _safe(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", model)  # "qwen2.5:7b" -> "qwen2.5-7b" (':' is illegal on Windows)


def cache_path(packs_path: Path, model: str) -> Path:
    return CACHE_DIR / f"{Path(packs_path).stem}__{_safe(model)}__{PROMPT_VERSION}.jsonl"


def load_cache(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        return {r["key"]: r for r in map(json.loads, fh)}


def _ollama_call(params: dict, url: str = OLLAMA_URL, timeout: float = 600) -> dict:
    req = urllib.request.Request(url, data=json.dumps(params).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _ollama_record(key: str, pack: dict, model: str, resp: dict, seconds: float) -> dict:
    stop = {"stop": "end_turn", "length": "max_tokens"}.get(resp.get("done_reason"), resp.get("done_reason"))
    return {"key": key, "alert_id": pack["alert_id"], "model": model, "stop_reason": stop,
            "text": resp.get("message", {}).get("content", ""), "seconds": round(seconds, 2),
            "usage": {"input": resp.get("prompt_eval_count", 0), "output": resp.get("eval_count", 0),
                      "cache_read": 0, "cache_write": 0}}


def _record(key: str, pack: dict, model: str, msg) -> dict:
    text = next((b.text for b in msg.content if b.type == "text"), "")
    u = msg.usage
    return {"key": key, "alert_id": pack["alert_id"], "model": model, "stop_reason": msg.stop_reason,
            "text": text, "usage": {"input": u.input_tokens, "output": u.output_tokens,
                                    "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
                                    "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0}}


def run_sync(packs: list[dict], client, cache_file: Path, model: str = MODEL, backend: str = "anthropic",
             call=_ollama_call) -> int:
    """One request at a time, appending each response to the cache as it arrives (safe to interrupt).
    client is the Anthropic client (anthropic backend); call posts to Ollama (ollama backend)."""
    cache = load_cache(cache_file)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(cache_file, "a", encoding="utf-8") as out:
        for i, p in enumerate(packs):
            params = params_for(p, backend, model)
            key = request_key(params)
            if key in cache:
                continue
            t0 = time.perf_counter()
            if backend == "anthropic":
                rec = _record(key, p, model, client.messages.create(**params))
            else:
                rec = _ollama_record(key, p, model, call(params), time.perf_counter() - t0)
            out.write(json.dumps(rec) + "\n"); out.flush()
            n += 1
            if n % 25 == 0:
                print(f"  {i + 1}/{len(packs)} done", flush=True)
    return n


def run_batch(packs: list[dict], client, cache_file: Path, model: str = MODEL, poll: int = 60) -> int:
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    cache = load_cache(cache_file)
    todo = {}
    for p in packs:
        params = request_params(p, model)
        key = request_key(params)
        if key not in cache:
            todo[key] = (p, params)
    if not todo:
        return 0
    batch = client.messages.batches.create(requests=[
        Request(custom_id=k, params=MessageCreateParamsNonStreaming(**params)) for k, (_, params) in todo.items()])
    print(f"batch {batch.id}: {len(todo)} requests", flush=True)
    while client.messages.batches.retrieve(batch.id).processing_status != "ended":
        time.sleep(poll)
    n = 0
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "a", encoding="utf-8") as out:
        for r in client.messages.batches.results(batch.id):
            if r.result.type == "succeeded" and r.custom_id in todo:
                out.write(json.dumps(_record(r.custom_id, todo[r.custom_id][0], model, r.result.message)) + "\n")
                n += 1
            else:
                print(f"{r.custom_id}: {r.result.type}", flush=True)
    return n


def decisions(packs: list[dict], cache_file: Path, model: str = MODEL, backend: str = "anthropic") -> list[dict]:
    """Join packs with cached responses; parse and check each. Missing responses are reported."""
    cache = load_cache(cache_file)
    out = []
    for p in packs:
        rec = cache.get(request_key(params_for(p, backend, model)))
        row = {"alert_id": p["alert_id"], "entity": p["entity"], "day": p["day"],
               "rank_in_day": p.get("rank_in_day"), "status": "missing"}
        if rec:
            row["usage"], row["seconds"] = rec["usage"], rec.get("seconds")
            if rec["stop_reason"] != "end_turn":
                row["status"] = rec["stop_reason"]
            else:
                try:
                    d = TriageDecision.model_validate_json(rec["text"])
                    row.update(status="ok", decision=d.model_dump(), check=check_faithfulness(d, facts(p)))
                except ValueError as e:
                    row.update(status="invalid_json", error=str(e)[:200])
        out.append(row)
    return out


# --------------------------------------------------------------------------- evaluation
VERDICT_ORDER = {"escalate": 0, "investigate": 1, "dismiss": 2}


def reorder(rows: list[dict]) -> list[dict]:
    """The analyst queue after triage: escalate > investigate > dismiss, then risk, then the
    detector's own rank. Alerts without a valid decision keep their place in 'investigate'."""
    def key(r):
        d = r.get("decision")
        return (VERDICT_ORDER[d["verdict"]] if d else 1, -(d["risk"] if d else 50), r["rank_in_day"])
    return sorted(rows, key=lambda r: (r["day"], key(r)))


def queue_recall(rows: list[dict], positives: set, k: int, total_pos: int) -> float:
    by_day: dict[int, list] = {}
    for r in rows:
        by_day.setdefault(r["day"], []).append(r)
    hit = sum((r["entity"], r["day"]) in positives for day in by_day.values() for r in day[:k])
    return hit / total_pos if total_pos else math.nan


def faithfulness_summary(rows: list[dict]) -> dict:
    ok = [r for r in rows if r["status"] == "ok"]
    claims = [c for r in ok for c in r["check"]["claims"]]
    rel = [c for c in claims if c["relation"] != "none"]
    return {
        "alerts": len(rows), "parsed": len(ok),
        "status_counts": {s: sum(r["status"] == s for r in rows) for s in {r["status"] for r in rows}},
        "alerts_fully_faithful": sum(r["check"]["faithful"] for r in ok) / max(1, len(ok)),
        "claims": len(claims),
        "claim_key_exists": sum(c["key_exists"] for c in claims) / max(1, len(claims)),
        "claim_value_ok": sum(c["value_ok"] for c in claims) / max(1, len(claims)),
        "claim_value_wrong_but_cosmetic_only": sum(c.get("value_cosmetic_only", False) for c in claims) / max(1, len(claims)),
        "relation_claims": len(rel),
        "relation_comparable": sum(c.get("relation_comparable", True) for c in rel) / max(1, len(rel)),
        "relation_ok": sum(c["relation_ok"] for c in rel) / max(1, len(rel)),
        "risk_median": sorted(r["decision"]["risk"] for r in ok)[len(ok) // 2] if ok else None,
        "verdicts": {v: sum(r["decision"]["verdict"] == v for r in ok) for v in VERDICT_ORDER},
        "alerts_with_ungrounded_numbers": sum(bool(r["check"]["ungrounded_numbers"]) for r in ok) / max(1, len(ok)),
    }


def triage_summary(rows: list[dict], positives: set, total_pos: int, ks=(5, 10, 25)) -> dict:
    """LABELS USED HERE ONLY. Original detector order vs the order after LLM triage."""
    base = sorted(rows, key=lambda r: (r["day"], r["rank_in_day"]))
    llm = reorder(rows)
    ok = [r for r in rows if r.get("decision")]
    tp = [r for r in ok if (r["entity"], r["day"]) in positives]
    fp = [r for r in ok if (r["entity"], r["day"]) not in positives]
    verdicts = lambda rs: {v: sum(r["decision"]["verdict"] == v for r in rs) for v in VERDICT_ORDER}  # noqa: E731
    return {
        "positives_in_window": total_pos, "positives_in_queue": len(tp),
        "recall_detector_order": {k: queue_recall(base, positives, k, total_pos) for k in ks},
        "recall_after_triage": {k: queue_recall(llm, positives, k, total_pos) for k in ks},
        "verdicts_true_alerts": verdicts(tp), "verdicts_false_alerts": verdicts(fp),
        "share_dismissed": sum(r["decision"]["verdict"] == "dismiss" for r in ok) / max(1, len(ok)),
    }


def cost(rows: list[dict], model: str, batch: bool) -> float:
    if model not in PRICES:  # local model
        return 0.0
    pin, pout = PRICES[model]
    f = 0.5 if batch else 1.0
    tot = 0.0
    for r in rows:
        u = r.get("usage")
        if u:
            tot += (u["input"] * pin + u["cache_write"] * pin * 1.25 + u["cache_read"] * pin * 0.1
                    + u["output"] * pout) / 1e6 * f
    return tot


def estimate(packs: list[dict], model: str, out_tokens: int = 1500) -> dict:
    """Rough pre-run cost: ~4 characters per token for input; output (incl. thinking) assumed."""
    pin, pout = PRICES[model]
    inp = sum(len(SYSTEM) + len(render_facts(facts(p))) + 60 for p in packs) / 4
    out = out_tokens * len(packs)
    std = (inp * pin + out * pout) / 1e6
    return {"alerts": len(packs), "input_tokens_approx": int(inp), "output_tokens_assumed": out,
            "usd_standard": round(std, 2), "usd_batch": round(std / 2, 2)}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="LLM triage of evidence packs")
    ap.add_argument("action", choices=["estimate", "run", "evaluate", "show"])
    ap.add_argument("--packs", required=True)
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--mode", choices=["sync", "batch"], default="sync")
    ap.add_argument("--db", default=None, help="DuckDB with labels (evaluate only)")
    ap.add_argument("--backend", choices=BACKENDS, default="anthropic")
    a = ap.parse_args(argv)
    packs = load_packs(Path(a.packs), a.limit)
    cf = cache_path(Path(a.packs), a.model)
    if a.action == "estimate":
        print(json.dumps(estimate(packs, a.model), indent=2))
    elif a.action == "run":
        if a.backend == "ollama":
            n = run_sync(packs, None, cf, a.model, "ollama")
        else:
            import anthropic
            client = anthropic.Anthropic()
            n = (run_batch if a.mode == "batch" else run_sync)(packs, client, cf, a.model)
        print(f"{n} new responses -> {cf}")
    elif a.action == "show":
        for r in decisions(packs, cf, a.model, a.backend):
            print(json.dumps(r, indent=1))
    else:
        import duckdb
        rows = decisions(packs, cf, a.model, a.backend)
        secs = [r["seconds"] for r in rows if r.get("seconds")]
        rep = {"packs": a.packs, "backend": a.backend, "model": a.model, "prompt_version": PROMPT_VERSION,
               "settings": OLLAMA_OPTIONS if a.backend == "ollama" else {"effort": EFFORT},
               "median_seconds_per_alert": sorted(secs)[len(secs) // 2] if secs else None,
               "cost_usd_if_batch": round(cost(rows, a.model, True), 2),
               "cost_usd_if_sync": round(cost(rows, a.model, False), 2),
               "faithfulness": faithfulness_summary(rows)}
        if a.db:
            con = duckdb.connect(a.db, read_only=True)
            days = sorted({p["day"] for p in packs})
            lab = con.execute("SELECT entity, day FROM labels.user_day WHERE is_malicious AND day BETWEEN ? AND ?",
                              [days[0], days[-1]]).fetchall()
            rep["triage"] = triage_summary(rows, {(e, int(d)) for e, d in lab}, len(lab))
        out = CACHE_DIR / f"eval_{Path(a.packs).stem}__{_safe(a.model)}__{PROMPT_VERSION}.json"
        out.write_text(json.dumps(rep, indent=2), encoding="utf-8")
        print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
