import json
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic")

from triage.llm import (  # noqa: E402
    Claim, TriageDecision, _strict, SCHEMA, check_faithfulness, decisions, facts, queue_recall, relation_holds,
    reorder, request_key, request_params, run_sync, triage_summary, ungrounded_numbers, value_matches,
)

PACK = {
    "alert_id": "U1718|d8", "entity": "U1718", "day": 8, "rank_in_day": 1, "two_stage_score": 2.75,
    "gate": {"passed": True, "n_new_src_remote": 43, "n_new_src_ntlm": 96},
    "forest": {"anomaly_score": 0.758, "path_length": 6.31, "expected_path_length": 21.41},
    "top_factors": [
        {"feature": "fail_ratio", "push": 1.296, "evidence": {"fail_ratio": 0.9369, "fail_ratio_base_mean": 0.9772}},
        {"feature": "slog_fail_ratio_peer_z", "push": 1.0,
         "evidence": {"fail_ratio": 0.9369, "fail_ratio_peer_z": 18.7378, "peer_group": "peer_C2519", "peer_n": 11}},
    ],
    "context": {"peer_group": "peer_C2519", "peer_n": 11, "baseline_days": 7, "is_first_day": False, "n_events": 1018},
}


def decision(**kw) -> TriageDecision:
    base = dict(verdict="dismiss", risk=20, summary="Failure ratio 0.94 is close to the usual 0.98.",
                claims=[Claim(key="obs.fail_ratio", value="0.94", relation="similar",
                              reference_key="obs.fail_ratio_base_mean", meaning="normal for this account")],
                benign_explanation="Service account that always fails a lot.", next_steps=["Check the account owner."])
    base.update(kw)
    return TriageDecision(**base)


def test_facts_are_flat_label_free_and_carry_the_evidence():
    f = facts(PACK)
    assert f["gate.n_new_src_ntlm"] == 96 and f["obs.fail_ratio_base_mean"] == 0.9772
    assert f["factor2.feature"] == "slog_fail_ratio_peer_z" and "two_stage_score" not in json.dumps(f)
    text = json.dumps(request_params(PACK)).lower()
    assert not any(b in text for b in ("malicious", "redteam", "is_mal", "label")), "no labels reach the model"


def test_request_is_cache_friendly_and_keyed_by_content():
    a, b = request_params(PACK), request_params({**PACK, "alert_id": "U2|d9", "day": 9})
    assert a["system"] == b["system"], "identical system prompt -> prompt caching works across alerts"
    assert request_key(a) == request_key(request_params(PACK)) != request_key(b)
    assert "temperature" not in a, "sampling params are rejected on current models"


def test_schema_is_strict():
    s = _strict(SCHEMA)
    def walk(n):
        if isinstance(n, dict):
            assert "$ref" not in n
            if n.get("type") == "object":
                assert n["additionalProperties"] is False and set(n["required"]) == set(n["properties"])
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
    walk(s)


@pytest.mark.parametrize("claimed,actual,ok", [
    ("0.94", 0.9369, True), ("94%", 0.9369, True), ("0.9", 0.9369, True), ("0.95", 0.9369, False),
    ("33", 33, True), ("34", 33, False), ("1,018", 1018, True), ("null", None, True), ("0", None, False),
    ("true", True, True), ("false", True, False), ("peer_C2519", "peer_C2519", True), ("many", 33, False),
])
def test_value_matching_allows_rounding_only(claimed, actual, ok):
    assert value_matches(claimed, actual) is ok


def test_relations():
    assert relation_holds("above", 33, 5) and not relation_holds("above", 5, 33)
    assert relation_holds("similar", 0.9369, 0.9772) and not relation_holds("similar", 30, 5)
    assert not relation_holds("above", None, 5), "null is not a number"


def test_ungrounded_numbers_in_free_text():
    f = facts(PACK)
    assert ungrounded_numbers("Failure ratio 94% vs a usual 98%, 96 NTLM events, peer group of 11.", f) == []
    assert ungrounded_numbers("That is 5x the usual and 300 events.", f) == ["5", "300"]


def test_faithful_decision_passes_and_each_kind_of_error_is_caught():
    f = facts(PACK)
    assert check_faithfulness(decision(), f)["faithful"]
    bad_key = decision(claims=[Claim(key="obs.n_ntlm", value="3", relation="none", reference_key="", meaning="")])
    bad_val = decision(claims=[Claim(key="gate.n_new_src_ntlm", value="9", relation="none", reference_key="", meaning="")])
    bad_rel = decision(claims=[Claim(key="obs.fail_ratio", value="0.94", relation="above",
                                     reference_key="obs.fail_ratio_base_mean", meaning="")])
    made_up = decision(summary="Ratio is 3 times the usual.")
    r = {n: check_faithfulness(d, f) for n, d in
         {"key": bad_key, "val": bad_val, "rel": bad_rel, "num": made_up}.items()}
    assert not r["key"]["claims"][0]["key_exists"]
    assert r["val"]["claims"][0]["key_exists"] and not r["val"]["claims"][0]["value_ok"]
    assert not r["rel"]["claims"][0]["relation_ok"]
    assert r["num"]["ungrounded_numbers"] == ["3"]
    assert not any(x["faithful"] for x in r.values())
    assert not check_faithfulness(decision(claims=[]), f)["faithful"], "no claims = nothing checkable"


class FakeClient:
    def __init__(self, text: str, stop: str = "end_turn"):
        self.calls, self.text, self.stop = 0, text, stop
        self.messages = SimpleNamespace(create=self.create)

    def create(self, **params):
        self.calls += 1
        usage = SimpleNamespace(input_tokens=1000, output_tokens=200, cache_read_input_tokens=0,
                                cache_creation_input_tokens=0)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.text)], stop_reason=self.stop, usage=usage)


def test_run_sync_caches_and_decisions_parse(tmp_path):
    cf = tmp_path / "c.jsonl"
    client = FakeClient(decision().model_dump_json())
    assert run_sync([PACK], client, cf) == 1 and run_sync([PACK], client, cf) == 0 and client.calls == 1
    rows = decisions([PACK], cf)
    assert rows[0]["status"] == "ok" and rows[0]["check"]["faithful"]
    assert decisions([{**PACK, "alert_id": "x", "day": 9}], cf)[0]["status"] == "missing"


@pytest.mark.parametrize("text,stop,status", [("not json", "end_turn", "invalid_json"), ("", "refusal", "refusal"),
                                               ("{}", "max_tokens", "max_tokens")])
def test_bad_responses_are_reported_not_dropped(tmp_path, text, stop, status):
    cf = tmp_path / "c.jsonl"
    run_sync([PACK], FakeClient(text, stop), cf)
    assert decisions([PACK], cf)[0]["status"] == status


def test_reorder_and_triage_summary():
    def row(e, d, rank, verdict=None, risk=50):
        r = {"entity": e, "day": d, "rank_in_day": rank, "status": "ok" if verdict else "missing"}
        if verdict:
            r["decision"] = {"verdict": verdict, "risk": risk}
        return r
    rows = [row("a", 1, 1, "dismiss", 10), row("b", 1, 2, "escalate", 90), row("c", 1, 3, None), row("d", 1, 4, "escalate", 95)]
    assert [r["entity"] for r in reorder(rows)] == ["d", "b", "c", "a"]
    pos = {("b", 1), ("d", 1)}
    assert queue_recall(sorted(rows, key=lambda r: r["rank_in_day"]), pos, 1, 2) == 0.0
    s = triage_summary(rows, pos, total_pos=3, ks=(1, 2))
    assert s["recall_detector_order"] == {1: 0.0, 2: 1 / 3} and s["recall_after_triage"] == {1: 1 / 3, 2: 2 / 3}
    assert s["verdicts_true_alerts"]["escalate"] == 2 and s["share_dismissed"] == 1 / 3


def test_ollama_backend_shares_prompt_schema_and_checker(tmp_path):
    from triage.llm import SYSTEM, cache_path, ollama_params, params_for
    o = ollama_params(PACK, "qwen2.5:7b")
    assert o["messages"][0]["content"] == SYSTEM and o["options"]["temperature"] == 0
    assert o["format"] == _strict(SCHEMA) and o["stream"] is False
    assert request_key(o) != request_key(params_for(PACK, "anthropic", "claude-opus-5-5"))
    assert ":" not in cache_path(tmp_path / "evidence_x.jsonl", "qwen2.5:7b").name
    calls = []

    def fake_call(params):
        calls.append(params)
        return {"message": {"content": decision().model_dump_json()}, "done_reason": "stop",
                "prompt_eval_count": 900, "eval_count": 150}
    cf = tmp_path / "o.jsonl"
    assert run_sync([PACK], None, cf, "qwen2.5:7b", "ollama", call=fake_call) == 1
    assert run_sync([PACK], None, cf, "qwen2.5:7b", "ollama", call=fake_call) == 0 and len(calls) == 1
    row = decisions([PACK], cf, "qwen2.5:7b", "ollama")[0]
    assert row["status"] == "ok" and row["check"]["faithful"] and row["usage"]["output"] == 150
    trunc = lambda p: {"message": {"content": "{"}, "done_reason": "length"}  # noqa: E731
    run_sync([{**PACK, "alert_id": "y", "day": 9}], None, cf, "qwen2.5:7b", "ollama", call=trunc)
    assert decisions([{**PACK, "alert_id": "y", "day": 9}], cf, "qwen2.5:7b", "ollama")[0]["status"] == "max_tokens"


def test_v2_only_a_value_and_its_own_reference_can_be_compared():
    from triage.llm import comparable
    assert comparable("obs.fail_ratio", "obs.fail_ratio_base_mean")
    assert comparable("obs.fail_ratio_base_mean", "obs.fail_ratio")
    assert comparable("forest.path_length", "forest.expected_path_length")
    assert not comparable("obs.n_new_dst_remote", "obs.fail_ratio_base_mean"), "pilot error: unrelated quantities"
    assert not comparable("obs.n_ntlm", "factor4.push")
    f = facts(PACK)
    unrelated = decision(claims=[Claim(key="obs.fail_ratio", value="0.94", relation="below",
                                       reference_key="forest.expected_path_length", meaning="")])
    c = check_faithfulness(unrelated, f)["claims"][0]
    assert not c["relation_comparable"] and not c["relation_ok"], "numerically true but meaningless"


@pytest.mark.parametrize("claimed,cosmetic", [("= 304", True), ("{304}", True), (">=304", True), ("305", False),
                                              ("log1p(304) = 5.72", False)])
def test_decorated_values_fail_but_are_flagged_cosmetic(claimed, cosmetic):
    f = {**facts(PACK), "obs.n_new_src_remote": 304}
    d = decision(claims=[Claim(key="obs.n_new_src_remote", value=claimed, relation="none", reference_key="", meaning="")])
    c = check_faithfulness(d, f)["claims"][0]
    assert not c["value_ok"] and c["value_cosmetic_only"] is cosmetic
