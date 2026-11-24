import json

import pytest

pytest.importorskip("pydantic")

from triage.llm import facts  # noqa: E402
from triage.narrate import Narrative, NClaim, check, ollama_params, render_claims, rows, run, summary  # noqa: E402
from tests.test_llm import PACK  # noqa: E402


def narrative(**kw) -> Narrative:
    base = dict(summary="Failures are high but close to what this account usually does.",
                claims=[NClaim(key="obs.fail_ratio", reference_key="obs.fail_ratio_base_mean", meaning="usual level"),
                        NClaim(key="gate.n_new_src_ntlm", reference_key="", meaning="many NTLM logons from new hosts")],
                benign_explanation="A service account that always fails often.", next_steps=["Ask the account owner."])
    base.update(kw)
    return Narrative(**base)


def test_values_and_relations_come_from_code_not_the_model():
    f = facts(PACK)
    r = render_claims(narrative(), f)
    assert r[0]["value"] == 0.9369 and r[0]["reference_value"] == 0.9772 and r[0]["relation"] == "similar"
    assert r[1]["value"] == 96 and "relation" not in r[1]
    props = json.dumps(ollama_params(PACK)["format"]["properties"]["claims"]["items"]["properties"])
    assert '"value"' not in props, "the model has no value field to fill"
    assert not {"verdict", "risk"} & set(ollama_params(PACK)["format"]["properties"])


def test_check_catches_bad_keys_references_numbers_and_directions():
    f = facts(PACK)
    assert check(narrative(), f)["faithful"]
    bad_key = narrative(claims=[NClaim(key="obs.nope", reference_key="", meaning=""),
                                NClaim(key="gate.n_new_src_ntlm", reference_key="", meaning="")])
    bad_ref = narrative(claims=[NClaim(key="obs.fail_ratio", reference_key="forest.path_length", meaning=""),
                                NClaim(key="gate.n_new_src_ntlm", reference_key="", meaning="")])
    grounded = narrative(summary="96 NTLM logons from new hosts; failure ratio 0.94.")
    made_up = narrative(summary="That is 5x the usual, 300 events.")
    wrong_dir = narrative(claims=[NClaim(key="obs.fail_ratio", reference_key="obs.fail_ratio_base_mean",
                                         meaning="far above the user's usual failure rate"),
                                  NClaim(key="gate.n_new_src_ntlm", reference_key="", meaning="")])
    one_claim = narrative(claims=[NClaim(key="obs.fail_ratio", reference_key="", meaning="")])
    assert check(grounded, f)["faithful"], "numbers from the facts are fine"
    for n in (bad_key, bad_ref, made_up, wrong_dir, one_claim):
        assert not check(n, f)["faithful"]
    assert check(made_up, f)["ungrounded_numbers"] == ["5", "300"]
    assert not check(wrong_dir, f)["claims"][0]["direction_ok"], "0.94 vs 0.98 is similar, not far above"


def test_schema_restricts_keys_to_this_alerts_facts():
    from triage.narrate import schema_for
    f = facts(PACK)
    claim = schema_for(f)["properties"]["claims"]["items"]["properties"]
    assert set(claim["key"]["enum"]) == set(f)
    assert "obs.fail_ratio_base_mean" in claim["reference_key"]["enum"] and "" in claim["reference_key"]["enum"]
    assert "factor1.push" not in claim["reference_key"]["enum"]


def test_run_caches_and_summary(tmp_path):
    calls = []

    def fake(params):
        calls.append(1)
        return {"message": {"content": narrative().model_dump_json()}, "done_reason": "stop", "eval_count": 9}
    cf = tmp_path / "n.jsonl"
    assert run([PACK], cf, call=fake) == 1 and run([PACK], cf, call=fake) == 0 and len(calls) == 1
    rs = rows([PACK], cf)
    assert rs[0]["status"] == "ok" and rs[0]["check"]["faithful"]
    s = summary(rs + [{"alert_id": "x", "status": "missing"}])
    assert s["alerts_fully_faithful"] == 0.5 and s["status_counts"] == {"ok": 1, "missing": 1}
