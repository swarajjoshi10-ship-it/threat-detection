"""The Sigma and Splunk ports must use the same parameters as the tested SQL rule and its reports."""

import json
import re
from pathlib import Path

from detections.rule import PARAMS

ROOT = Path(__file__).resolve().parents[1]
SIGMA = (ROOT / "detections" / "sigma" / "host_many_accounts.yml").read_text(encoding="utf-8")
SPL = (ROOT / "detections" / "splunk" / "host_fanout.spl").read_text(encoding="utf-8")


def test_sigma_threshold_is_the_label_free_one():
    rows = json.loads((ROOT / "reports" / "detection_count_rule.json").read_text())["rows"]
    label_free = [r["threshold"] for r in rows if r["label_free"]]
    assert re.findall(r"^\s+gte: (\d+)$", SIGMA, re.M) == [str(t) for t in label_free]
    assert "generate: false" in SIGMA, "the base rule must not alert on its own"


def test_generated_spl_matches_the_sigma_threshold():
    gen = (ROOT / "detections" / "sigma" / "host_many_accounts.generated.spl").read_text(encoding="utf-8")
    assert re.search(r"value_count >= (\d+)", gen).group(1) == re.search(r"gte: (\d+)", SIGMA).group(1)


def test_splunk_port_uses_the_sql_rule_parameters():
    thr = json.loads((ROOT / "reports" / "detection_rule.json").read_text())["params"]["threshold"]
    w, min_new, watch = PARAMS["w"], PARAMS["min_new"], PARAMS["watch_days"]
    assert f"fanout>={thr:g} AND n_recent_new_users>={min_new}" in SPL
    assert f"first_day>today-{w}" in SPL and f"pair_first_day>first_trigger-{w}" in SPL
    assert f"last_trigger>=today-{watch}" in SPL
    # same exclusions and the same cold-start rule as the SQL
    assert SPL.count('TargetUserName!="*$"') == 2 and "first_day>user_first_day" in SPL
