# Alert explanations: lanl_pilot v2, days 1-7, top 50/day

- alerts explained: 350; max |SHAP reconstruction - forest score| = 1.55e-15
- refit reproduces stored two_stage scores: False

## Deletion check (reset k features to the training median, rescore the forest)

| k | mean drop, top-SHAP k | mean drop, random k | share of alerts where top beats random |
|---|---|---|---|
| 1 | 0.0227 | 0.0022 | 99.4% |
| 3 | 0.0561 | 0.0076 | 100.0% |
| 5 | 0.0824 | 0.0138 | 100.0% |

## Leading factor, true vs false alerts (labels used for this table only)

```
{
  "false_alerts": {
    "n": 346,
    "gate_pass_rate": 1.0,
    "top1_factor_counts": {
      "log1p_n_new_src_ntlm": 167,
      "new_dst_ratio": 63,
      "fail_ratio": 48,
      "log1p_n_new_src_remote": 30,
      "off_hours_ratio": 11,
      "log1p_n_fail": 7
    }
  },
  "true_alerts": {
    "n": 4,
    "gate_pass_rate": 1.0,
    "top1_factor_counts": {
      "log1p_n_new_src_ntlm": 4
    }
  }
}
```

## Highest-ranked true alert (rank 3 on day 1)

**U748|d1**: gate passed (n_new_src_remote=165, n_new_src_ntlm=87); forest score 0.599, path length 11.66 vs expected 21.41

- `log1p_n_new_src_ntlm` push +2.225: n_new_src_ntlm=87
- `log1p_n_new_src_hosts` push +1.125: n_new_src_hosts=23
- `log1p_n_new_src_remote` push +1.086: n_new_src_remote=165
- `log1p_n_new_dst_hosts` push +0.877: n_new_dst_hosts=22, n_new_dst_hosts_base_mean=0.0
- `log1p_n_new_pair_events` push +0.803: n_new_pair_events=705

## Highest-ranked false alert (rank 1 on day 1)

**U1718|d1**: gate passed (n_new_src_remote=37, n_new_src_ntlm=53); forest score 0.717, path length 7.57 vs expected 21.41

- `fail_ratio` push +1.655: fail_ratio=0.9772, fail_ratio_base_mean=0.9757
- `log1p_n_new_src_ntlm` push +1.603: n_new_src_ntlm=53
- `log1p_n_new_src_hosts` push +1.323: n_new_src_hosts=241
- `log1p_n_new_dst_hosts` push +1.248: n_new_dst_hosts=883, n_new_dst_hosts_base_mean=0.0
- `log1p_n_fail` push +1.043: n_fail=1071, n_fail_base_mean=1123.0
