# Alert explanations: lanl v2, days 8-14, top 50/day

- alerts explained: 350; max |SHAP reconstruction - forest score| = 9.99e-16
- refit reproduces stored two_stage scores: True

## Deletion check (reset k features to the training median, rescore the forest)

| k | mean drop, top-SHAP k | mean drop, random k | share of alerts where top beats random |
|---|---|---|---|
| 1 | 0.0209 | 0.0025 | 99.4% |
| 3 | 0.0536 | 0.0081 | 100.0% |
| 5 | 0.0799 | 0.0145 | 100.0% |

## Leading factor, true vs false alerts (labels used for this table only)

```
{
  "false_alerts": {
    "n": 321,
    "gate_pass_rate": 1.0,
    "top1_factor_counts": {
      "log1p_n_new_src_ntlm": 150,
      "new_dst_ratio": 36,
      "fail_ratio": 35,
      "log1p_n_new_src_remote": 32,
      "off_hours_ratio": 26,
      "log1p_n_fail": 5
    }
  },
  "true_alerts": {
    "n": 29,
    "gate_pass_rate": 1.0,
    "top1_factor_counts": {
      "log1p_n_new_src_ntlm": 23,
      "slog_n_ntlm_peer_z": 2,
      "log1p_n_new_pair_events": 1,
      "slog_n_new_dst_hosts_peer_z": 1,
      "log1p_n_fail": 1,
      "slog_n_dst_hosts_peer_z": 1
    }
  }
}
```

## Highest-ranked true alert (rank 2 on day 8)

**U8946|d8**: gate passed (n_new_src_remote=210, n_new_src_ntlm=33); forest score 0.697, path length 8.24 vs expected 21.41

- `log1p_n_new_src_ntlm` push +1.249: n_new_src_ntlm=33
- `log1p_n_new_dst_hosts` push +0.831: n_new_dst_hosts=30, n_new_dst_hosts_base_mean=5.0
- `log1p_n_new_src_remote` push +0.821: n_new_src_remote=210
- `log1p_n_new_src_hosts` push +0.801: n_new_src_hosts=24
- `log1p_n_fail` push +0.663: n_fail=241, n_fail_base_mean=6.2857

## Highest-ranked false alert (rank 1 on day 8)

**U1718|d8**: gate passed (n_new_src_remote=43, n_new_src_ntlm=96); forest score 0.758, path length 6.31 vs expected 21.41

- `fail_ratio` push +1.296: fail_ratio=0.9369, fail_ratio_base_mean=0.9772
- `log1p_n_new_src_ntlm` push +1.210: n_new_src_ntlm=96
- `log1p_n_new_src_hosts` push +1.036: n_new_src_hosts=179
- `log1p_n_new_dst_hosts` push +1.023: n_new_dst_hosts=770, n_new_dst_hosts_base_mean=491.2857
- `slog_fail_ratio_peer_z` push +1.000: fail_ratio=0.9369, fail_ratio_peer_z=18.7378, peer_group=peer_C2519, peer_n=11
