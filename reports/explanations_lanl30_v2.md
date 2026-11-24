# Alert explanations: lanl30 v2, days 15-29, top 50/day

- alerts explained: 750; max |SHAP reconstruction - forest score| = 1.22e-15
- refit reproduces stored two_stage scores: True

## Deletion check (reset k features to the training median, rescore the forest)

| k | mean drop, top-SHAP k | mean drop, random k | share of alerts where top beats random |
|---|---|---|---|
| 1 | 0.0216 | 0.0027 | 100.0% |
| 3 | 0.0561 | 0.0085 | 100.0% |
| 5 | 0.0823 | 0.0151 | 100.0% |

## Leading factor, true vs false alerts (labels used for this table only)

```
{
  "false_alerts": {
    "n": 750,
    "gate_pass_rate": 1.0,
    "top1_factor_counts": {
      "log1p_n_new_src_ntlm": 321,
      "fail_ratio": 96,
      "new_dst_ratio": 82,
      "log1p_n_new_src_remote": 68,
      "off_hours_ratio": 42,
      "slog_n_dst_hosts_peer_z": 27
    }
  }
}
```

## Highest-ranked false alert (rank 1 on day 15)

**U1718|d15**: gate passed (n_new_src_remote=32, n_new_src_ntlm=39); forest score 0.748, path length 6.62 vs expected 21.41

- `fail_ratio` push +1.385: fail_ratio=0.9563, fail_ratio_base_mean=0.9567
- `log1p_n_new_src_ntlm` push +1.086: n_new_src_ntlm=39
- `slog_fail_ratio_peer_z` push +1.021: fail_ratio=0.9563, fail_ratio_peer_z=19.0311, peer_group=peer_C2519, peer_n=11
- `log1p_n_new_src_hosts` push +0.976: n_new_src_hosts=91
- `log1p_n_new_dst_hosts` push +0.946: n_new_dst_hosts=344, n_new_dst_hosts_base_mean=441.8571
