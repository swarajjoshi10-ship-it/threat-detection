# Alert explanations: synthetic v2, days 8-13, top 10/day

- alerts explained: 60; max |SHAP reconstruction - forest score| = 6.66e-16
- refit reproduces stored two_stage scores: None

## Deletion check (reset k features to the training median, rescore the forest)

| k | mean drop, top-SHAP k | mean drop, random k | share of alerts where top beats random |
|---|---|---|---|
| 1 | 0.0295 | 0.0035 | 100.0% |
| 3 | 0.0715 | 0.0106 | 100.0% |
| 5 | 0.0988 | 0.0176 | 100.0% |

## Leading factor, true vs false alerts (labels used for this table only)

```
{
  "false_alerts": {
    "n": 45,
    "gate_pass_rate": 0.4,
    "top1_factor_counts": {
      "log1p_n_new_src_hosts": 16,
      "log1p_n_new_dst_hosts": 4,
      "fail_ratio": 4,
      "log1p_n_fail": 3,
      "slog_n_new_dst_hosts_z": 3,
      "slog_n_off_hours_peer_z": 2
    }
  },
  "true_alerts": {
    "n": 15,
    "gate_pass_rate": 0.933,
    "top1_factor_counts": {
      "slog_n_src_hosts_z": 11,
      "log1p_n_new_src_hosts": 3,
      "log1p_n_fail": 1
    }
  }
}
```

## Highest-ranked true alert (rank 1 on day 8)

**U224|d8**: gate passed (n_new_src_remote=25, n_new_src_ntlm=25); forest score 0.789, path length 5.03 vs expected 19.76

- `slog_n_src_hosts_z` push +1.075: n_src_hosts=11, n_src_hosts_base_mean=1.0, n_src_hosts_z=10.0, baseline_days=7
- `log1p_n_new_src_ntlm` push +0.833: n_new_src_ntlm=25
- `log1p_n_new_src_hosts` push +0.793: n_new_src_hosts=10
- `new_dst_ratio` push +0.760: new_dst_ratio=0.7143
- `log1p_n_new_pair_events` push +0.705: n_new_pair_events=27

## Highest-ranked false alert (rank 3 on day 8)

**U50|d8**: gate passed (n_new_src_remote=49, n_new_src_ntlm=2); forest score 0.594, path length 11.07 vs expected 19.76

- `log1p_n_new_src_hosts` push +1.950: n_new_src_hosts=1
- `log1p_n_new_pair_events` push +1.838: n_new_pair_events=74
- `log1p_n_new_src_remote` push +1.713: n_new_src_remote=49
- `log1p_n_new_src_ntlm` push +1.518: n_new_src_ntlm=2
- `slog_n_new_dst_hosts_peer_z` push +0.407: n_new_dst_hosts=3, n_new_dst_hosts_peer_z=3.0, peer_group=peer_C10, peer_n=9
