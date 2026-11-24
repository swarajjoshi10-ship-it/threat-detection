Window **dev** (days 8-14), W = 7, 55,228 user-days, 116 malicious

| detector | pr_auc | alerts_per_day@80 | recall@10/day | recall@50/day | accounts_caught@50/day | median_days_to_first_catch |
|---|---|---|---|---|---|---|
| rules | 0.053 | 960 | 0.013 | 0.163 | 0.186 | 0.0 |
| iforest | 0.057 | 1,441 | 0.069 | 0.190 | 0.198 | 0.0 |
| two_stage | 0.095 | 614 | 0.078 | 0.250 | 0.302 | 0.0 |
| iforest_v3 | 0.099 | 486 | 0.086 | 0.302 | 0.337 | 0.0 |
| host_fanout | 0.162 | 92 | 0.034 | 0.302 | 0.326 | 0.0 |

Host view: positive_host_days = 9, distinct_attacker_hosts = 3, host_recall@1/day = 0.000, host_recall@5/day = 0.222, host_recall@10/day = 0.222
