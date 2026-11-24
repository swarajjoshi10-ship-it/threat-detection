Window **posthoc** (days 15-29), W = 7, 114,393 user-days, 47 malicious — **post-hoc**

| detector | pr_auc | alerts_per_day@80 | recall@10/day | recall@50/day | accounts_caught@50/day | median_days_to_first_catch |
|---|---|---|---|---|---|---|
| rules | 0.001 | 4,101 | 0.002 | 0.032 | 0.000 | – |
| iforest | 0.003 | 2,083 | 0.000 | 0.064 | 0.027 | 0.0 |
| two_stage | 0.002 | 2,192 | 0.000 | 0.000 | 0.000 | – |
| iforest_v3 | 0.003 | 1,831 | 0.000 | 0.064 | 0.027 | 0.0 |
| host_fanout | 0.002 | 2,507 | 0.000 | 0.021 | 0.027 | 14.0 |

Host view: positive_host_days = 12, distinct_attacker_hosts = 2, host_recall@1/day = 0.000, host_recall@5/day = 0.000, host_recall@10/day = 0.000
