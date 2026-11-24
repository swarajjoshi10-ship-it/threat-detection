Source: **synthetic**, features **v2** · fit on days < 8 (2,381 active user-days) · tested on days >= 8 (1,779 user-days, 6 days, 24 malicious, prevalence 1.349%)

| model | pr_auc | alerts_per_day@50 | alerts_per_day@80 | alerts_per_day@90 | recall@5/day | recall@10/day | recall@25/day | recall@50/day | PR-AUC 90% CI | alerts/day@80 90% CI |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 0.486 | 4 | 95 | 176 | 0.606 | 0.657 | 0.759 | 0.781 | 0.349–0.605 | 10–157 |
| zscore_max | 0.231 | 12 | 100 | 104 | 0.417 | 0.500 | 0.542 | 0.650 | 0.121–0.374 | 42–107 |
| new_src_remote | 0.239 | 5 | 164 | 217 | 0.542 | 0.590 | 0.612 | 0.647 | 0.105–0.392 | 6–205 |
| iforest | 0.552 | 3 | 42 | 57 | 0.542 | 0.625 | 0.708 | 0.833 | 0.361–0.708 | 7–58 |
| autoencoder | 0.613 | 3 | 45 | 52 | 0.583 | 0.625 | 0.750 | 0.833 | 0.442–0.742 | 7–57 |
| supervised_ceiling | 0.792 | 2 | 8 | 24 | 0.792 | 0.833 | 0.875 | 0.958 | 0.617–0.917 | 2–23 |
