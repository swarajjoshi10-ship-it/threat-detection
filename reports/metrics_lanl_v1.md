Source: **lanl**, features **v1** · fit on days < 8 (60,336 active user-days) · tested on days >= 8 (55,228 user-days, 7 days, 116 malicious, prevalence 0.210%)

| model | pr_auc | alerts_per_day@50 | alerts_per_day@80 | alerts_per_day@90 | recall@5/day | recall@10/day | recall@25/day | recall@50/day | PR-AUC 90% CI | alerts/day@80 90% CI |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 0.019 | 491 | 3,462 | 5,676 | 0.003 | 0.006 | 0.018 | 0.052 | 0.013–0.025 | 2,420–4,367 |
| zscore_max | 0.004 | 2,110 | 3,934 | 5,088 | 0.000 | 0.017 | 0.052 | 0.052 | 0.003–0.008 | 3,192–4,343 |
| iforest | 0.040 | 408 | 2,271 | 3,379 | 0.034 | 0.060 | 0.112 | 0.172 | 0.020–0.081 | 1,494–2,692 |
| autoencoder | 0.011 | 1,159 | 2,700 | 3,674 | 0.009 | 0.034 | 0.060 | 0.086 | 0.006–0.023 | 2,220–2,882 |
| supervised_ceiling | 0.085 | 92 | 1,602 | 2,834 | 0.057 | 0.109 | 0.218 | 0.343 | 0.059–0.112 | 385–2,795 |
