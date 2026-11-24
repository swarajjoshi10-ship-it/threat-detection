Source: **synthetic**, features **v1** · fit on days < 8 (2,381 active user-days) · tested on days >= 8 (1,779 user-days, 6 days, 24 malicious, prevalence 1.349%)

| model | pr_auc | alerts_per_day@50 | alerts_per_day@80 | alerts_per_day@90 | recall@5/day | recall@10/day | recall@25/day | recall@50/day | PR-AUC 90% CI | alerts/day@80 90% CI |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 0.392 | 6 | 94 | 175 | 0.590 | 0.658 | 0.760 | 0.782 | 0.261–0.509 | 10–157 |
| zscore_max | 0.231 | 12 | 100 | 104 | 0.417 | 0.500 | 0.542 | 0.650 | 0.121–0.374 | 42–107 |
| iforest | 0.543 | 3 | 51 | 66 | 0.500 | 0.625 | 0.708 | 0.792 | 0.385–0.676 | 7–69 |
| autoencoder | 0.644 | 3 | 32 | 55 | 0.583 | 0.708 | 0.750 | 0.875 | 0.480–0.772 | 5–56 |
| supervised_ceiling | 0.719 | 2 | 10 | 20 | 0.708 | 0.875 | 0.917 | 0.917 | 0.536–0.857 | 3–20 |
