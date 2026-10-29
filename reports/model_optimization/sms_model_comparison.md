# SMS model comparison (validation, 865 rows; test only where stated)

Per-class columns are precision / recall / F1 on validation.

| Model | Macro-F1 | legitimate | generic_spam | smishing | Legit FPR* | Δ vs prod (95% CI) |
|---|---|---|---|---|---|---|
| **production** (char LR) | **0.9245** | .988/.997/.992 | .869/.841/.855 | .958/.896/.926 | 0.28% | — |
| A retrain | 0.9245 | identical | identical | identical | 0.28% | 0 |
| B LinearSVC char (calibrated) | 0.9405 | .989/.999/.994 | .889/.889/.889 | .986/.896/.939 | 0.14% | +0.016 [+0.003, +0.035] |
| C XGB word k2000 | 0.8570 | .974/.993/.984 | .730/.730/.730 | .952/.779/.857 | 0.69% | −0.069 [−0.124, −0.016] |
| D XGB word k2000 + numeric | 0.8892 | .994/.996/.995 | .776/.825/.800 | .903/.844/.872 | 0.41% | −0.036 [−0.086, +0.014] |
| E XGB char k5000 + numeric | 0.9081 | .992/1.00/.996 | .862/.794/.826 | .908/.896/.902 | 0.00% | −0.017 [−0.067, +0.029] |

\* Legit FPR = legitimate messages predicted as spam or smishing.

## Confusion matrices (validation)

Rows are true labels, columns are predictions, both in the order legit / spam / smish.

| Model | Matrix |
|---|---|
| production | `[[723,2,0],[7,53,3],[2,6,69]]` |
| B | `[[724,1,0],[6,56,1],[2,6,69]]` |
| C | `[[720,5,0],[14,46,3],[5,12,60]]` |
| D | `[[722,3,0],[4,52,7],[0,12,65]]` |
| E | `[[725,0,0],[6,50,7],[0,8,69]]` |

## Cost

Latency is per message, `predict_proba`, mean of 200 calls.

| Model | Train time | Latency | Size |
|---|---|---|---|
| production / A | 6.5 s | 0.71 ms | 1.45 MB |
| B | 1.2 s | 3.76 ms | 4.76 MB |
| C | 2.7 s | 2.60 ms | 1.77 MB |
| D | 1.9 s | 3.79 ms | 1.82 MB |
| E | 8.1 s | 6.69 ms | 2.61 MB |

## Reproducibility: grouped 5-fold CV on train+val (A vs B)

| | Mean macro-F1 | Std |
|---|---|---|
| A | 0.923 | 0.019 |
| B | 0.920 | 0.015 |

B − A = −0.003. B is better in 2 of 5 folds, so it is not a reproducible improvement.

## Locked test (scored once, after the retain decision)

| Model | Macro-F1 | Matrix | Legit FPR |
|---|---|---|---|
| production | 0.8929 | `[[725,0,0],[6,49,8],[2,9,66]]` | 0% |
| B | 0.8976 | `[[725,0,0],[6,49,8],[2,8,67]]` | 0% |

The models differ on 1 message.
