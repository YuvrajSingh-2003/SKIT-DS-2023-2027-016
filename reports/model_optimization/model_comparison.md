# URL model comparison

All rows: seed 42, same estimator and features, train on `stratified_train.csv`.
- **Val** = `stratified_validation.csv` (35,305 rows); used for all selection.
- **Test** = locked `stratified_test.csv` (35,306 rows); scored once at the end.
- **OpenPhish** = 300 unseen 2026-10-28 phishing URLs (recall only).
- **Probes** = 20,227 legitimate validation URLs, transformed (FPR).

| Candidate | Norm. | Thr | Val phish P / R / F1 | Val FPR | Val AUC | Test phish P / R / F1 | Test FPR | Test AUC | OpenPhish recall |
|---|---|---|---|---|---|---|---|---|---|
| production | raw | 0.5 | 0.983 / 0.942 / 0.962 | 1.24% | 0.987 | 0.985 / 0.943 / 0.963 | 1.10% | 0.988 | 95.0% |
| c1 neutral | scheme+www stripped | 0.5 | 0.945 / 0.706 / 0.808 | 3.07% | 0.884 | 0.943 / 0.704 / 0.806 | 3.16% | 0.884 | 87.3% |
| c2 host | host only | 0.5 | 0.887 / 0.629 / 0.736 | 6.00% | 0.840 | 0.887 / 0.627 / 0.734 | 5.97% | 0.840 | 65.7% |
| c3 host + thr | host only | 0.7366 | 0.972 / 0.540 / 0.694 | 1.17% | 0.840 | 0.968 / 0.538 / 0.692 | 1.34% | 0.840 | 59.7% |

Legitimate-class precision / recall / F1 on test:

| Candidate | Legitimate P / R / F1 |
|---|---|
| production | 0.959 / 0.989 / 0.974 |
| c1 | 0.814 / 0.968 / 0.885 |
| c2 | 0.772 / 0.940 / 0.848 |
| c3 | 0.741 / 0.987 / 0.847 |

Test confusion matrices (tn / fp / fn / tp):

| Candidate | tn / fp / fn / tp |
|---|---|
| production | 20006 / 222 / 862 / 14216 |
| c1 | 19588 / 640 / 4468 / 10610 |
| c2 | 19021 / 1207 / 5627 / 9451 |
| c3 | 19957 / 271 / 6960 / 8118 |

## Template probes (FPR on legitimate validation URLs)

| Probe | production | c1 | c2 | c3 |
|---|---|---|---|---|
| as is | 1.24% | 3.07% | 6.00% | 1.17% |
| drop `www.` | **85.2%** | 3.07% | 6.00% | 1.17% |
| `http://` | **100%** | 3.07% | 6.00% | 1.17% |
| no scheme | **100%** | 3.07% | 6.00% | 1.17% |
| `+/about` | **100%** | **100%** | 6.00% | 1.17% |
| `+/search?q=news` | **100%** | **100%** | 6.00% | 1.17% |

## Latency and size

- Latency: about 2.6 ms per single URL for every model, including feature extraction (mean of 200
  calls, 24-core CPU).
- Size: production 752,883 B; c1 900,392 B; c2/c3 930,789 B.

## Interpretation

Production's in-distribution scores are real but not representative: the probes show the model uses
the PhiUSIIL template. The honest, template-free skill available from lexical features on this dataset
is about AUC 0.84 (host only) to 0.88 (path still allowed). None of the candidates dominates
production on every axis, so none is promoted.
