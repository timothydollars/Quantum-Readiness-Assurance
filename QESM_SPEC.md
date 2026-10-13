# Quantum Exposure Scoring Model (QESM) — specification

This is the method described in Exhibit E-1, Section 6. `qraf.qesm` must
implement it exactly; `tests/test_qesm.py` checks it against the worked example.

## Inputs (one row per asset, CSV)

| Column | Meaning | Allowed values |
| --- | --- | --- |
| `asset_id` | Unique identifier, ideally a CBOM bom-ref | text |
| `description` | Short human description | text |
| `x_shelf_life_years` | Years the protected data must stay confidential (X) | number >= 0 |
| `y_migration_years` | Years migration of this asset will take (Y) | number >= 0 |
| `e_exposure` | How easily traffic or keys can be captured (E) | integer 1-5 |
| `c_criticality` | Business criticality from the BIA (C) | integer 1-5 |
| `d_dependency` | Lack of direct control over the fix; vendor-controlled = 5 (D) | integer 1-5 |

Rows that break these rules must raise `ValueError` naming the asset and column.

## Steps

1. Timeline gap: `gap = X + Y - Z`, where Z is the horizon in years (default 9).
2. Timeline score T from the gap:

   | Gap | T |
   | --- | --- |
   | >= 0 | 5 |
   | >= -2 | 4 |
   | >= -4 | 3 |
   | >= -6 | 2 |
   | below -6 | 1 |

3. Priority: `P = wT*T + wE*E + wC*C + wD*D`, rounded to 2 decimals.
   Default weights (config/qesm_weights.yaml): wT 0.35, wE 0.25, wC 0.25, wD 0.15.
   Weights must sum to 1 (tolerance 1e-9); otherwise raise `ValueError`.
4. Tier from P: >= 4.0 Tier 1; >= 3.0 Tier 2; otherwise Tier 3.
5. Output sorted by P (highest first), ties broken by asset_id.

## Sensitivity analysis

* **Horizon:** re-score at Z = 4, 9 and 14. Report each asset's tier at each
  horizon and the number of assets whose tier differs from the Z = 9 result.
* **Weights:** for each weight, add and subtract 0.05, renormalize all four so
  they sum to 1, re-score, and report how many assets change tier. That gives
  8 scenarios.

## Worked example (examples/qesm_assets_example.csv), Z = 9

| Asset | Gap | T | P | Tier |
| --- | --- | --- | --- | --- |
| sftp-core-ach | 0 | 5 | 4.50 | 1 |
| tls-online-banking | -2 | 4 | 4.20 | 1 |
| backup-key-wrap | 3 | 5 | 3.70 | 2 |
| internal-ca | -5 | 2 | 2.50 | 3 |

Work these out by hand once before you code, and again at Z = 4 and Z = 14.
The tests check your code against all three horizons.
