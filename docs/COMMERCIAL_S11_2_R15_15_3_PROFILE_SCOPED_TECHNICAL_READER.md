# Commercial S11.2-R15.15.3 profile-scoped Technical reader

## Scope and root cause

R15.15.2 proved `EXPECTED_SHARED_BINDING_CONTRACT_MISMATCH`. Application and
Control intentionally use the same `target_release_id` and
`technical_evidence_run_id` for Technical and REAL Direct latency evidence.
Despite its historical name, `technical_evidence_run_id` is not an exclusive
Technical namespace. The REAL writer and the Technical Probe writer are both
correct and remain unchanged.

The old Control reader selected every DIRECT row in the shared release/run and
rolling 24-hour window, selected Technical values, and then required the
Technical selection count to equal the total row count. A fresh, valid REAL
Direct row therefore caused `S11_2_TECHNICAL_PROVENANCE_RED`. Waiting for that
row to expire was not a root-cause resolution.

R15.15.3 keeps the broad bounded read so ambiguous evidence remains visible.
It first validates every DIRECT row against canonical provenance and metric
bounds, then selects only the Technical Runtime profile. Known canonical rows
from another profile are ignored only by this Technical calculation; they are
not deleted, rewritten, or hidden from their corresponding reader.

## Cross-profile contract

The canonical semantic authority is Application commit
`db87896697d56b24f192fc1cd0324b6fe46d734b`,
`src/tu1nz_public_s8/latency_slo.py`. The Control regression mirror is
`tests/fixtures/s11-2-r15-15-3/application-latency-profile-contract.json`.

| Profile | Source | Evidence | Sample type | Interaction path | Metric | Window | Release selector | Run selector |
|---|---|---|---|---|---|---|---|---|
| `TECHNICAL_RUNTIME_LATENCY` | DIRECT | INTERNAL_TEST | DIRECT_BOT_RESPONSE | profile does not add a filter; canonical writer uses INTERNAL_ACCEPTANCE | HANDLER | rolling 24 h | target_release_id | technical_evidence_run_id |
| `REAL_USER_DIRECT_LATENCY` | DIRECT | REAL | DIRECT_BOT_RESPONSE | profile does not add a filter; canonical writer uses TELEGRAM_DIRECT | BOT_RESPONSE | rolling 24 h | target_release_id | technical_evidence_run_id |
| `S11_CANARY_TECHNICAL_LATENCY` | DIRECT | INTERNAL_TEST | S11_CANARY_RESPONSE | INTERNAL_ACCEPTANCE | HANDLER | immutable Canary epoch, at most 24 h | canary_release_id | none |
| `S11_CANARY_REAL_USER_LATENCY` | DIRECT | REAL | S11_CANARY_RESPONSE | TELEGRAM_DIRECT | BOT_RESPONSE | immutable Canary epoch, at most 24 h | canary_release_id | none |

The runtime writer maps other canonical Direct evidence classes to their
dedicated paths: SYNTHETIC to SYNTHETIC_FIXTURE, HEALTH to RUNTIME_HEALTH, and
PROVIDER_PROBE to PROVIDER_PROBE. Such valid rows may share the binding and do
not count toward the Technical profile.

## Fail-closed and metric rules

Any bounded DIRECT row containing UNKNOWN, null, empty, unrecognized values,
an impossible evidence/path combination, a missing metric, or a non-integer or
out-of-range metric raises `S11_2_TECHNICAL_PROVENANCE_RED`. This validation
precedes Technical selection, so an UNKNOWN row cannot be made invisible by a
narrow SQL predicate. Every latency metric must be an integer from 0 through
300000 ms.

Only `handler_duration_ms` from canonical
INTERNAL_TEST/DIRECT_BOT_RESPONSE/INTERNAL_ACCEPTANCE rows enters the Technical
SLO. REAL `bot_response_latency_ms` is never substituted. The sample floor is
five and `missing_samples=max(0, 5-current_valid_technical_samples)`: REAL rows
do not change that count.

## Freeze and next boundary

The 29-key binding stays stable. `technical_evidence_contract` advances to
`PROFILE_SCOPED_MIXED_PROVENANCE_DYNAMIC_HARD_CAP_V2`. The new controller-bound
tag is `s11-2-r15-15-3-profile-scoped-technical-freeze-r1`; historical tags are
immutable and remain verifiable under their historical contract values.

R15.15.3 is source-only. It performs no SSH, sudo, deployment, database write,
Technical Probe, Canary, Yoti access, or product-boundary activation. R15.16
runtime execution requires separate authorization after the new tag and the
source-only simulator are both verified GREEN.
