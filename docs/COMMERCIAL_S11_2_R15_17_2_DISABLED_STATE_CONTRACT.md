# Commercial S11.2-R15.17.2 disabled-state contract

## Scope and root cause

R15.17.2 corrects `DISABLED_STATE_CONTRACT_MISMATCH`. The rejected R15.17.1
deployment reached `S11_2_CODE_OFF_RED` because the controller treated
`canary_live_start IS NULL` as part of every code-off state. A canonical
rollback intentionally leaves a completed, terminal Canary epoch attached to
the disabled singleton until the later rearm phase archives it. The precise
failure class is `TERMINAL_CANARY_EPOCH_REJECTED_BEFORE_CANONICAL_REARM`.

This is a Control-only contract correction. Application migrations and their
serialized transition/rearm entrypoints remain authoritative and unchanged.
There is no direct cleanup, evidence deletion, gate bypass, automatic retry or
product-boundary expansion.

## Canonical classifier

The controller reads the singleton once and classifies it with the same helper
used by preflight, installation, fallback, rearm and rollback:

Before migration 0033, absence of all six bootstrap columns is an explicit
legacy schema. Only `enabled=false` with `live_start=NULL` maps to
`CLEAN_NOT_STARTED`; a partially installed bootstrap schema or any live legacy
state maps to `INVALID_DISABLED_STATE`. This preserves first-install support
without weakening the post-migration classifier.

| Class | Required disabled-state shape | Where accepted |
|---|---|---|
| `CLEAN_NOT_STARTED` | product disabled; `live_start`, full-live and all active epoch fields null; `S11_DISABLED/NOT_STARTED` | fresh preflight, install, fallback and rearm |
| `TERMINAL_REARMABLE` | product disabled; `live_start` and full-live null; `S11_DISABLED`; promotion is `CANARY_RED` or `CANARY_INSUFFICIENT_REAL_VOLUME`; complete 24-hour historical epoch including non-null Canary live start | fresh preflight, install and fallback; then canonical rearm |
| `PRE_CANARY_ARMED` | product disabled; `S11_DISABLED/NOT_STARTED`; current release and evidence epoch bound; Canary live start null; valid 24-hour horizon | only the evidence-epoch and Canary-start phases, plus rollback cancellation |
| `INVALID_DISABLED_STATE` | every inconsistent or partial combination | hard red everywhere |

`PUBLIC_CODE_OFF`, `EPOCH_CLEARED` and `TERMINAL_EPOCH_REARMABLE` are separate
invariants. In particular, historical `canary_live_start` is not public-live
state.

## State transitions and archival

Allowed controller flow:

1. `CLEAN_NOT_STARTED` may proceed unchanged.
2. `TERMINAL_REARMABLE` is preserved through install, synthetic journeys and
   feature-off fallback.
3. `CANARY_REARMED` records the history count, invokes only
   `tu1nz_s11_2_rearm_runtime_control`, requires exactly one new history row and
   then requires `CLEAN_NOT_STARTED`. Before invoking the database function it
   atomically persists a privacy-safe rearm intent with the pre-rearm history
   count. If execution is interrupted after the transaction commits, resume
   accepts the already-clean state only after proving the persisted count grew
   by exactly one; it never replaces that proof with a zero-delta artifact.
4. `SET_EVIDENCE_EPOCH` changes clean state to `PRE_CANARY_ARMED`.
5. Only `START_CANARY` changes `PRE_CANARY_ARMED` to
   `S11_CANARY/CANARY_COLLECTING_EVIDENCE`.
6. A failed active Canary is canonically transitioned to terminal red during
   rollback; that historical state is deliberately preserved for the next
   separately authorized deployment.

The controller never updates the singleton directly and never deletes latency
or epoch-history evidence. Privacy-safe runtime evidence records only phase,
before/after classification, archival delta and a bounded safe code.

## Repeated-deployment regression

The source-only R15.17.2 simulator models the exact live-shaped sequence:

- deployment 1 starts clean, arms an epoch, starts one Canary and fails;
- canonical rollback leaves a complete terminal epoch;
- deployment 2 accepts `TERMINAL_REARMABLE` as code off;
- install, synthetic validation and fallback preserve it;
- canonical rearm archives exactly one epoch and yields clean state;
- one new epoch is armed and exactly one new Canary start occurs;
- the R15.17.1 current-invocation Systemd handoff and standalone verification
  remain green.

The A-J matrix covers clean, both terminal outcomes, canonical pre-Canary and
partial/stale/active/full-live invalid combinations. The live-shaped technical
profile remains five valid samples and zero missing samples; no fixture mutates
runtime or database state.

## Preserved gates and boundaries

All prior R15.4, R15.6, R15.8, R15.10, R15.12, R15.14, R15.14.1, R15.15.3,
R15.16.4 and R15.17.1 contracts remain mandatory. Adult media, real AVS,
payments, external publishing, controlled beta and production remain closed.
The runtime deployment allowance is exactly one fresh, frozen, backup-first
attempt after read-only classification and all gates are green. An invalid
state or repository/process drift stops before mutation.
