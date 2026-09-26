# Commercial S11.2-R15.10 Bash nounset and pre-Canary error safety

Status: source-only. No server, systemd, database, Telegram, public runtime, or
Canary mutation was performed by this release.

## Root cause

R15.9 stopped in `pre_canary_health()` before the first S11.2 Canary phase.
The declaration combined assignment and expansion in one `local` command:

```bash
local destination="$1" structured="${destination}.ndjson"
```

Under `set -u`, Bash expands every assignment operand before `local` installs
the local variables. `destination` was therefore unset while `structured` was
expanded. Bash terminated the shell with an unbound-variable error. This class
of expansion does not reliably execute an `ERR` trap, so a rollback contract
that depends only on that trap is incomplete.

The failure happened before the health child executed and before any Canary
activation. It was a Bash declaration-order defect, not a health, Telegram,
provider, latency, evidence, or product-boundary failure.

## Complete same-local inventory

The full controller scan found three dependency declarations:

1. `write_technical_profile()`: `destination` to `gate_file`.
2. `complete_technical_evidence()`: `backup_path` to `profile`.
3. `pre_canary_health()`: `destination` to `structured`.

All three now declare names first and assign dependencies on separate commands.
`set -Eeuo pipefail` and `umask 077` remain mandatory. The focused regression
suite scans every logical `local` declaration in the controller and rejects any
future same-command dependency.

## Explicit failure supervision

The controller no longer relies on `trap ERR` for deployment rollback.

- Target fetch and freeze validation run in a strict child shell before the
  mutation boundary. Failure returns an explicit pre-mutation code and performs
  no rollback.
- The mutating phase runner executes in a strict child shell. The parent always
  receives its numeric exit status, including a Bash `nounset` termination.
- The parent keeps the original controller-lock descriptor across the child
  handoff. Rollback reacquires that inherited descriptor without closing and
  reopening it, so there is no pre-mutation unlock/relock race.
- The intentional `SYSTEMD_HANDOFF` unlock/relock cycle also operates on that
  inherited descriptor. The parent therefore retains the reacquired lock after
  the supervised child exits, including when a later health or evidence step
  fails and rollback begins.
- `MUTATION_STARTED` is written only after the deployment lock is acquired and
  immediately before the mutating phase body.
- A non-zero post-boundary status enters `perform_rollback_once()` explicitly.
- `ROLLBACK_STARTED` and `ROLLBACK_COMPLETED` make rollback fail-closed,
  exactly-once, and idempotent. A repeated rollback request verifies source
  state instead of restoring twice.
- Fresh deployment and explicit resume remain separate entrypoints. There is no
  automatic retry and no second Canary attempt.

## Preserved contracts

- Phase contract: `S11_2_R15_8_ORCHESTRATION_V1`, unchanged and ordered.
- Health contract: `S10_1_HEALTH_CHILD_V1`, unchanged.
- Runtime access: `SOURCE_CHATOPS_RUNTIME_INSTALLED_V1`, unchanged.
- Technical evidence: dynamic missing-sample hard cap; 0/5, 3/5, 4/5, and 5/5
  start states are supported.
- Canary activation remains after technical completion, synthetic validation,
  fallback validation, rearm, and evidence-epoch creation.
- Adult media, AVS, payments, external publishing, Controlled Beta, and
  Production remain closed.

## Source-only validation matrix

The R15.10 suite covers:

- exact old Bash fixture: unbound variable and skipped `ERR` trap;
- corrected `pre_canary_health()` path expansion under `set -u`;
- complete same-local dependency scan;
- pre-mutation `nounset`: explicit stop, no rollback;
- post-mutation `nounset`: exactly one rollback;
- repeated rollback request: one restore execution;
- technical plan starts at 0/5, 3/5, 4/5, and 5/5;
- bad provenance, SLO RED, and pre-Canary health RED;
- explicit resume boundaries and unchanged R15.8 phase ordering;
- rollback before and after Canary boundaries without source permission changes.

R15.10 authorizes source readiness only. A later R15.11 must use a fresh
backup and one explicitly authorized deployment attempt; this source release
does not itself authorize runtime execution.
