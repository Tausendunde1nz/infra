# Commercial S11.2-R15.8 deployment orchestration

Status: source-only contract. No runtime deployment, live probe, sudo action, or
Canary activation was performed while producing this release.

## Root cause

R15.7 stopped before sudo because the canonical controller did not implement
the reviewed runtime order. It generated five synthetic timing fixtures,
started the Canary, and only then persisted five technical samples. It also did
not install and verify the R15.6 S10 health-child artifacts before depending on
their structured output. This could over-probe a 4/5 state and could extend an
evidence epoch with deployment-generated samples.

## Ordered contract

The runtime entrypoint now commits these phases, in order, to the root-private
`phase-state.json` inside the fresh deployment backup:

1. `PRECHECK`
2. `BACKUP_COMPLETE`
3. `HEALTH_CONTRACT_INSTALLED`
4. `TECHNICAL_EVIDENCE_COMPLETE`
5. `S11_INSTALLED_DISABLED`
6. `SYNTHETIC_VALIDATION_GREEN`
7. `FALLBACK_GREEN`
8. `CANARY_REARMED`
9. `EVIDENCE_EPOCH_SET`
10. `CANARY_ACTIVE`
11. `SYSTEMD_HANDOFF`

A phase is written only after its operation and verification are complete. The
ledger binds `release_id`, `run_id`, `phase`, `completed_at`, and
`S11_2_R15_8_ORCHESTRATION_V1`. Its ordered prefix is validated on every read.

`deploy` requires a new absent backup path. `resume` is a separate command for
a separately authorized invocation. It validates the same backup, release/run
binding, freeze, and completed prefix before selecting the next phase. It does
not retry automatically and it never reruns a completed phase.

If an abrupt interruption occurs after the epoch or Canary transition but
before the corresponding phase commit, resume recognizes the already valid
database state and commits the phase without repeating the transition. Any
rollback writes root-private started/completed markers; a rolled-back run is
not resumable and requires a fresh, separately authorized backup/run.

## R15.6 health contract

Before technical evidence evaluation, the controller installs from the frozen
Control commit and verifies path, SHA-256, owner, group, mode, and contract
version for:

- `tu1nz_adult_public_s10_health_child_contract.py`
- `tu1nz_adult_public_s10_1_health.py`
- `tu1nz_adult_public_s10_2d_health_gate.py`
- `tu1nz_adult_public_s11_2_health_preflight.py`
- `tu1nz_adult_public_s11_2_recovery_diagnostic.py`

The generated runtime manifest is root-owned mode `0644`; scripts are
root-owned mode `0755`. The structured preflight preserves outer code, child
code, component, classification, next action, and exit class. Missing or
unknown child codes stop fail-closed. No transient condition triggers an
automatic retry. The controller captures a journal cursor before starting the
S10 health unit and evaluates only output after that cursor, so retained GREEN
records cannot satisfy the new pre-Canary invocation.

## Technical evidence completion

The canonical technical profile is run-bound and rolling-24-hour bound:

- source: `DIRECT`
- evidence class: `INTERNAL_TEST`
- sample type: `DIRECT_BOT_RESPONSE`
- interaction path: `INTERNAL_ACCEPTANCE`
- release: current runtime target release
- run: current `technical_evidence_run_id`

The required floor is read from the deployed technical evaluation contract.
At phase start the controller computes:

`missing_samples = max(0, required_floor - current_valid_samples)`

That initial missing count is the hard cap for the whole phase. Each bounded
systemd probe must complete successfully and increase the valid count by
exactly one. The controller then rereads provenance, count, and SLO. It stops
immediately when GREEN; invalid/REAL/UNKNOWN provenance, RED at the floor, or
continued insufficiency after the cap stops the deployment without Canary.

There is no fixture insertion path and Canary activation contains no probe
logic.

## Disabled install, epoch, and activation

S11 runtime artifacts and migrations are installed only after technical GREEN.
Migration 0035 separates the immutable evidence-epoch transition from Canary
activation:

- `SET_EVIDENCE_EPOCH` requires disabled/not-started state and leaves
  `enabled=false`, `live_start=null`, and `canary_live_start=null`.
- `CANCEL_EVIDENCE_EPOCH` is the sole rollback transition for that armed but
  still disabled/not-started state. It clears only the epoch binding and never
  deletes latency or product evidence.
- `START_CANARY` requires the existing epoch and does not generate technical
  evidence.

Immediately before the single `START_CANARY` transition, the controller again
requires R15.6 health, technical GREEN, disabled install, all eight synthetic
journeys, feature-off fallback, rearm, the immutable epoch, product boundaries,
public health, poller/lease, rotation, services, and timers.

## Access and rollback

The R15.4 split remains unchanged: source checks run as `chatops`; installed
runtime copies are root-owned and execute with the canonical Application venv.
The systemd controller retains only the justified supplementary `chatops`
group. Source permissions and sudoers are unchanged. Phase separation adds no
manual privilege checkpoint and remains compatible with the single-sudo
operator flow.

The fresh backup additionally captures the five R15.6 artifacts, its manifest,
and the orchestration helper. Rollback restores exact bytes, modes, units,
runtime manifests, and presence/absence. A pre-Canary error after epoch arming
first uses `CANCEL_EVIDENCE_EPOCH`; a post-Canary error first uses the canonical
`CANARY_RED` fallback. Neither path mutates retained latency or product
evidence.

## Source-only acceptance matrix

The deterministic simulator proves:

- 4/5 valid → exactly one probe → one Canary start
- 5/5 valid → zero probes → one Canary start
- 3/5 valid → at most two probes → one Canary start
- invalid provenance → stop, zero Canary starts
- technical SLO RED → stop, zero Canary starts
- R15.6 health RED → stop, zero Canary starts
- resume after each reviewed safe boundary → no duplicate side effect
- rollback before/after Canary → exact restore, canonical fallback when needed

The next runtime run remains separately authorized. R15.8 itself does not
change the live technical sample count, acquisition baseline, S11 state, or any
closed product boundary.
