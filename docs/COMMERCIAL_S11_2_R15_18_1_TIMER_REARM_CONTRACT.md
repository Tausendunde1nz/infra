# Commercial S11.2-R15.18.1 explicit timer-rearm contract

## Scope and root cause

R15.18.1 is a bounded source correction for the last observed S11.2 handoff
failure. The rejected runtime reached `CANARY_ACTIVE`, but the already enabled
controller timer remained `active/elapsed`, its next monotonic activation was
`infinity`, and PID 1 created no new controller invocation. The prior
`systemctl enable --now` operation was therefore an enablement operation with no
fresh `StartUnit` effect for the loaded timer object. The strict R15.17.1
acceptance correctly timed out with `S11_2_FIRST_NATURAL_CONTROLLER_RUN_TIMEOUT`.

The defect classification is
`SYSTEMD_TIMER_STALE_ACTIVE_ELAPSED_ACTIVATION`. It is not an evidence,
disabled-state, technical-profile, synthetic-journey, or acceptance defect.

## Activation contract

`arm_controller_timer_for_handoff` owns activation only. It verifies the
installed service and timer bytes, reloads systemd, rejects an unexpectedly
running controller service, records the pre-arm state, enables the timer
without `--now`, stops stale loaded timer state, resets failed state, captures
the deployment-local realtime and monotonic handoff marker, and issues exactly
one explicit `systemctl start` for the timer.

The helper never starts the controller service. `RefuseManualStart=yes` remains
mandatory. A failed timer start is immediately hard red and is never retried.
The root-private `timer-arm.json` records pre-arm state, marker, one-arm count,
command result, and post-arm state without secrets.

`wait_controller_natural_run` remains a separate strict acceptance function.
It still requires a trigger and service start after the fresh marker, a new
InvocationID tied to the first PID 1 timer-created start journal entry,
`Result=success`, `ExecMainStatus=0`, timer `active/waiting`, and a finite future
activation. A successful timer-start command alone is never accepted.

## Regression and simulation

The source-only A-L fixture matrix covers a new timer, an already-enabled stale
timer, stale-object clearing, timer-start failure, no current invocation,
failed invocation, missing recurrence, valid handoff, historical invocation,
manual invocation, idempotent enablement, and the one-arm invariant. The exact
R15.18 regression proves that the old model times out from
`LastTriggerUSecMonotonic=0`, `active/elapsed`, no InvocationID and infinite
next activation, while the new model produces a current PID 1 invocation and a
finite recurring schedule.

The full next-runtime simulator preserves the R15.17.2 repeated-deployment
contract: Technical is green, S11 installs disabled, Synthetic is 8/8,
Fallback is green, canonical Rearm adds exactly one history row, a fresh
Evidence Epoch is created, Canary starts once, and standalone verification and
Systemd Handoff are green. The simulator performs no runtime mutation.

## Freeze and boundaries

The replacement annotated tag is
`s11-2-r15-18-1-timer-rearm-contract-freeze-r1`. The canonical freeze remains
exactly 29 ordered bindings. `phase_contract` advances to
`S11_2_R15_18_1_EXPLICIT_TIMER_REARM_V1` and the simulator binding advances to
`EXPLICIT_SINGLE_FRESH_TIMER_ARM_V1`; all old tags remain immutable.

Real AVS, adult media, adult submission, community adult media, external
publishing, payment, controlled beta and adult production remain closed. This
source change does not contact the server, create technical samples, start a
Canary, access Yoti, or mutate product data.
