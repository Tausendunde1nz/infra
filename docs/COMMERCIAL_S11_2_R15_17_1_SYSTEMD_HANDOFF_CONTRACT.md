# Commercial S11.2-R15.17.1 Systemd Handoff Contract

## Scope and recovery baseline

R15.17 was rolled back exactly once from the verified, root-owned predeploy backup
`20260927T113457Z-predeploy`. The restored runtime baseline is Application
`77f9079956a42ee411e17f5697da96f6810ba966` (tree
`370001f8ce0491ddf7709c2cee16d452d6098721`) and Control
`7c634d3b82572e8459d51c69f04dce82c624d766` (tree
`1bfbd80d5478dd24f8f3e47d3654a8b7dea649e4`). S11 is disabled, the rejected
controller timer is not installed, real acquisition remains active with its
original baseline, and all Adult, AVS, payment, publishing, beta, and production
gates remain closed.

## Confirmed R15.17 failure

The rejected controller accepted a changed textual `LastTriggerUSec` together
with historical `Result=success` and `ExecMainStatus=0`. It did not prove that a
service invocation began after the current handoff. The live timer then reached
`SubState=elapsed` with no realtime next event and monotonic `infinity`, but the
old future-run test treated that non-empty value as healthy. Finally, standalone
`verify TARGET_CONTROL BACKUP_PATH` initialized the backup variable but not
`S11_2_TARGET_CONTROL`, so a clean `set -u` environment could abort in the
health-contract reader.

## Current-invocation contract

A natural controller run is accepted only when all of the following evidence is
bound to the current handoff:

- the monotonic timer trigger is later than the deployment-local handoff marker;
- the service `InvocationID` is non-empty and differs from the pre-handoff ID;
- `ExecMainStartTimestampMonotonic` is later than the handoff marker;
- the accepted service start is not earlier than the accepted timer trigger, so
  an independently started invocation cannot be certified as the timer run;
- the accepted invocation has journal evidence;
- the completed service is inactive with `Result=success` and
  `ExecMainStatus=0`;
- the timer is enabled, active, and `SubState=waiting`;
- the timer has a finite next activation that is later than the current
  realtime or monotonic clock.

Historical trigger/result state can only remain waiting until timeout; it can
never become GREEN. A new failed invocation is immediately RED. The accepted
handoff evidence is serialized into the deployment backup and included in the
postdeploy evidence checksum set.

## Finite-future timer contract

One canonical helper is used by dependency timer checks, final target
verification, and Systemd handoff acceptance. It rejects empty values, `n/a`,
`0`, `infinity`, `infinite`, `never`, `-`, and equivalent case variants. A
realtime value must parse to a future epoch. A monotonic value must parse through
the host Systemd timespan parser and exceed current monotonic uptime. The S11
recurring timer additionally requires `SubState=waiting`; `elapsed` is always
RED.

The recurring unit semantics remain unchanged: `OnBootSec=3min`,
`OnUnitActiveSec=5min`, `RandomizedDelaySec=30s`, `AccuracySec=15s`, and
`Persistent=true`.

## Standalone verify contract

`standalone_verify TARGET_CONTROL BACKUP_PATH` initializes both
`S11_2_TARGET_CONTROL` and `S11_2_BACKUP_PATH` before any dependent verifier is
entered. The command remains fail-closed for target and tree drift, Freeze or
installed-artifact mismatch, health-contract mismatch, Technical RED, hard-gate
RED, non-waiting timer state, and missing finite recurrence.

## Regression and simulator coverage

The deterministic A-J matrix covers historical trigger/success, persistent
elapsed/infinity state, trigger without invocation, failed current invocation,
missing recurrence, elapsed recurrence, valid current invocation, empty plus
infinity, `n/a` plus zero, and standalone verify from a scrubbed environment.
Only the valid current invocation and clean standalone verify cases are GREEN.

The full source-only simulator also preserves Technical profile selection,
dynamic missing probes, Runtime Access, Synthetic 8/8, fallback, rearm, fresh
epoch, exactly one Canary start, no automatic retry, and no runtime/database
mutation.

## Freeze and next runtime

The next immutable tag is
`s11-2-r15-17-1-systemd-handoff-contract-freeze-r1`. It retains exactly 29
canonical bindings and changes the simulator binding value to
`CURRENT_INVOCATION_FINITE_FUTURE_V1`. The prior tags remain immutable. Runtime
deployment is permitted only after focused and full tests, secret/PII scan, CI,
same-SHA review, merge-commit integration, post-merge CI, 29/29 Freeze proof,
and a GREEN full source simulator.

At this source stage, no runtime mutation, Canary start, Yoti call, or product
gate opening has occurred.
