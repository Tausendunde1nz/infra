# R14 — S11/S12 release and completion compatibility (source only)

## Delta and prospective bindings

R13 installs Application `93555d8a141caf8ace33522f9340d30bfc47d2bb`
(tree `1e8a644115127818f394b6f9d24f31826e04ecba`) into the shared
checkout; the installed S11 controller requires
`db87896697d56b24f192fc1cd0324b6fe46d734b`
(tree `b915a04e19eef8a244c300b16577a44cea89e2ab`). These are distinct
release contracts, not evidence of an unauthorized writer. Quarantined Git
metadata additionally makes the legacy reader report a failed read as drift.

R14 retains both exact Application pairs, with different installed manifests:

| Phase | Application | S11 installed binding |
| --- | --- | --- |
| Historical recovery / rollback | `db878966…` | Original S11 freeze and V1 manifest, exact historical artifact hashes |
| R14 installed / accepted | `93555d8a…` | Reviewed R14 controller, V2 manifest bound to R14 Control commit/tree and immutable freeze |

This is not adoption of an arbitrary observed HEAD. The prospective S12
Application release already contains the reviewed sandbox implementation;
the S11 runtime packages and its installed gate, orchestration, unit, timer,
experience contract and copy remain pinned. The two existing provider-file
changes concern sandbox notification/session identifiers and per-operation
guards. Real AVS remains closed. Application identities, all installed S11
artifacts, metadata and the loaded PID-1 unit are checked independently of
previous health state. An unknown pair, dirty tree, unreadable object,
artifact mismatch, hardlink, unsafe owner/mode or ACL remains RED.

## Transition, recovery and natural completion

The existing S11 advisory lock excludes its observer from partial replacement
of controller/manifest and the protected Git transition. No S11 service start,
timer change, Canary promotion or status clearing is added. Both replacement
files are backed up before mutation. An interrupted pair is not a new runtime
state: only canonical rollback/recovery can restore the backed-up pair.
Historical V8 backups and R12 evidence remain unchanged; R14 V9 backups carry
the mandatory additional S11 contract. Missing/downgraded bindings remain RED.
Historical recovery still does not require S11
GREEN while the Git barriers prevent reading it.

After target installation, before S12 activation, and again before successful
completion, wait for a new natural S11 invocation. Verify boot ID, distinct
InvocationID, timer trigger/start/exit monotonic ordering after the completed
release transition, successful exit, invocation-scoped journal evidence, and
the unchanged installed release binding. The pinned unit refuses manual
starts and must be loaded without drop-ins or pending daemon reload. Timeout,
reboot, stale success, failed run and incompatible release remain RED.
Rollback restores the original controller/manifest and Application pair,
then requires its own new natural S11 proof. Repository rollback evidence is
distinct from current S11 health evidence; recovery never reactivates S12.

Runtime health is not promotion readiness: the unchanged S11 gate reports
`ok=false` for an already terminal, disabled Canary. Accept that exact terminal
envelope only alongside the successful new pinned observer invocation, which
independently checks current integrity and hard gates before exiting zero.
A fresh RED transition, failed hard gate, malformed envelope or stale run is
not accepted. No Canary state is changed by this distinction.

The fixed `r13-followup-1` slot and protected explicit human authorization are
unchanged. R14 neither consumes nor resets that slot in source work. The new
freeze changes release provenance only; it does not itself authorize runtime.

## Validation and remaining gate

Regression evidence is pending until the complete Linux suite, same-SHA
review, merge and post-merge CI complete. Tests retain native Git/ACL/writer
protections and exercise S11 read/error classification, installed bindings,
natural-run freshness, interrupted pair restoration and the integrated
R12/recovery/follow-up success/rollback/replay chain.

Historical S11 artifact assertions now read their last verified canonical
Control snapshot `4652b172…`. Their old hashes are not rewritten to claim that
the new R14 controller was part of the original S11 freeze. The new controller
and compatibility tests are separately bound into the R14 immutable freeze.

Runtime remains NO-GO pending a separately authorized, verified R14 execution:
fresh canonical recovery proof, exact immutable release, backup, compatible
source/runtime state, mandatory kernel protection, writer exclusion and
protected slot authorization. No server mutation or runtime retry is part
of this source task.
