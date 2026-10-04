# R15 — independent containment of the terminal R14 partial failure

Source-only. No live application, recovery, unlock, process action or deployment
is authorized by this change. R14's original error/PID is unknown; current CWD
handles are not historical writer evidence. The preserved diagnostic digest and
historical journal hashes are bound in the evidence delta and new freeze.

## Decision: contain, do not roll back into writable admission metadata

The proved state has 235 completed bindings, one pending chmod with identical
pre/post metadata (the ACL step already established the final mode), and 18
unstarted bindings. Thus 236 paths match the locked target, 18 the old admission.
Restoring admission would regrant write rights; it is not the chosen compensation.
`contain-aborted --metadata-contract ...` is a **separate** one-shot closure,
never a resumed reconciliation or successful R12 application. It authenticates
the exact immutable ABORTED ledger and receipt, original journal, backup, Git
identities and R12 contract. The original ABORTED inputs are never rewritten.

All 254 paths must equal their acknowledged state or the single recorded pending
post-state, including descriptor/path identity, birth time, contents and ACLs.
The prospective finite plan uses only the already justified R12 restrictive
target: root-owned, write bits denied, no new release permission. Already equal
states are not rewritten; an indistinguishable pending noop is not replayed.
The 18 residual paths are monotonically contained under the unchanged full-index
Git, open-permission, inotify, attribute and retained-handle protection stack.
Existing metadata/default-ACL transitions are used, not ad-hoc chmod/chown.

## Durable one-shot closure and interruptions

Before the first compensating syscall, an O_EXCL/fsynced immutable containment
plan binds the exact historical inputs and every allowed transition. Every
actual syscall has a durable progress intent. A successful result requires exact
final states, unchanged historical inputs and Git guards, watch finalization and
successful cleanup. Only then is a separate `CLOSED_CONTAINED` receipt published.
It explicitly says `metadata_rolled_back=false`, historical phase `ABORTED`, and
no recovery/deployment authority. V3 is retained; no V4/SEALED journal is published.

An interrupted or failed closure is **not automatically resumable**. The claim
remains consumed even if the failure happened before any compensating syscall.
Repeated calls with no final receipt perform only validation and return
`INCOMPLETE_NO_RETRY`: they never grant a new observation epoch, replay an intent,
or infer uninterrupted writer exclusion. A separately reviewed disposition would
be necessary. This is the deliberately smallest fail-closed interruption policy.
After success a repeat revalidates the same protected target and scope fingerprint
and returns zero mutations, never cached runtime GREEN. Any drift remains RED.
Reconciliation, recovery and deployment explicitly reject a containment claim.

## Failure provenance

Primary, abort-finalization and each cleanup failure are captured separately with
phase, code/type/errno and function/line frames; no messages, locals or arguments.
Captured guard process/thread start identities and boot ID describe the observer's
actual evidence, not inferred historical causality or write permission. Evidence
files are append-only, root-private O_EXCL objects. Evidence-write failures are
retained in the returned envelope and cannot skip remaining cleanup. The primary
exception remains primary even when abort or cleanup also fails. No missing R14
exception is invented. A cleanup-only failure cannot publish successful closure.

## Acceptance

Native Linux CI exercises the real 254-path mixed fixture, unchanged kernel
guards, content/metadata/identity drift, held writers, reverted foreign attribute
events, durable intent/syscall/claim/receipt interruptions and repeated closure.
No disabled guard is accepted as security evidence. Existing R12, integrated
attempt-chain and S11/S12 gates remain mandatory, followed by Same-SHA review,
merge/post-merge CI and a new immutable freeze. Live permission remains separate.
The target S11 manifest/controller binding advances together to the exact R15
freeze (not a wildcard or an additional accepted live version). The integrated
real-S11 check rejects a stale R14 manifest; the legacy rollback pair is unchanged.
