# S12.1 R13 — one explicitly authorized follow-up attempt

Source-only change. No runtime approval is implied by this document, commit,
PR, tag, or the isolated test receipts. R12's 254 nonhistorical metadata
assignments and both live Git barriers remain outside this source task.

**Runtime status: NO-GO without separate authorization.** Source release
requires GREEN CI, exact-SHA review without open P1/P2, merge, post-merge CI and
the immutable R13 annotation generated and checked by the canonical freeze
tool. The original materialization blocker remains historical evidence in
`analysis/COMMERCIAL_S12_1_R13_OFFLINE_CHAIN_BLOCKER_2026-10-03.diagnose`.

Continuation under expanded source-only authority: the candidate now allocates
Git blobs in a same-filesystem, root-private per-attempt transaction directory.
Finite path/policy intent precedes allocation; device/inode/kernel-birth and
metadata/content bindings precede publication. Publication uses durable move
intents and `renameat2(RENAME_NOREPLACE)`. Existing objects are retained for
reversal, not recreated from content. New maintenance policy is owner/group
from the protected repository record, files 0660 (executables 0770), directories
2770, no inherited default ACL; objects enter the worktree already write-fenced.
Continuously held permission, attributed mutation and retained-handle guards
cover allocation, binding and publication. Git only reads blobs and updates its
quarantined index/refs. Parent inode/birth/metadata bindings prevent retargeting
after process loss. The legacy root-only successor fallback is disabled for
this attempt. Symlinks are bound at their prospectively declared maintenance
UID; their fenced parents, not ineffective symlink mode bits, enforce exclusion.

Native CI 37125011050 (fa02185) passed the full suite, including complete success,
activation failure/rollback, twelve actual process-loss seams, a foreign root
mutation/reversion, same-content inode substitution across the phase handoff,
and interrupted-state inode/ACL/parent/policy negatives. Final CI additionally
tests loss after allocation and metadata initialization, before inode binding:
the unbound private object is quarantined in the consumed attempt, never
adopted, published or used for another attempt. The original repository objects
are restored; historical origin is not asserted for unbound private artifacts.
Before releasing the source worktrees the contract revalidates both published
successors and retained predecessors, ensuring the declared reversal is still
available. A successful source CI does not grant runtime authority.

The interrupted-materialization recovery prefix repeats canonical admission
before any object move: both Git barriers, no successful attempt result,
inactive runtime, no control-sync/Git process or retained Git/worktree writer.
A violation poisons the transaction and retains its guards; a later disappearance
of the writer is not retroactive authority. Linux negatives include a real
separate process holding the quarantined Git HEAD open for writing.
The fixed private staging namespace and both repositories must share a
filesystem for atomic no-replace moves. Follow-up admission checks this before
claim consumption; a real root-filesystem/tmpfs negative proves rejection
without a claim or deployment. Cross-filesystem copy is not a fallback.

Same-SHA review identified a P1 watch-lifetime gap after each materializer
returned. Allocation and successor guards now remain owned by the enclosing
serialized operation through both repositories, immutable staging and the
complete post-yield audit. A reverted foreign-root mutation therefore cannot
disappear between snapshots. Linux negatives exercise unchanged and new inodes
at the cross-repository handoff and after the final snapshot audit. Poisoning
retains the latest durable journal phase even when a guard outlives rollback.
The watches remain alive during Git-barrier exchange and overlap the release
permission/event guard before draining. PID-attributed mutation watches also
cover the declared release metadata transitions and retained rollback objects;
failed handoff re-seals and reinstalls both Git barriers. Native negatives
include reverted mutations after barrier exchange and during metadata release.
The interrupted undo prefix shares this same guard owner with canonical
recovery; a separate Linux negative covers reverted root mutation between
those phases. Neither a normal return nor snapshot equality ends supervision.
Successful transfer retires only the in-memory watch callbacks, allowing the
canonical second finalization phase to establish a fresh watch set. A failed
transfer poisons the owner; no closed descriptor is treated as a live guard.

## Delta and trust boundary

The historical `state/deployment-attempted.json` remains byte-for-byte intact.
The original deploy entry point continues to reject that marker. R13 adds one
finite slot, `r13-followup-1`, reached only through the controller CLI with
`--authorization` and `--authorization-sha256`. There is no arbitrary attempt
identifier, reset, implicit retry, or deploy resume operation. Manifest
`second_deployment_allowed=false` continues to prohibit repeating an attempt;
the separate follow-up admission contract is not a reset of attempt 1.

The operator must provision a fresh, explicitly human-authorized receipt at
`/etc/tu1nz/adult-commercial-s12-1-private/authorizations/r13-followup-1.json`,
root:root 0600, single-link regular file under a root-controlled directory
chain. The invocation pins its independently verified SHA-256. An existing
credential, a changed tag, or an unchanged source SHA is not authorization.
The controller validates protected provisioning, not a cryptographic human
signature: the operator must verify the recorded human authorization before
provisioning it. No usable receipt is generated or committed by this task.

Receipt schema `TU1NZ_S12_1_FOLLOWUP_AUTHORIZATION_V1` has exactly these fields:

- `slot`: `r13-followup-1`.
- `human_authorization_sha256`: nonzero SHA-256 of the explicit runtime grant.
- `acknowledgment`: `AUTHORIZE_ONE_SYNTHETIC_SANDBOX_DEPLOYMENT_AFTER_RECOVERY`.
- `authorized_at`, `expires_at`: integer Unix seconds; at most 24 hours apart.
  Admission must be within that interval. Safe recovery remains possible after
  expiry; it never activates the runtime.
- `release`: exact `tag`, `tag_object`, `control_commit`, `control_tree`,
  `application_commit`, `application_tree`, `controller_sha256`,
  `application_bundle_sha256`, `control_bundle_sha256`.
- `parent_proof`: hashes of `attempt`, `index`, `rollback`, `progress`,
  `recovery`, `r12_original`, `r12_ledger` at fixed controller-derived paths.

The historical attempt/index/original-journal hashes are also pinned in source
to the audited R12 inputs. The remaining proof hashes can only be supplied
after actual R12 metadata sealing and successful canonical recovery.
Admission revalidates backup payloads, real Git/reflog/worktree state,
ownership/rights, writer absence, S12 inactivity and public/S11 prerequisites.
A stale success receipt alone cannot admit a new attempt. Historical missing
metadata evidence remains missing: the R12 ledger must explicitly declare
`historical_continuity=false`. An ambiguous prior deployment result is RED.

## Exactly once, association and interruption

Under the existing exclusive repository-parent flock, the controller durably
creates `state/r13-followup-1.consumed.json` with O_EXCL, file fsync and parent
fsync **before** deployment. It contains the full attempt binding and parent
classification. A complete or partial claim permanently consumes this slot;
neither failure nor changing the grant/tag permits another activation.

New state is confined to `state/attempts/r13-followup-1`; backups are confined
to `backups/r13-followup-1`. The installed unit's state and write allowance use
that exact namespace. Attempt marker, backup index, result and recovery result
carry the release/authorization/parent binding; rollback data reside only in
that attempt's bound backup. Shared unit/nginx/release staging is reused only
after verified parent closure and under the exclusive controller lock.

`recover` with the same protected grant targets only the new namespace and
never calls deploy. Legacy recovery is rejected after the claim exists unless
the new target is explicit. A crash immediately after claim consumption and
before namespace/backup creation can close as
`S12_1_FOLLOWUP_CONSUMED_WITHOUT_DEPLOYMENT` only after revalidating the parent.
If interruption leaves an empty protected attempt namespace before any barrier
or backup, recovery revalidates the unchanged closed parent and public state.
It writes only the fixed consumed-slot parent receipt
`state/r13-followup-1.closed-without-deployment.json`. The empty namespace is
retained without an origin assertion, not adopted or written into. Closure is
idempotent even across process loss before/after its atomic write; the slot
stays consumed. Nonempty/unsafe leftovers or any backup exclude this early
closure. Unparseable claims, concurrent writers and unclear states remain
fail-closed; no leftover is deleted or retroactively attributed.

## Integrated offline acceptance

`tests/test_s12_1_attempt_chain.py` runs as root on native Linux with real
fanotify/handle guards. It uses isolated Git repositories, original journal,
backup, R12 metadata reconciliation, canonical recovery, protected receipt,
input bundles, new backup, repository synchronization and immutable staging.
The intended success/failure scenarios assert at most one activation, exact
historical-marker preservation, per-attempt evidence and blocked replay.

Only external systemd/nginx/public-HTTP/provider boundaries are simulated.
The isolated interpreter and release commits are fixture-specific: their
real byte hashes, Git identities and immutable metadata are checked; dependency
attestation and the production artifact verifier are substituted for those
fixture identities. Production all-artifact freeze verification remains a
separate mandatory release gate. Offline evidence is not provider acceptance.

Admission negatives cover malformed authority, release/parent mismatch,
expired/future/overlong grants, wrong digest/permissions, hardlinks, partial
claims, unknown namespaces, parent rejection and interruption after claim.
Existing R12 negative/interruption regressions remain mandatory and unchanged
in safety meaning. The complete integrated gate must pass before review/merge.

## Other proven continuation defects fixed

Canonical recovery previously treated its own quarantined Git directory as
foreign untracked content and restored only the controller's current freeze
ref. Recovery now uses the existing quarantine-aware identity selector and
the authenticated backup's bounded historical freeze ref. Arbitrary refs and
foreign untracked changes remain rejected. Neither fix changes the original
backup or claims historical metadata continuity.

## Remaining runtime prerequisites

Separate explicit runtime approval; immutable R13 artifact verification;
same-filesystem private staging preflight;
unchanged audited server admission; verified backup/abort paths; successful
R12 metadata sealing retaining both barriers; separate canonical recovery
releasing them; fresh protected grant and matching bundles; all public/S11,
repository, credential and writer gates GREEN. Then at most one synthetic
Sandbox attempt, followed by controlled inactivity. Real identities, AVS,
Adult media/uploads, external publishing, payments, beta and production remain
closed. No runtime activity is authorized by the source-only release.
