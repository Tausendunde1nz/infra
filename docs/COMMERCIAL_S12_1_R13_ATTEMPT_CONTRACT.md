# S12.1 R13 — one explicitly authorized follow-up attempt

Source-only change. No runtime approval is implied by this document, commit,
PR, tag, or the isolated test receipts. R12's 254 nonhistorical metadata
assignments and both live Git barriers remain outside this source task.

**Runtime status: NO-GO without separate authorization.** Source release
requires GREEN CI, exact-SHA review without open P1/P2, merge, post-merge CI and
the immutable R13 annotation generated and checked by the canonical freeze
tool. The original materialization blocker remains historical evidence in
`analysis/COMMERCIAL_S12_1_R13_OFFLINE_CHAIN_BLOCKER_2026-10-03.diagnose`.

**Current source release status: pending final CI/review and Git closure.** Exact-head Code Review of
`28d7fe240068c6e728d4a5566403eae44843d4c7` found one remaining P1
(`4173769781`): the prior recursive Git watch was installed after the yielded body's
authorized Git writes and immutable-stage work. It cannot attest to a reverted
foreign mutation before that installation. The real-root regression now also
exercises `REF_UPDATED` and `REPOSITORIES_MATERIALIZED`; it must reject those
writers with both barriers retained and no activation. Prior GREEN CI proves
the covered boundaries, not this missing interval. No test expectation is
relaxed and no finding is dismissed without final-head evidence.

The attributed-writer candidate `d7385c54954ea9801e862bdab58c5d0bc6235171`
passed CI 37137943280: 35 native integrated tests (including both new ref
boundaries, real Git threads, success, interruption, rollback and replay),
20 native R12 kernel tests, and the full 1081-test suite (67 privilege/platform
skips in that non-root suite; native gates ran separately). The subsequent
failure-cleanup and in-flight interruption cases require the same complete
CI gate and fresh exact-SHA review; this earlier GREEN is not substituted.

Exact-head review of `0baec87d7e49d96afb1fe00348be8f8b81160a2a` found two
additional P1 intervals (4174122623/4174122629). Both existing worktrees now
receive retained attributed watches before the serialized body can prepare
fetch inputs or a backup; pending undo receives the same early coverage.
Installation snapshots include ctime and subsequent materializers must check
the retained history before adding their own guards. Foreign pre-materialization
events poison the writer epoch, so an empty materialization journal is not a
recovery exemption. The bootstrap image is the prospectively hashed running
interpreter, opened via `/proc/self/exe` and descriptor-executed. Replacing
`sys.executable` after intent cannot execute replacement code; the initial
ptrace stop also revalidates the bootstrap inode/digest before writer admission.
Native negatives cover both worktrees at body entry/after Application fetch and
an interpreter-path replacement at the pre-spawn seam. Final CI/review remain
required; these corrections have no runtime authority.

Review of `77521969c946de99e93d111e468519c4c25fe9c3` identified three more
P1 gaps (4174243927/4174243936/4174243942): index enumeration preceded the
worktree stream, helper-path discovery executed unbound Git, and read-only
Git/binary/backup helpers bypassed supervision. The stream now precedes all
worktree enumeration; queued opaque events are classified against the captured
inodes and new parent/target edges, including reverted inventory-time writes.
Linux helper paths are fixed and validated without executing Git. Every Git
invocation in the epoch uses the same descriptor-bound, traced executor.
Read-only commands receive no filesystem write grant (apart from the bound
null device and an explicitly journaled backup-output descriptor when needed).
Fetch and immutable-stage writers have finite, separate staging namespaces;
they cannot write the live worktrees. Native negatives cover inventory-time
reversion and replaced Git pathname execution; the integrated suite exercises
the real backup, binary readers, staging and rollback through this executor.
No earlier CI or review is substituted for this candidate's complete gates.

The existing attributed guard trusts only the controller TID; real Git writes
run in subprocesses and may create further processes/metadata directories.
Root ownership, payload equality, arbitrary descendant trust, or rebasing a
fingerprint after those writes is not sufficient provenance. Closing this
interval requires a reviewed, prospective Git-writer/namespace contract that
also covers child-process lifetime, newly created metadata and rollback, with
unbroken transfer from the initial quarantine guard. No such new trust
mechanism was present at that checkpoint. R12 remains canonical; runtime starts are 0.

### Authorized writer continuation (candidate, not released)

The candidate establishes a filesystem-wide FAN_REPORT_TID/DFID_NAME_TARGET
stream while the initial quarantine guard is still live. Opaque file handles
bind the initial namespace and observed parent/target creation transitions;
unclassified events remain retained for graph closure, including events before
a newly created parent's notification. Root and controller descendants receive
no writer exemption. Overflow, unsupported kernel features and ambiguous object
identity fail closed. Unrelated names/content are not retained.

Each selected Git command is durably bound to the attempt/release, exact argv,
metadata inode, boot ID, executable identity and bootstrap digest before spawn. An
isolated bootstrap applies Landlock ABI >=3 write confinement to that metadata
inode (no worktree/backup writes) before its ptrace stop. The sole additional
write sink is an O_PATH-bound root-owned `/dev/null` character device (1:3),
not a general `/dev` grant. Parent-death protection covers the pre-ptrace
bootstrap interval. Fork/clone/exec/exit
stops bind each task's kernel identity and lifetime before continuation; only
the prospectively bound Git frontends, separate upload-pack inode and exact
local-upload-pack shell bridge can execute. Equal bytes do not substitute for
these explicit system-tool path/inode bindings; image metadata/digests remain
fixed across the epoch and its interrupted continuation.
EXITKILL closes live writers on controller death. Queue draining precedes PID
retirement/admission. Kernel-stopped newborns enter the cleanup set before
fallible guard checks, but receive no writer grant before durable task binding.
The private process session is only a bounded failure-cleanup fence, never
writer authority; it also terminates fork/clone tracees whose notifications
have not yet been consumed. This is not an ancestry-only permission grant.
Failure journaling cannot prevent process cleanup: if that write fails, the
durable RUNNING intent continues to deny resumption and all held writers are
terminated/reaped without signalling unrelated controller children.

RUNNING/FAILED journals never authorize resumed writers. QUIET checkpoints bind
the protected metadata fingerprint including root and descendant ctime; resumption
requires a fresh live guard and exact checkpoint agreement, not a claim that
the old monitor survived. Validation precedes new lock metadata changes.
Per-command task histories retain birth/exit evidence; concurrent tasks, total
task births, command count, output and pending events are bounded. Pending undo
shares the epoch with canonical recovery.
Final release guards overlap epoch retirement. Landlock does not restrict all
chmod/chown/xattr operations; attributed filesystem events and pinned executable
identity remain required, not optional substitutes. This candidate still needs
native Linux integration and same-SHA review before any source release.

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
The post-write handoff also watches the complete quarantined Git metadata
tree recursively before its atomic exchange back to `.git`. Those inode
watches and the pre-exchange fingerprint (including descendant ctime) survive
the rename and drain behind the already-installed release guards. Deep refs
are not first baselined after exposure. Native negatives change and restore a
branch-ref mode from another root process both immediately after exchange and
during the later metadata-release phase; both retain the Git barriers and
reject recovery/replay without activation.

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
