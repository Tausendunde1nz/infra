# Commercial S12.1 Yoti Sandbox runtime Control contract

## Release and activation boundary

S12.1 is a bounded, one-attempt runtime acceptance release.  The immutable
annotated tag `s12-yoti-sandbox-runtime-freeze-r9` binds the exact Application
merge commit and tree, the exact Control merge commit and tree, every runtime
artifact, the hard-gate values and the exactly-once rollback contract.  The
older `s12-yoti-sandbox-source-freeze-r1` remains immutable and is not an
activation release.

The immutable pre-deployment r1 freeze remains preserved. Its read-only server
preflight rejected the healthy activation-relative S11 controller timer because
systemd correctly populated `NextElapseUSecMonotonic` rather than
`NextElapseUSecRealtime`. No r1 deployment attempt or server mutation occurred.
The r2 contract accepts a finite future elapse in either systemd clock domain,
while still requiring the timer to be enabled, active and waiting.

The immutable pre-deployment r2 freeze is also preserved. Its complete
read-only preflight exposed that the canonical Control checkout intentionally
predates the release sync and therefore cannot supply the reviewed nginx
baseline file before backup. No r2 deployment attempt or server mutation
occurred. The r3 controller instead compares the installed nginx site against a
reviewed SHA-256 constant. That constant is source-validated and the baseline
file is independently bound in the annotated freeze.

The immutable r3 freeze is preserved as the first controller that reached the
live mutation boundary. Its sole invocation stopped before backup and before
the durable deployment-attempt marker with `S12_1_RECOVERY_GIT_ACTIVE_RED`.
The cause was a recovery scanner that received whole Worktree roots although
the exclusion resource was Git metadata. Healthy S7/S8/S10 processes retaining
their canonical WorkingDirectory were consequently misclassified. The r4
controller protects `.git` and `.git.s12-1-recovery` handles, while namespace
locks preserve every previously available read/traverse class and remove only
write authority. No service-name allowlist exists.

The immutable r5 freeze is preserved as the first pristine-V1 direct-release
controller. Its sole recovery invocation stopped before journal release with
`S12_1_REPOSITORY_PARENT_RED`: the canonical shared repository parent contains
intentional POSIX access/default ACLs with named runtime principals. The r6
controller accepts only structurally complete POSIX ACLs, binds their exact
bytes in the continuous release fingerprints and still rejects every unknown
xattr, malformed ACL, duplicate principal or unmasked named entry.

The immutable r6 freeze is preserved as the first structurally-valid-ACL
controller. Its sole recovery invocation stopped before journal release with
`S12_1_WORKTREE_LAYOUT_RED`: pristine legacy repositories contain pre-existing
root-owned generated and Git entries. The r7 controller reuses the bounded
journal-transition owner set only for pristine V1 orphan release: recorded
owner/group, root with the recorded group, or root/root. Exact repository-root
metadata, regular-file single-link checks, Git/index identity, xattr checks and
continuous writer guards remain mandatory.

The immutable r7 freeze is preserved as the first controller to release that
legacy orphan and reach the fresh Worktree write-barrier capture. Its sole
deployment invocation stopped before backup, the durable attempt marker and
repository sync with `S12_1_RECOVERY_WORKTREE_BARRIER_RED`: 30 tracked Control
files intentionally use owner-only `0600`/`0700`, so a root ownership handoff
would have removed the recorded owner's read or traversal access. The r8
controller preserves that access with an exact POSIX ACL entry for the
recorded numeric UID. On ACL-free paths this is one generated temporary entry;
an existing canonical ACL is preserved only when it already contains the
named UID with sufficient effective read/execute access under a mask that is
not widened. Without that named UID, every group-object, named-group and other
class that could be selected must independently preserve the former owner's
rights; group entries are never accepted as a substitute authorization proof.
For an ACL-free path, both the retained-group and nonmember permission
classes are treated as possible after handoff; if either lacks a prior owner
read/traversal right, the exact named-UID ACL is mandatory. This avoids using
the retained GID as a capability and has no dependency on complete NSS account
or group enumeration. Every write bit remains removed.
The normalized source xattr fingerprint remains bound; during the barrier only
the byte-exact generated owner ACL may be omitted from that fingerprint. A
generated ACL is installed and verified before the root ownership handoff,
then retained until the exact owner has been restored during teardown; a bound
source ACL is retained throughout. The recovery lock and failure-path reseal
recognize both bounded reverse-transition states—owner restored while the
generated ACL remains, and owner restored after that ACL is removed but before
the original mode is restored—and re-establish the root-owned barrier before
any guard is released. A root-owned generated mode whose owner ACL is already
absent is rejected as drift because teardown always restores the recorded owner
before removing that ACL.
New tracked inodes created by the completed root Git operation are checked for
file capabilities, durably journaled with their exact source ACL/xattrs and
then sealed through the same write barrier before release validation.
The controller also
rejects setuid and setgid regular files and all unrelated ownership, mode, ACL
or xattr drift, preserves the original journal mode across same-inode release
refresh, and restores the exact original mode and ownership during teardown or
rollback.

The immutable r8 freeze is preserved as the first controller to capture the
complete tracked-path write barrier successfully. Its sole deployment
invocation stopped before backup and before repository mutation with
`S12_1_REPOSITORY_BARRIER_JOURNAL_RED`: the 879-entry root-private journal was
236,582 bytes, while the generic private-JSON reader still enforced the older
128 KiB ceiling. The r9 controller gives only the authenticated barrier
journal a 1 MiB ceiling, retains the 128 KiB ceiling for every other private
JSON artifact, and rejects an oversized barrier payload before publishing it
atomically. Journal parsing, exact schema validation, ownership, mode and
single-link checks remain unchanged.

The deployment controller refuses floating refs, dirty repositories, an
unannotated tag, a second deployment marker or a release/hash mismatch.  It
creates and verifies a fresh dedicated backup before the first canonical
repository, systemd, nginx or runtime-state mutation.  Any failure after that
boundary executes the canonical rollback exactly once and stops; there is no
hotfix or second runtime attempt.

After synchronizing both canonical repositories, the controller installs the
atomic Git recovery barriers and clones both reviewed commits into a fresh
root-private release tree. It also copies the complete canonical virtual
environment while comparing source-before, source-after and materialized-tree
SHA-256 values. The interpreter and complete venv SHA-256 values are first
recorded as reviewed manifest/freeze bindings; a canonical venv that differs
before staging is therefore RED rather than allowed to self-attest. File
symlinks, including the Python launcher, are dereferenced;
only relative directory symlinks that resolve inside the venv (for example
`lib64 -> lib`) are preserved, while escaping/absolute links and special files
are rejected. The staged interpreter is a
root-owned regular executable, the exact locked dependency versions are
verified from the staged metadata, and an immutable environment record binds
the interpreter and complete venv hashes. The controller verifies that record
again immediately before the sole systemd start and retains the venv hash in
the bounded deployment result.

The controller verifies the exact Application commit/tree and the exact
annotated Control freeze target, atomically isolates the complete source and
runtime tree under the root-only parent, removes every write bit recursively
and durably flushes it before use. Both `ExecStart` and `ExecStartPost` execute
the staged Python binary; the systemd acceptance imports Application code and
performs every Git release check only against this immutable private tree. A
later `chatops` sync, Git writer or canonical-venv writer can therefore neither
replace the interpreter/dependencies/source nor alter the verified release
identity during the credential-bearing acceptance.

## Credential and provider boundary

The approved credential files remain root-owned `0600` regular single-link
files.  Only metadata is retained.  systemd supplies the values under fixed
credential names with `LoadCredential`; no value enters an environment
variable, command argument, Git artifact, general backup, journal or evidence.

The runtime can represent only Yoti Age Verification Sandbox:

```text
environment=SANDBOX
provider=YOTI
method=AGE_ESTIMATION
threshold=18
hosts=age.yoti.com,auth.api.yoti.com
```

Production, unknown environments, plaintext HTTP, arbitrary endpoint
selection and redirects to unknown hosts are hard failures.

## Callback and decision authority

During the short acceptance window, the public site temporarily exposes only
`POST /avs/sandbox/callback` through nginx to loopback port 18126 with a 16 KiB
body limit and short proxy timeouts.  The Application verifies the published
Sandbox notification signature and the exact armed session/reference.  The
callback is only a trigger; it never decides the AVS result.  Only an
authenticated fetch for the exact known Sandbox session can produce
`AVS_VERIFIED_SANDBOX`.

The original nginx site is restored and validated immediately after the
one-shot service completes.  The callback then becomes inactive.

## Acceptance, privacy and final posture

Acceptance covers authentication, official synthetic adult/pass and
under-threshold scenarios, signed notification, authenticated result fetch,
identical and conflicting replay, expiry, new-session retry, unknown-session
rejection, same-reference substitution, registered-scenario mutation,
Production crossover rejection and the complete synthetic WMS
journey.  No real person, identity, document, selfie, biometric, adult media,
payment or external Adult publication is used.

Retained evidence contains safe codes, booleans and normalized states only.
No exact age, identity data, raw provider payload, SDK ID, private key or access
token is retained.  On success, the reviewed unit remains static/disabled,
the credential-bearing systemd transaction executes safe-stop as
`ExecStartPost`, the activation contract is removed only after its controlled
inactive evidence has been validated, S11 remains untouched and all
real/Adult/Publishing/Payment/Beta/Production gates remain false.
The freeze validator and executable simulator both require HTTPS-only transport
and reject redirects to any host outside the exact Sandbox allowlist.
They also bind the callback to signed Yoti Sandbox RSA-PSS/SHA-256 triggers,
`POST`, loopback `127.0.0.1:18126`, the exact HTTPS public URL and a 16 KiB
body limit.
Source validation and simulation require the exact eight-key hard-gate set;
an empty, partial or arbitrarily renamed all-false map is RED rather than
vacuously closed.
The complete final posture is equally exact: runtime controlled inactive,
callback inactive and Yoti Sandbox disabled for real users.
Accepted mock-provider decisions live in private simulator state; mutations of
the public session result field cannot become authoritative or replay GREEN.
Every manifest object is exact, including decision, credentials, health,
systemd, network, Sandbox policy, rollback and final posture. Unknown nested
fields, weakened privacy flags, arbitrary unit names and value-bearing
credential fields are RED. Equality is recursively type-aware: JSON `0` cannot
substitute for `false`, `1` cannot substitute for `true`, and a floating-point
number cannot substitute for an integer schema field.

## Backup and rollback

The root-private backup and state live below
`/etc/tu1nz/adult-commercial-s12-1-private`, whose existing ancestry is
root-owned and has no group/world write permission. Both are therefore outside
the deliberately shared-writable canonical repository, runtime and log
ancestries. The backup contains Git bundles, exact pre-state commits/trees,
the exact attached-branch or detached-HEAD posture, the exact prior
`ORIG_HEAD` value or its absence, a byte- and mode-bound snapshot of the
complete reflog tree or its absence, domain-separated SHA-256 hashes of the
tracked paths and their ancestors, the prior
unit/runtime-config/nginx bytes and modes, credential metadata only,
SHA-256 values and a restore index.  Rollback requires a successful systemd
stop and verifies `inactive/dead` before it restores the pre-state files and
branches, reloads systemd/nginx, preserves credentials and writes one
privacy-safe rollback marker.  It never reports rollback success while the
runtime may still be active. Rollback also removes the fixed root-private
release and staging trees and fsyncs their parent before completion. A second
rollback invocation or a second
deployment marker is rejected.

Before backup, the controller requires every tracked index entry in both
canonical repositories to be a normal cached `H` entry. Assume-unchanged,
skip-worktree, unresolved and other noncanonical index states are rejected;
the same check is repeated by backup race validation. The sealed offline
release trees are also compared against every ignored local worktree path
using bounded NUL-delimited Git output. Any exact or ancestor/descendant
collision is rejected before backup and checked again immediately before the
durable attempt marker. File names and contents are never emitted or retained.
Consequently checkout cannot overwrite unbacked ignored state, and rollback
never needs to reconstruct unrecorded index flags.

The repository barrier additionally requires homogeneous owner/group metadata
within each ownership domain: all non-Git worktree entries must match the
recorded checkout root, and the complete Git tree must match the recorded Git
root. This is checked before any barrier mutation and repeated after the shared
repository parent is locked. Barrier teardown traverses the worktree and Git
domains separately and invokes `chown` only for entries whose owner actually
differs. An ignored root-protected file can therefore never be silently granted
to `chatops`, while unchanged ownership-sensitive inode metadata is untouched.

Before rollback changes either repository, the controller compares every
current ignored path and its ancestors with the authenticated hashed path sets
from the pre-state backup. Any exact or ancestor/descendant collision fails
closed while both repository barriers remain installed. The hash-only V8
backup extension neither retains nor emits repository path names or local
content, and a later ignored writer can never be silently overwritten by the
forced restore checkout.

Initial deployment still accepts only the recorded ownership posture.
Before journaling or changing tracked Worktree ownership, the controller
requires either an ACL-free mode contract or a canonical ACL containing an
explicit named-user entry for the journaled UID. Existing ACL masks may only be
tightened; group entries do not prove access. Where an ACL-free owner's read or
traversal would otherwise disappear, the controller derives one byte-exact
named-user POSIX ACL from the journaled UID and original read/execute class.
Owner-only `0600`/`0700`
therefore appear as temporary root-owned `0440`/`0550` barriers, but the owning
group's ACL entry remains `---`; only the named former UID receives `r--` or
`r-x`. A shared, externally enumerated or setgid-acquired GID cannot gain those
permissions. The exact temporary ACL is excluded only from the already-bound
xattr fingerprint and every differing ACL remains RED. Same-inode refresh
compares against the computed temporary barrier mode and exact ACL while
retaining the journaled original mode. Newly tracked root-owned paths remain
closed to group/other write and are journaled without inventing a group-based
authorization path.
The generated ACL is installed and verified before ownership changes to root.
The reverse transition changes ownership back first and removes the generated
ACL only afterward. Exact recorded-owner/generated-ACL and
recorded-owner/no-ACL intermediate states are accepted solely when their inode,
mode and normalized xattr contract match the journal, making both transitions
crash-resumable without an access gap. The release-wide xattr baseline omits
only those byte-exact, journal-derived generated ACLs; final validation after
their intentional removal must match that normalized baseline while preserving
every source ACL and unrelated xattr.
Journal-backed rollback and crash recovery additionally recognize the finite
intermediate postures created by the controller itself: recorded ownership
with traversal-preserving restricted mode, root-owned checkout roots retaining
the recorded group, and root-owned or recorded-owner Git roots at the recovery
mode. Nested entries may be either
the recorded owner or root-owned controller output only. Arbitrary ownership
or mode drift remains RED, while a stop between root locking, Git exchange and
metadata restoration remains idempotently recoverable.
Only that journal-backed entry path tolerates an indexed path already absent
because an interrupted checkout removed an old path before replacing the
index. Fresh predeploy scans remain strict, and completed recovery revalidates
the restored tracked set strictly.

On the normal first-install posture, an explicitly reported `LoadState=not-found`
or systemd “unit could not be found” result is normalized to `inactive/dead`;
all other state-query errors remain fail-closed.

The backup also records the named `main`/`control-main` tips and `ORIG_HEAD`
independently of the attached or detached HEAD posture. Each Git bundle
explicitly includes `HEAD`, all refs and a present `ORIG_HEAD`. During rollback
the controller verifies the
recorded bundle SHA-256, verifies and imports the bundle into the quarantined
Git directory, and proves the recorded commit/tree and release-branch objects
exist before checkout. Rollback therefore remains exact even when the original
state was an otherwise unreachable detached HEAD and later Git maintenance has
pruned its canonical object. Both named tips are restored and verified, so a
detached pre-state cannot conceal a release-branch mutation. `ORIG_HEAD` is
likewise restored and verified, including deletion when it was absent before
the attempt. Rollback removes all reflogs created by release checkout/merge or
recovery itself and restores and verifies the complete pre-attempt reflog-tree
digest, so `HEAD@{n}` and branch-reflog history also return to their prior
state.
The controller captures repository-parent, repository-root and `.git`
ownership/modes, durably journals those exact recovery values, then removes
namespace write permission while retaining the recorded group's read/traverse
permission; a baseline lacking group read/traverse is RED. It separately
fingerprints the complete Git-metadata tree, installs a kernel mutation watch
over every metadata directory, and requires a matching full-tree fingerprint
before the first process scan. It then changes real Git metadata to
`root:root` mode `0700`. Any writer event or fingerprint drift is rejected
before the protected body, including a short writer that exits before the
later process scan. The watch remains active
through the atomic exchange; failure or event-queue overflow is fail-closed.
The controller then atomically installs the repository barriers. After the
exchange, it rejects retained handles and re-fingerprints the quarantined inode
tree; this also closes the short-lived writable-mapping case that Linux
mutation notification does not promise to report. Only then does it capture
repository identity, attached/detached posture, release-branch
tip, managed refs, bundles or pre-state files. The same barriers remain held
without a gap through backup validation, the durable attempt marker, canonical
sync and immutable release-stage creation. All backup Git reads and the exact
release sync address the quarantined Git directories explicitly as root. No
ordinary `chatops` Git writer can therefore complete between the point-in-time
backup and the canonical mutation that backup protects. The controller still
re-reads every recorded value after bundle and file capture and immediately
before the durable attempt marker. Any mixed-generation backup is rejected
before deployment mutation. Dirty-state checks exclude only the controller's
fixed, prevalidated quarantine-directory name while the barrier is active;
every other tracked change or untracked path remains RED.
After canonical synchronization, the controller durably records the exact
clean Application and Control release states, complete ref namespaces and
reflog-tree digests in the attempt marker. If any
later acceptance step fails, rollback reacquires the repository barrier and
compares both complete release states before changing non-public runtime files
or Git. The backed-up nginx site and enablement state are restored, validated
and reloaded before barrier acquisition, so repository contention cannot leave
the temporary public callback route loaded.
Any intervening completed commit, checkout or worktree change therefore stops
with `S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED` instead of being overwritten.
Option-like attached branch names are rejected before backup because they
cannot be replayed safely through the bounded branch-restoration command.
If synchronization or immutable-stage creation itself fails, repository
rollback runs through the already-installed barriers before they are released;
no writer gap exists even though no complete post-sync state was available.
Before the first canonical sync mutation, and before any later rollback
mutation, the controller durably records `RESTORE_STARTED` in the root-private
backup. It advances that journal to `REPOSITORIES_RESTORED` while the barriers
are still held and binds that phase to the complete restored repository
states. A failed restore intentionally preserves the physical Git and parent
barriers so recovery can resume `RESTORE_STARTED` without exposing partially
restored repositories. From `REPOSITORIES_RESTORED`, recovery does not replay
Git restoration: it removes any lingering old barrier, reacquires writer
exclusion, revalidates the recorded restored states, and writes the
rollback-complete marker while that exclusion is still held. If barrier
cleanup is interrupted after the marker, recovery removes only the remaining
barrier. Thus a crash, restore error, writer race or `daemon-reload` failure
cannot turn the controller's own partial rollback into false external drift,
emit a false GREEN over repository drift, or cause a second destructive
restore over subsequent work.
Each root-owned, single-link, digest-bound release input bundle is opened once
with `O_NOFOLLOW`; inode identity, owner, mode, link count and SHA-256 are
validated on that descriptor. Bundle verification, head inspection and import
consume its digest-checked copy created from that descriptor only after the
repository parent is locked, so renaming or replacing the input's
`chatops`-managed ancestor cannot substitute release bytes.
After the shared repository parent is locked and retained handles are rejected,
every regular file throughout both canonical worktrees must have link count
one. An external hardlink alias therefore fails closed before either checkout
is mutated or consumed by root.
The root-private barrier journal exists before the first parent/root chmod or
`.git` exchange. A crash before the durable deployment-attempt marker is
therefore recovered as a barrier-only operation: exact ownership and modes are
restored, the fixed disposable fetch stage is removed, and no deployment or
acceptance run is started. A crash after the attempt marker enters the existing
exactly-once rollback path. The journal is removed only after all barriers have
been durably restored.

Before the single `systemctl start`, the unit must be `inactive/dead`, prior
acceptance/final/result evidence is backed up and removed, and newly created
root-private evidence must have a timestamp within this attempt. A stale
successful result cannot satisfy acceptance.
The preflight rejects every effective systemd drop-in and any enabled, linked,
masked, aliased, indirect or otherwise unexpected unit-file state. After the
reviewed main unit is installed and `daemon-reload` completes, its effective
`DropInPaths` must remain empty, its effective `FragmentPath` must equal the
reviewed file below `/etc/systemd/system`, and `is-enabled` must be exactly
`static` before the sole start and again during final read-only verification.

If the controller or host terminates after the durable attempt marker, the
explicit `recover` operation loads the root-private restore index and performs
rollback only. It never starts acceptance and refuses recovery after a
completed successful deployment; an already-complete rollback is verified but
not repeated.

Recovery treats a deployment as successfully complete only when the
root-private result binds the exact backup path and start timestamp from the
current attempt marker. A stale, malformed or differently bound result cannot
block rollback of an interrupted current attempt.

Both `deploy` and `recover` hold one non-blocking exclusive lock on the verified
repository-parent directory inode outside both checked-out worktrees before
preflight or backup. A branch checkout cannot replace this stable inode. This
adds no lock file or pre-backup mutation, while ensuring that concurrent
controllers cannot both observe an absent attempt marker.

Before the backup barrier, the read-only preflight rejects any active long-lived
`/usr/local/bin/tu1nz_sync_all.sh --loop` process with
`WAITING_OPERATOR_CONFLICTING_CONTROL_SYNC`. It neither stops nor bypasses that
external mutator. Normal Git calls before the barrier are dropped to the
`chatops` account and use repository-scoped `safe.directory` values. Release
objects arrive only through two externally authenticated, digest-bound Git
bundles and are imported by isolated root Git into one fixed root-owned
disposable bare stage before the canonical barrier is entered; no canonical
ref or worktree is changed by this acquisition. The shared repository parent
is then root-owned with its original group and write bits removed; retained
parent/staging directory handles are
rejected, and the staged commit/tree/annotated-tag
identity is validated. Once the barrier is active, backup identity, bundle
verification, local-only release sync and immutable cloning use the
quarantined Git directories while bundle bytes are streamed through root-opened
backup descriptors; `chatops` never needs access to the root-private backup
tree.
Every Git process that must run as root uses an empty environment, disables
system/global config, prompts, credentials, hooks, fsmonitor and maintenance,
rejects network protocols, and permits only the local file protocol. Before
such use, repository-local config keys are allowlisted and executable hooks
are rejected. Root Git also requires a direct Git directory and direct object
metadata directories: `commondir`, symlinked object metadata directories, and
local or HTTP object alternates are rejected before Git runs. The complete Git
metadata tree is walked without following links; any symlink or special file,
including nested reference or reflog directories, is rejected before root Git
can read or update it. The active
repository-parent/root barrier prevents the `chatops` owner from changing this
validated layout before root consumes it. Local bundle imports use
`--no-write-fetch-head --no-tags --refmap=` so configured
ref mappings cannot advance `origin/main`, `origin/control-main` or
any other tracking ref. The branch imports are source-only object transfers;
only the exact immutable freeze-tag ref has an explicit local destination. Its
prior presence/target is stored in the restore index and restored or removed
during rollback, so no remote-tracking or tag ref drift can survive a failed
deployment.

Deployment and recovery never execute the controller from the shared
`chatops` checkout. After the single `sudo -v`, trusted system tools copy the
reviewed controller to
`/etc/tu1nz/.tu1nz-adult-commercial-s12-1-runtime.py` as `root:root` mode
`0500`, verify it against the `control_runtime_sha256` value from the immutable
Runtime Freeze, and launch it with an empty environment plus that digest and
the SHA-256 values of both root-owned input bundles. The
controller rejects any other path, owner, group, mode, link count or digest;
the bundle-imported annotated freeze must repeat the same digest before the
single deployment marker can be written. The temporary trusted copy is removed
after success or failure.

Before the repository parent or roots are locked, and again after each lock
stage, `/proc` is checked for every other process retaining a cwd, file
descriptor or mapping in the actual `.git` or `.git.s12-1-recovery` trees. The
final post-exchange check covers the inaccessible guards and both quarantined
Git directories. Worktree cwd, ordinary-file fd and `.venv` mappings remain
allowed because they are not Git metadata. Any metadata mapping is rejected,
including read-only mappings, so an inode retained across the exchange cannot
silently preserve stale metadata.

Release acquisition performs no server-side network Git operation. The exact
reviewed Application `main`, Control `control-main` and annotated Runtime Freeze
tag are carried in dedicated Git bundles from the authenticated review host
over Tailscale SSH. The operator wrapper installs both bundles below the fixed
input directory as `root:root` mode `0600` and binds each to an out-of-band
SHA-256. The controller verifies complete bundle graphs and exact advertised
refs, the annotated tag target and the trusted-controller digest before backup
or canonical repository mutation. The previous canonical Control checkout is
therefore not required to contain the new tag. The later freeze verifier still
proves every commit, tree and artifact binding. The wrapper removes both inputs
after success or failure. Server `chatops` Git/SSH configuration, aliases,
proxies, credentials and host files are never consulted during release
acquisition.

Reviewed unit and nginx artifacts are written to a same-directory temporary
regular file and atomically replace the destination. A pre-existing mask or
other destination symlink is backed up but never followed, so its target
(including `/dev/null`) cannot be modified.

Every atomic JSON or installed-file write fsyncs the temporary file before the
rename and the containing directory after the rename. Attempt, restore-index,
rollback-complete and final-result names therefore survive a crash or power
loss with the same exactly-once meaning as their durable contents.

Before `create_backup` returns, every bundle, copied pre-state file and restore
index is mode `0600` and fsynced; the backup directory and `BACKUP_ROOT` are
then fsynced as well. Newly created private backup/state directory components
are each mode `0700`, root-owned, and made durable by fsyncing both the new
directory and its parent before repository, nginx or systemd mutation starts.
Every existing component from `BACKUP_ROOT` to `/` is also required to be
root-owned, a real directory and neither group- nor world-writable. Creation
and recovery both fail closed if this secure ancestry contract is not met.

Rollback unlinks and symlink restoration fsync their destination parent before
the rollback-complete marker can be written. The restored nginx files are
tested and the baseline is reloaded immediately after file restoration, before
the potentially blocking repository recovery barrier. A Git-process or stale-
lock stop can therefore never leave the temporary callback route loaded in the
running proxy. A completed rollback marker can therefore never outrun deletion
or symlink directory metadata. The standalone
`runtime.py simulate` CLI explicitly adds the frozen repository root to its
module path and emits bounded JSON rather than an import traceback.

Before repository rollback, the controller confirms that neither the Control
sync loop nor any Git process rooted in either canonical checkout is active.
It records the repository-root and Git-directory ownership/modes, removes
namespace write authority while retaining `chatops` traversal, locks `.git`
itself to `root:root` mode `0700`, requires the kernel mutation watch and
cryptographic transition fingerprint to remain clean, and creates a fixed
root-owned mode-`000` guard and atomically exchanges that
directory with each real `.git` directory (`RENAME_EXCHANGE`/`RENAME_SWAP`).
There is no absent-`.git` interval. Normal Git writers therefore cannot enter,
replace or recreate either repository's metadata, nor explicitly select the
quarantined Git path, while recovery
is clearing locks or restoring refs and worktrees. After that barrier exists,
the controller repeats the process/sync checks and rejects any process retaining
a cwd or open file descriptor below the moved Git directories. Only then may it
remove validated, single-link, bounded lock files; every unlink is parent-fsynced.
The quarantined Git root is root-owned mode `0700`; recovery Git therefore runs
only as root while the checkout remains readable/traversable to its recorded
group but namespace-immutable. Every
recovery `git clean` has an exact exclusion for that fixed metadata directory.
The complete quarantined Git metadata tree must contain only real directories
and single-link regular files; symlinks, special files and hard-linked metadata
are rejected before any root Git operation.
Before either guard is removed, Linux `syncfs` durably flushes the filesystem
containing each restored worktree and its quarantined Git metadata. The guard
is then removed, the original Git directory atomically restored, and recorded
repository ownership/modes restored while `chatops` is still excluded. A second
`syncfs` pass after that metadata restoration durably flushes both canonical
repositories before the durable rollback-complete marker is allowed.
An interrupted barrier is recognized and safely resumed by `recover`.
Process matching includes cwd, `-C`, `--git-dir`, `--work-tree` and the
corresponding `GIT_*` environment selectors. An unreadable active Git process,
a matching process, a retained handle or an unsafe lock fails recovery closed.
Retained cwd/fd targets and mappings are matched by device and inode against
the complete protected Git-metadata trees, not merely by pathname. This
also catches an external hardlink opened and then unlinked before the barrier.

The runtime and standalone simulator parse the complete manifest with recursive
duplicate-key rejection before exact structural comparison. A later JSON key
can therefore never silently replace an earlier security-sensitive value.
That structural comparison also requires identical scalar types at every leaf.
Simulator expiry retry additionally requires the exact registered session
object, its immutable `EXPIRED` scenario binding, and the already accepted
authoritative `AVS_EXPIRED` result; a fabricated or publicly mutated object
cannot authorize a retry.
Repeated Git `-C` options are resolved sequentially exactly as Git does, so a
relative selector following an absolute parent selector cannot hide an active
canonical-repository process.
