# Commercial S12.1 Yoti Sandbox runtime Control contract

## Release and activation boundary

S12.1 is a bounded, one-attempt runtime acceptance release.  The immutable
annotated tag `s12-yoti-sandbox-runtime-freeze-r1` binds the exact Application
merge commit and tree, the exact Control merge commit and tree, every runtime
artifact, the hard-gate values and the exactly-once rollback contract.  The
older `s12-yoti-sandbox-source-freeze-r1` remains immutable and is not an
activation release.

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
complete reflog tree or its absence, the prior
unit/runtime-config/nginx bytes and modes, credential metadata only,
SHA-256 values and a restore index.  Rollback requires a successful systemd
stop and verifies `inactive/dead` before it restores the pre-state files and
branches, reloads systemd/nginx, preserves credentials and writes one
privacy-safe rollback marker.  It never reports rollback success while the
runtime may still be active. Rollback also removes the fixed root-private
release and staging trees and fsyncs their parent before completion. A second
rollback invocation or a second
deployment marker is rejected.

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
`chatops` access from the shared repository parent and atomically installs the
repository barriers before
it captures repository identity, attached/detached posture, release-branch
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
compares both complete release states before changing runtime files or Git.
Any intervening completed commit, checkout or worktree change therefore stops
with `S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED` instead of being overwritten.
Option-like attached branch names are rejected before backup because they
cannot be replayed safely through the bounded branch-restoration command.
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
is then root-owned mode `0500`, retained parent/staging directory handles are
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
stage, `/proc` is checked for every other process retaining a cwd or file
descriptor or writable memory mapping anywhere below either complete canonical
worktree. The final post-exchange check covers both complete worktrees and both
quarantined Git directories. A retained handle or mapping therefore stops the
attempt before backup or canonical mutation instead of surviving a chmod
barrier. Shared mappings are rejected even when currently read-only because an
existing shared mapping can retain permission to become writable later.

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
`chatops` write/traverse authority from the checkout root, creates a fixed
root-owned mode-`000` guard and atomically exchanges that
directory with each real `.git` directory (`RENAME_EXCHANGE`/`RENAME_SWAP`).
There is no absent-`.git` interval. Normal Git writers therefore cannot enter
or recreate either repository, nor explicitly select the quarantined Git path,
while recovery
is clearing locks or restoring refs and worktrees. After that barrier exists,
the controller repeats the process/sync checks and rejects any process retaining
a cwd or open file descriptor below the moved Git directories. Only then may it
remove validated, single-link, bounded lock files; every unlink is parent-fsynced.
The quarantined Git root is root-owned mode `0700`; recovery Git therefore runs
only as root while the checkout root remains locked. Every
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
Retained cwd/fd targets and writable or shared mappings are matched by device
and inode against the complete protected trees, not merely by pathname. This
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
