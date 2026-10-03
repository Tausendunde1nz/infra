# R12: explicit metadata policy and successor bindings

## Scope and authority

Source-only; no server application, guard removal, recovery or deployment was
authorized in this change. The future `reconcile-metadata --metadata-contract
<protected-contract>` operation is separate from `recover` and `deploy`; neither
calls it implicitly. It requires the existing exclusive flock, trusted-controller
digest, root, Linux and the exact SHA-256-bound contract. It returns with both Git
guards installed. Its result is **not** runtime health or a recovery GO.

The contract enumerates exactly 254 paths from protected read-only evidence
`9624ea3d41804d0ef7c13350e69075fce469250e0871d35e0b76599eb28c11ad`
(2026-10-03T09:43:58.276816Z). Admission tuples are observations, not a statement
about who created an object. That investigation verified 1,302 release files and
the recorded backup digests; it did not test a restore or prove continuous writer
exclusion. The contract binds the original journal, attempt, restore index,
quarantined Git identities, release commits and individual content digests.

## Policy, not retrospective history

| Class | Count | New source policy |
|---|---:|---|
| No historical per-path record | 16 | `NEW_CANONICAL_ASSIGNMENT` |
| New inode at a recorded predecessor path | 238 | `NEW_SUCCESSOR_ASSIGNMENT` |

For the 16 unjournaled paths, the sole maintenance identity is the journal-bound
repository owner/group (1001:1001). Non-executable source files use `0660`,
directories `2770`: owner/group maintenance remains possible after a separately
validated release, other access is forbidden, setgid preserves the maintenance
group for child creation. No executable privilege is inferred from current mode;
Git's executable class is the only source-class authority. No source file in this
16-path set is executable. There is no default ACL and no inherited named ACL in
this new baseline. This removes implicit inheritance from the new policy, not
evidence from the original journal. Current values such as `2775` or `2755` are
admission observations and explicitly do **not** become the desired state.

For the 238 successors, the proved predecessor UID/GID/mode and normalized ACL
payload are retained as the explicit policy template. A fingerprint recomputed
with the **predecessor** path/device/inode must match the original journal. This
proves only the template; it does not transfer identity. Each current object gets
a distinct new binding to its open descriptor, device, inode, kernel birth time,
kind, link count, target blob and exact xattr payload. Historical continuity is
always false. Unknown xattrs, capabilities, symlinks, hardlinked files, wrong
owners/modes, unsupported birth time and drift are rejected, never normalized away.

## Transaction and interruption contract

1. Verify the exact protected inputs, associated backup blob/reflog digests, root
   barriers and unchanged Git guards. Reject actual Git/sync or retained writers.
2. Pin all path components without symlink traversal. Keep the existing Git
   metadata watch, Worktree inotify/open-permission guard and retained-handle
   quiescence across **all index names and existing ancestors**, not only the 254
   assignment paths or present regular files. Absent entries are guarded through
   their nearest existing ancestor; symlinks through their parent without
   following their targets. Intermediate symlinks fail closed. Late-writer
   regressions cover unrelated regular, missing and symlink index entries, also
   with missing ancestor directories. A separate PID-attributed `FAN_ATTRIB` guard rejects other threads'
   chmod/chown/xattr events, including changes later reverted. Linux
   [file-handle fanotify events](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
   and open-permission support are mandatory; there is no fallback.
3. Preserve the original journal byte-for-byte as a root-only immutable-by-contract
   sidecar. Save the full `PREPARED` successor ledger durably before changing any
   affected path. Original records stay separate from new bindings.
4. Before each descriptor-bound metadata syscall, fsync its finite transition
   intent. Accept on resume only the exact bound pre-state or that intent's exact
   post-state (including birth time, content and ACLs). Reacquire all guards;
   do not claim uninterrupted exclusion during process downtime. An unmatched
   state, identity replacement or detected competing event aborts closed.
5. The metadata transaction grants no writes: objects become root-owned with all
   write bits removed. Named-owner read/traverse access remains available through
   the existing ACL contract. The journal records the separately justified future
   release mode/owner, not a false historical owner of the successor inode.
6. Persist the `SEALED` ledger, then atomically publish a V4 barrier journal binding
   its hash, the original-journal hash and the immutable contract hash. Original
   journal and bindings remain retained. V4 load/refresh preserves this lineage.
   A detected failure first durably records an abort receipt. If V4 was already
   published, the original V3 journal is restored byte-for-byte **before** the
   ledger becomes `ABORTED`. Thus no published V4 references a rewritten ledger.
   The receipt blocks V4 consumption during interrupted finalization. A later
   invocation may only finish restoring V3 and aborting the ledger, then returns
   `S12_1_R12_ABORTED_NO_RETRY`; it cannot retry metadata assignment. No automatic
   second attempt or guard release is allowed.
   A repeated call after V4 commit stops with
   `S12_1_R12_ALREADY_SEALED_RECOVERY_PREFLIGHT_REQUIRED`, not cached GREEN.

Crash boundaries before/after intent, metadata syscalls, ledger completion and
journal commit are part of regression coverage. An interruption does not relax
any admission predicate. No Git content/ref/index mutation occurs in this entrypoint.
The existing exactly-once backup/rollback contracts remain in force. Changes made
by a subsequent Git restore outside this 254-path transaction remain subject to
the existing barriers; R12 does not promise that an unexecuted recovery is GREEN.

## Validation and handoff

The required native Linux CI step runs the real privileged guards and metadata
tests without mocks. Local Docker LinuxKit has `CONFIG_FANOTIFY=y` but lacks
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS`; local state-machine diagnostics with that
one guard disabled are explicitly **not** security acceptance. The CI step must
pass before merge/freeze. The R12 freeze binds this contract, runtime, tests,
documentation and validation workflow in addition to all previous artifacts.

The next runtime gate remains `S12_1_RECOVERY_WORKTREE_BARRIER_RED` until a separately
authorized, backup-first runtime step stages and verifies the exact R12 artifacts
and completes live preflight. No runtime permission is implied by source GREEN.
