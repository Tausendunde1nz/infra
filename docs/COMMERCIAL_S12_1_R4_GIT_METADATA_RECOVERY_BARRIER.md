# S12.1-R4 Git metadata recovery barrier

## Scope

R4 corrects the r3 Worktree-handle false positive without weakening Git writer
exclusion. Protected resources are the canonical `.git` trees and, during an
atomic exchange, `.git.s12-1-recovery`. Ordinary tracked files, the preserved
`.venv`, and healthy service WorkingDirectories are not Git metadata.

## Exclusion sequence

1. Validate repository identity, layout and recorded ownership/modes.
2. Resolve the regular files currently tracked by each canonical index. Reject
   the competing Control sync loop, actual Git processes, retained Git-metadata
   handles, writable tracked-file descriptors, writable shared mappings and
   read-only shared mappings whose `VmFlags` still permit a write upgrade.
3. Journal the exact repository and shared-parent metadata durably. Reject a
   tracked regular file carrying `security.capability` before any ownership
   transition, because Linux `chown(2)` would otherwise clear that xattr and
   make exact recovery impossible.
4. Fingerprint the complete protected Git-metadata tree, install a kernel
   mutation watch on every metadata directory, then require a second full-tree
   fingerprint to match before the first process scan begins.
5. Remove write bits from the shared parent and repository roots, change only
   their owner to root, and retain their recorded groups and traversal classes.
   A baseline without recorded-group read/traverse permission is rejected.
6. Change canonical `.git` to `root:root` mode `0700`, then require both the
   transition fingerprint and the kernel event queue to remain unchanged. The
   transition fingerprint normalizes the controller-owned top-directory
   owner/mode/ctime change. In a POSIX access ACL it also normalizes only the
   base permission fields that `chmod(0700)` deterministically rewrites; ACL
   structure, named user/group entries, default ACLs and every other xattr
   remain bound. The canonical mode restore rewrites those normalized base
   fields again, so an external persistent root xattr or ACL change cannot hide
   in the accepted `IN_ATTRIB` transition events.
7. From the durably journaled tracked-path set, remove every write bit and move
   tracked regular inodes plus their ancestor directories under root ownership.
   Read and execute/traversal bits are preserved. Repeat actual-Git,
   metadata-handle and writable tracked-worktree-handle checks, then require a
   fresh clean identity before the protected body.
8. Create a root-owned mode-`000` guard and atomically exchange it with `.git`.
   Keep the mutation watch through the exchange and reject any writer event,
   including one from a process that already exited before the process scan.
9. Reject handles into either guard or quarantined metadata, re-fingerprint the
   quarantined inode tree and re-check writable tracked-worktree handles. This
   catches both a closed writable Git-metadata mapping and a retained writer to
   a tracked Worktree inode.
10. Run isolated
   root Git exclusively against the quarantined directory.
11. Re-resolve the post-operation tracked set and require every current tracked
   inode and ancestor to be root-owned without group/other write permission.
   Reject any remaining write-capable handle, require a fresh clean Worktree
   identity, then repeat the write-handle scan.
12. Exchange Git metadata back while the tracked-path write barrier remains in
   force, repeat the barrier/identity/handle checks against canonical `.git`,
   and only then start both a kernel mutation watch and a fanotify
   open-permission barrier covering every tracked path, ancestor, repository
   root and every directory in each canonical `.git` tree before restoring the
   exact journaled ownership/modes.
13. After the staggered permission restore, accept only the controller's own
   attribute events, restore surviving recorded inodes exactly, and explicitly
   normalize every new or replaced current tracked inode to the canonical
   repository owner/group while preserving its reviewed Git mode. Validate
   that released state, then repeat identity/handle/identity checks. Any
   waiting writer, newly opened writable mapping or replacement event fails
   closed before the guards are released. Git metadata stays root-only until
   all Worktree validation is complete and is released by changing the `.git`
   root mode last. The controller then revalidates the complete Worktree and
   repository contracts, matches an exact Git-metadata namespace/content/mode
   fingerprint captured before release, matches a separate extended-attribute
   fingerprint across every guarded path, repeats Git/handle/identity checks
   and drains the event queue once more. Shutdown repeats that validation while
   all inotify watches remain active, removes every watch, and requires the
   ordered `IN_IGNORED` event for every watch without any intervening mutation.
   The final released-state validation therefore runs entirely under active
   attribute watches, and a retained read descriptor's `fchmod`/`fsetxattr` in
   the former drain-to-close gap is rejected while the ordered watch-removal
   barrier is consumed. Fanotify remains active until that barrier completes.
   The Git fingerprint
   intentionally ignores only ownership/ctime and the top `.git` mode changed
   by the controller. Both release fingerprints normalize the same POSIX ACL
   base permission fields deterministically rewritten by the intentional mode
   restore, while still binding ACL structure, named entries and all unrelated
   xattrs; the Git fingerprint otherwise
   binds nested modes, names, inode identities, sizes, mtimes and file bytes.
   Flush repository filesystems throughout; the synchronized watch-removal
   barrier is the transaction's explicit writer-release point.

The namespace locks prevent an unprivileged writer from replacing `.git` in
the scan/exchange race. The fingerprint plus the kernel mutation watch closes
the short-lived-writer gap: a metadata change is rejected before the protected
body even when no process or descriptor remains at the later scan. The group
traversal contract keeps S7, S8 Landing, S8 Telegram and S10 WMS able to use
their existing Worktree and `.venv` paths.

Every permission mutation is resumable at its syscall boundary. Recovery
accepts the journaled owner with write bits already removed and
`root:<recorded-group>` with the restricted mode, then completes the lock.
Before permission release, the barrier journal is refreshed with the exact
current inode and canonical target metadata for every path created or replaced
by root Git. A release interrupted after ownership restoration can therefore
reseal only the journal-bound inode; a later replacement still fails closed.
An R3 orphaned parent or repository root at `root:root 0500` is normalized to
the R4 traversal-preserving `root:<recorded-group>` restricted mode before any
subsequent validation or Git transition.

## Classification matrix

| Retained resource | Decision |
|---|---|
| Worktree root cwd | allowed |
| ordinary tracked-file fd opened read-only | allowed |
| ordinary tracked-file fd opened write-capable | RED |
| read-only shared mapping without write capability | allowed |
| writable or write-upgradeable shared mapping | RED |
| private copy-on-write mapping without writable fd | allowed |
| new path-based tracked-file writer after lock | blocked by permissions |
| external read-only open during release | allowed after blocked-syscall flag proof |
| writer waiting for restored owner permission | detected by release watch; RED |
| new writable mmap opened during release | blocked/denied by fanotify; RED |
| nested `.git` create/write during release | recursively watched and fingerprinted; RED |
| external chmod/fchmod during release or guard shutdown | final post-inotify contract/fingerprint mismatch or event; RED |
| external setxattr/fsetxattr during lock or release | root transition or guarded-path xattr fingerprint mismatch/event; RED |
| tracked file with `security.capability` | rejected before ownership transition; RED |
| `.venv` executable/map | allowed |
| `.git` cwd/fd/map | RED |
| `.git.s12-1-recovery` cwd/fd/map | RED |
| Git process targeting either canonical repository | RED |
| unrelated external process | ignored |

No service or executable name is trusted. Classification is based only on the
protected resource, descriptor flags, mapping permissions/`VmFlags` and
canonical Git-process selectors.

## Worktree mutation proof

The exact frozen Application delta is limited to S12/Yoti modules, tests,
documentation and packaging metadata. Active S7/S8/S10 entrypoints do not
import the changed provider/S12 modules. The ignored `.venv` remains in place.
The r4 live-shaped regression holds four representative Worktree users through
the complete barrier and proves cwd traversal, ordinary reads and `.venv`
access continue. A broader release touching active runtime modules would need
its own safety proof or immutable-runtime migration and cannot inherit this
release-specific conclusion.

## Orphan recovery

An orphan journal is never manually removed. The reviewed `recover` operation
validates its schema, paths and metadata; proves no Git writer or metadata
handle; restores an installed exchange atomically when present; restores exact
ownership/modes; verifies repositories; fsyncs the relevant filesystems; and
only then durably removes the journal. Barrier-only recovery does not consume
the fresh runtime deployment attempt.

## Product boundary

R4 changes repository recovery only. Yoti remains Sandbox-only; no real
identity, document, selfie or biometric is used. Real AVS, Adult media,
publishing, payment, Controlled Beta and Production remain closed.
