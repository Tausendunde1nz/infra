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
   A normal predeploy scan remains strict when an indexed path is absent.
   Journal-backed recovery alone may skip an absent index path because an
   interrupted root checkout can remove the old path before replacing the
   index; all surviving entries remain fully validated and the restored result
   is resolved again under the strict contract.
3. Journal the exact repository and shared-parent metadata durably, including
   normalized xattr/ACL fingerprints for the shared parent and both repository
   roots before any sequential lock begins. Reject a
   tracked regular file carrying `security.capability` or a set-user-ID mode
   before any ownership transition. Linux `chown(2)` would otherwise clear the
   capability xattr and make exact recovery impossible, while restoring the
   set-user-ID mode after the temporary root handoff could create a transient
   setuid-root executable.
4. Fingerprint the complete protected Git-metadata tree, install a kernel
   mutation watch on every metadata directory, then require a second full-tree
   fingerprint to match before the first process scan begins.
5. Remove write bits from the shared parent and repository roots, change only
   their owner to root, and retain their recorded groups and traversal classes.
   Validate each journaled root fingerprint before and after its lock. A
   baseline without effective recorded-owner read/traverse permission after
   the handoff is rejected.
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
   Before the journal or any transition, resolve the permission class that the
   recorded owner will actually receive after the handoff: a matching named
   user entry takes precedence; otherwise the union of the owning-group and
   matching named-group ACL entries is filtered through the ACL mask (including
   a valid base ACL carrying an optional mask without named entries); only an
   account matching no group entry receives the other class. Without an access
   ACL, the same retained-group-membership decision is applied directly to the
   ordinary group/other mode classes before ownership changes.
   Reject the path unless that exact class retains every prior owner read and
   execute/traversal right. Owner-only `0600`/`0700` and the group-member case
   `0604` therefore cannot become unreadable or untraversable merely because
   ownership moves to root. The V3 journal also binds both repository roots,
   while retaining the V2 binding for each tracked inode's and
   ancestor directory's normalized xattr/ACL fingerprint before any path is
   locked, and validates it before and after lock, restore and reseal. A V1
   orphan is upgraded only if each extant path has no unbound named ACL
   principal or unrelated xattr; missing obsolete paths remain explicitly
   bound as missing. Read and execute/traversal bits are otherwise preserved.
   Repeat actual-Git,
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
   root and every directory in each canonical `.git` tree. Before the guard is
   drained, bind the shared parent's normalized xattr/ACL fingerprint in the
   V3 barrier journal and validate it before and after every soft lock, hard
   lock and restore. V1/V2 orphan upgrades bind repository-root xattrs only
   when the previously unbound root contains no named ACL principal or
   unrelated xattr; the V1 parent/path upgrade keeps the same rule. Then harden the shared
   parent to `root:root 0500`. Both syscall-boundary states of that hardening
   transition are journal-recognized and resumable.
13. Discover every non-controller process that retains an exact guarded inode
   or a directory handle/cwd inside either Worktree, including the controller's
   launcher, shell and supervisor ancestry; only the controller PID itself is
   exempt. Keep healthy read-only handles valid, but briefly quiesce every
   thread of their owning processes with `PTRACE_SEIZE` plus
   `PTRACE_INTERRUPT` for the final ownership handoff. Linux automatically
   detaches and restarts ptrace-stopped tracees
   if the controller dies, so no persistent service stop can be orphaned.
   Validate process/thread start times and the ptrace-stop state, and iterate
   the scan until no inheriting child or new thread remains. A journaled path
   legitimately deleted by the completed checkout is omitted from handle
   discovery because no guarded inode remains; the later released-contract
   validation must still prove that the recorded path is obsolete. An
   unresolved deleted directory fd is skipped per descriptor, never per
   process, so it cannot hide a later guarded fd from quiescence. This
   changes no unit state and causes no restart. With both inotify and fanotify
   still active, restore exact journaled ownership/modes, accept only the
   controller's attribute events, validate the released contracts and both
   fingerprints, and re-check repository identity and writer exclusion. Then
   remove every inotify watch and require the ordered `IN_IGNORED` barrier for
   every watch without any intervening mutation. Revalidate that every retained
   handle owner is still the same ptrace-stopped process before closing
   fanotify. Restore the shared parent as the explicit release point while the
   exact seized threads remain ptrace-stopped, then detach them. A handled
   parent-release failure first reseals the repository and only then detaches
   those processes; controller death is kernel-cleaned. Existing
   read-only service cwd/fd/maps are thus
   allowed without reopening an unobserved `fchmod`/relative-path race. The Git
   fingerprint
   intentionally ignores only ownership/ctime and the top `.git` mode changed
   by the controller. Both release fingerprints normalize the same POSIX ACL
   base permission fields deterministically rewritten by the intentional mode
   restore, while still binding ACL structure, named entries and all unrelated
   xattrs; the Git fingerprint otherwise
   binds nested modes, names, inode identities, sizes, mtimes and file bytes.
   Flush repository filesystems throughout; the synchronized watch-removal
   barrier completes while paths remain unreachable to their owners; restoring
   the single shared parent is the transaction's explicit writer-release point.
   Fanotify classifies only native open forms whose access flags are present in
   immutable syscall arguments; `openat2` remains fail-closed because its
   already-consumed `open_how` userspace structure can change while the caller
   is blocked. Worker health is checked before every sentinel open, and a
   worker error closes the permission group to wake blocked syscalls before the
   controller reports RED. With the shared parent still hard-locked and every
   retained handle owner still quiesced, guard teardown atomically flushes the
   fanotify marks, then denies both user-space-held and kernel-queued permission
   events through the still-open cached group before closing its descriptor.
   No new event can enter the group after the flush, and namespace/handle
   exclusion remains in force until the parent is restored as the release
   point.

The namespace locks prevent an unprivileged writer from replacing `.git` in
the scan/exchange race. The fingerprint plus the kernel mutation watch closes
the short-lived-writer gap: a metadata change is rejected before the protected
body even when no process or descriptor remains at the later scan. The group
traversal contract keeps S7, S8 Landing, S8 Telegram and S10 WMS able to use
their existing Worktree and `.venv` paths.

Every permission mutation is resumable at its syscall boundary. Recovery
accepts the journaled owner with write bits already removed and
`root:<recorded-group>` with the restricted mode, then completes the lock.
An indexed old path already removed by an interrupted checkout is accepted
only in this journal-backed entry phase; the path is never fabricated or
silently accepted in a fresh deployment.
Before permission release, the barrier journal is refreshed with the exact
current inode and canonical target metadata for every path created or replaced
by root Git. A release interrupted after ownership restoration can therefore
reseal only the journal-bound inode; a later replacement still fails closed.
An R3 orphaned parent or repository root at `root:root 0500` is normalized to
the R4 traversal-preserving `root:<recorded-group>` restricted mode before any
subsequent validation or Git transition. Recovery also accepts the exact
interrupted root transition `root:<recorded-group> 0500` and completes its
pending chmod, so a crash between those two syscalls cannot strand the
checkout.

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
| `openat2` during release | unclassifiable mutable argument; held fail-closed |
| fanotify worker error/overflow | permission group closed to wake waiters; RED |
| writer waiting for restored owner permission | detected by release watch; RED |
| new writable mmap opened during release | blocked/denied by fanotify; RED |
| nested `.git` create/write during release | recursively watched and fingerprinted; RED |
| external chmod/fchmod during final ownership restore | retained handle owner is quiesced or watched event fails; RED |
| external setxattr/fsetxattr during lock or release | root transition or guarded-path xattr fingerprint mismatch/event; RED |
| healthy retained read-only Worktree cwd/fd | allowed; briefly quiesced only for final ownership handoff |
| read-only mapping without retained fd/cwd | allowed; no metadata capability to quiesce |
| tracked file with `security.capability` | rejected before ownership transition; RED |
| tracked path with set-user-ID mode | rejected before ownership transition; RED |
| tracked path with owner-named ACL that would reduce post-chown read/traverse | rejected before ownership transition; RED |
| repository parent/root with owner-named ACL that would override required group traversal | rejected before ownership transition; RED |
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

The repository-root xattr fingerprint remains barrier-journal state and is not
copied into the six-field repository metadata in a runtime backup index; backup
capture and reconstruction therefore compare the same canonical schema.

An orphan journal is never manually removed. The reviewed `recover` operation
validates its schema, paths and metadata; proves no Git writer or metadata
handle; restores an installed exchange atomically when present; restores exact
ownership/modes; verifies repositories; fsyncs the relevant filesystems; and
only then durably removes the journal. Barrier-only recovery does not consume
the fresh runtime deployment attempt.

### Pristine V1 orphan release

The r5 continuation handles the narrower state in which a V1 journal was
durably written but the repository transition never began. The direct release
is allowed only when there is no deployment-attempt marker, no fetch stage, no
worktree-barrier payload, both canonical `.git` directories are installed,
neither recovery directory is present, and the repository-parent and both
repository roots still match the six recorded owner/group/mode fields. Both
indexes and clean identities are validated with Git optional locking disabled,
so the classifier cannot refresh or replace an index. Control sync, Git processes,
Git-metadata handles, tracked-file writers and exact parent-directory handles
must be absent before and after repository filesystem synchronization. Only
then may the reviewed recovery operation durably remove the V1 journal.

This path performs no repository permission or ownership transition. It
therefore neither upgrades unbound legacy ACL/xattr state nor constructs a new
tracked-path barrier merely to release a pre-mutation journal. Every V2/V3
journal, any installed/partial recovery exchange, any fetch stage, any attempt
marker and every metadata mismatch continues through the existing full
fail-closed barrier recovery.

## Product boundary

R4 changes repository recovery only. Yoti remains Sandbox-only; no real
identity, document, selfie or biometric is used. Real AVS, Adult media,
publishing, payment, Controlled Beta and Production remain closed.
