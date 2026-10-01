# S12.1-R4 Git metadata recovery barrier

## Scope

R4 corrects the r3 Worktree-handle false positive without weakening Git writer
exclusion. Protected resources are the canonical `.git` trees and, during an
atomic exchange, `.git.s12-1-recovery`. Ordinary tracked files, the preserved
`.venv`, and healthy service WorkingDirectories are not Git metadata.

## Exclusion sequence

1. Validate repository identity, layout and recorded ownership/modes.
2. Reject the competing Control sync loop, actual Git processes and retained
   Git-metadata handles.
3. Journal the exact repository and shared-parent metadata durably.
4. Fingerprint the complete protected Git-metadata tree, install a kernel
   mutation watch on every metadata directory, then require a second full-tree
   fingerprint to match before the first process scan begins.
5. Remove write bits from the shared parent and repository roots, change only
   their owner to root, and retain their recorded groups and traversal classes.
   A baseline without recorded-group read/traverse permission is rejected.
6. Change canonical `.git` to `root:root` mode `0700`, then require both the
   transition fingerprint and the kernel event queue to remain unchanged.
7. Repeat actual-Git and metadata-handle checks.
8. Create a root-owned mode-`000` guard and atomically exchange it with `.git`.
   Keep the mutation watch through the exchange and reject any writer event,
   including one from a process that already exited before the process scan.
9. Reject handles into either guard or quarantined metadata and re-fingerprint
   the quarantined inode tree. This also catches a closed writable mapping,
   which Linux mutation notification alone does not promise to report.
10. Run isolated
   root Git exclusively against the quarantined directory.
11. Flush repository filesystems, exchange metadata back, restore exact
   ownership/modes and flush again.

The namespace locks prevent an unprivileged writer from replacing `.git` in
the scan/exchange race. The fingerprint plus the kernel mutation watch closes
the short-lived-writer gap: a metadata change is rejected before the protected
body even when no process or descriptor remains at the later scan. The group
traversal contract keeps S7, S8 Landing, S8 Telegram and S10 WMS able to use
their existing Worktree and `.venv` paths.

## Classification matrix

| Retained resource | Decision |
|---|---|
| Worktree root cwd | allowed |
| ordinary tracked-file fd | allowed |
| `.venv` executable/map | allowed |
| `.git` cwd/fd/map | RED |
| `.git.s12-1-recovery` cwd/fd/map | RED |
| Git process targeting either canonical repository | RED |
| unrelated external process | ignored |

No service or executable name is trusted. Classification is based only on the
protected resource and canonical Git-process selectors.

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
