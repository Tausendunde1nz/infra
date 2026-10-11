# Historical read R6 — known owned inputs, source-only

R5's current protected metadata prefix rejected regular descendant inputs
owned by UID1001 even though it already held their exact ext4 read leases.
The sole failed predicate was the residual UID0-only regular-file requirement;
the same held route admitted UID1001 directories. This is an incomplete R4
integration of kernel-excluded capture, not a proven content mutation. The
separate private observation binds the current rejected objects and preserves
the original unaddressed R5 RED result; it does not retroactively identify that
earlier first failure or prove historical owner/inode continuity.

The smallest correction admits **only the already bounded UID0/UID1001 Git
descendant identities**, for regular files as well as directories, **only in
the held-descriptor route**. Native ext4, matching stat/held inode, active
regular-file read lease, directory watch, exact known ACL/default/xattr/flag
layout, GID0/1001, type and regular single-link constraints remain mandatory.
The containing reader must still retain and check the complete whole-tree and
historical ancestry witnesses, all object/evidence inputs and the common
deadline. Kernel exclusion, not owner/group/ACL trust, establishes integrity.
No regular file becomes eligible through the descriptor-free legacy route.
Unknown UIDs/GIDs, effective historical-parent writers, wrong fixed-root/
guard ownership, missing/broken leases, retained writers/maps, metadata or
namespace mutation, indirection, interruption and cleanup failure still deny.

The writer model and kernel TCB are unchanged from R4. UID1001 ownership does
not exempt a writer from kernel fencing; an owner can change inode metadata,
but that event/fingerprint change must reject the completed capture. Ordinary
UID0 writers remain equally fenced. No new delegated rights or privileged
administrator exemption is asserted. Host delegated privileges, historical
causes/PIDs and predecessor continuity remain UNKNOWN.

Native regression fixtures model UID1001 regular Git config and an extra
non-input regular node, exact ACL masks and mode-only profiles. Positive
repository/object capture must preserve bytes and metadata without
normalization. Negative tests require exclusion of retained writable FDs and
shared mappings, new owner write attempts, retained-handle owner metadata
changes, unknown owner/group/ACL, hardlinks, unleased/descriptor-free calls,
interruption and replay. Existing R4/R5 negatives remain required.

Mandatory Control CI, unchanged native S11/S12/R12/R15/S12 attempt gates,
Application's pinned private image/provisioning/PostgreSQL chain, exact final
reviews, merges/post-merge CI and a new immutable R6 freeze remain required.
Old green results do not accept changed source; R1–R5 and historical tags are
never overwritten. The original systemd-Q investigation is not repeated.

## Host plan and remaining gates

This correction needs **no** server owner/group/mode/ACL/flag normalization,
new host path, process pause, or repository unlock. It is source-only. The
historical `.git` barriers and four independently fixed evidence digests stay
unchanged. The S8 slot remains `s8-same-release-20261004-1`; a new freeze does
not create another start or attempt. Installation and Runtime admission are
not performed by this reader or by source closure.

No automatic whole-Reader retry follows the fix. A separately authorized fresh
protected historical capture must bind R6 sources and current host state;
the targeted metadata result cannot accept HEAD/tree/objects/evidence, all
worktree/index/unversioned state, source origin or a Control rollback. The
existing Control-only recovery authorization still requires those fresh
technical proofs and a tested Control-only procedure; the canonical two-root
S12 recovery is not a shortcut and its ABORTED denial remains intact.

Lighting's independent content/source/local tests may continue. Its RC5
Control basis cannot be equated to the Adult/infra historical source, and its
productive handoff/publication remains blocked on source, content, recovery,
rollback and the separately accepted deployment route. No website is
published in this source/diagnosis task.

Live/S8/R15/runtime/product gates remain NO-GO. R15 pause compatibility OPEN;
S9/S10/S11 RED states are not uplifted by an S8 source result. Final evidence
and exact SHA/CI/review/freeze bindings are retained privately after closure;
this candidate documentation is not host acceptance.
