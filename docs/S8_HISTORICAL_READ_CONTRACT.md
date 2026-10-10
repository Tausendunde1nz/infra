# Historical S8 read binding — R3 source delta, 2026-10-10

R2 confused the strict metadata predicate for new execution stock with
protected reading of the incident's historical repositories. Its group-zero
requirement rejected the observed root-owned GID1001 repository directories;
the no-xattr predicate rejected the Application Git access/default ACLs.
Those rejections establish neither a content mutation nor inaccessible data's
commit/tree identity. Four fixed historical evidence digests matched in the
separately retained read-only observation; repository HEAD/tree remains a
mandatory **unperformed host check**, not a match inferred from this fix.

## Separate read eligibility, exact content and historical provenance

Only the two canonical historical roots and the Application Git barriers use
the exact incident-observed metadata profiles. Current eligibility is not a
historical metadata baseline. New execution stock, markers, admission anchor,
drop-ins and all unspecified ancestors retain their original strict policy.
Historical creation is forbidden. Unknown owners/groups, xattrs, ACL layouts,
effective non-owner write rights, symlinks, file hardlinks and Git indirection
remain denied. The existing ancestor DAC/ACL/flag and exchange checks apply.

The Application named UID1001 and group entries contain raw `rwx`, but the
access mask limits repository-root effective rights to `r-x` and Git-directory
non-owner rights to `---`. Defaults with write bits are compared only; they
are never exercised to create or adopt objects. This is no group/ACL writer
exception. Existing Git descendants must themselves deny effective non-owner
writes and match the bounded read policy; unobserved descendant metadata may
therefore still deny the later host check. No normalization is authorized.
Both historical Git guards still require exact root-owned `0000`, and their
real Git directories exact `0700`; a reopened guard remains denied even if
the commit/tree still matches. Control retains its no-ACL Git profile.

Every Git inode and relevant ancestor is continuously watched for this read
interval, including write-and-restore through an already open descriptor.
Lost/overflowed watches, interrupted reads and detected changes deny the
result. Git reads use no optional locks, inherited credentials/configuration,
hooks, replace objects or allowed transports. Includes, alternate object
stores, shallow/promisor and external worktree/config indirection are denied.
Pinned HEAD/tree are checked; raw commit/tree bytes must hash to the exact
object identities and the commit's tree must match. No live-worktree equality,
historical inode predecessor, missing owner identity or successor is inferred.

Errors distinguish `HISTORICAL_READ_UNAVAILABLE` / missing binding from
`HISTORICAL_CONTENT_RED`, unsafe access conditions and read-interval changes.
Primary, abort and cleanup provenance remain separate and privacy-redacted.
Failed access is not proven drift; readable files alone are not integrity.
No observer read creates a marker, permission, reset, retry or start. Missing
follow-on markers still cannot authorize a new attempt. Slot identity remains
`s8-same-release-20261004-1`; R3 does not create another allowance.

## Integration and remaining gates

The exact historical-read module is embedded in the same frozen code bundle.
Byte-preserving source transport removes an unnecessary inner base64 layer
while retaining source digest/encoding validation, isolated imports and the
existing 100000-byte command bound. Synthetic native Linux tests cover the
evidenced group/ACL combinations, effective writers, wrong/missing identities,
indirection, interruption, descriptor write/restore and ancestor exchange.
Existing nonblocked native PID1, PostgreSQL and S11/S12 integration gates and
final same-SHA reviews remain required; historical green cannot accept R3.

The accepted administrative systemd model is unchanged. Its original blocked
Q investigation is not repeated or relabelled. Historical incident causes,
PIDs and metadata predecessor continuity remain UNKNOWN. R15 pause
compatibility OPEN; S9/S10/S11 RED and product gates CLOSED remain separate.

Source merge/freeze is conditional on new final CI/reviews and post-merge
evidence. A future protected read-only host acceptance must independently
verify current ancestry and Git-descendant permissions, fixed object/evidence
bindings, service/lease/rights state and retained attempt markers. This source
delta is neither that host acceptance nor a live grant, repair or deployment.
