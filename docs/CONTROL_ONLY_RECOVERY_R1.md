# Control-only recovery R1 — separate protected source view

Source-only contract. Source closure is established only by the immutable
`control-only-recovery-source-freeze-r1` payload with exact CI/review/merge
bindings. This document, a test GREEN or a generated packet is NOT Host or
deployment authority. R6 history capture remains GREEN for its old interval;
it is neither repeated nor a continuing writer fence.

## Source identity and consumers

The new view is exactly `Tausendunde1nz/control`, commit
`2281b2b397c017bc370ba108eab3dc00c989eaa5`, tree
`3d52fe0898238e1132d8947a7e171d8086982170` (includes RC5 PR75).
It is NOT the historical Adult-Control `infra` content at `b44a3a7e…` /
`477e63c…` and NOT Lighting PR76's candidate `901ef43…`.

Historical `/opt/tu1nz_repos/control`, `.git` guard and quarantined Git stay
in place. No in-place exchange, git clean/force checkout or guard transition.
All current worktree/index deltas, ignored/unversioned files and hardlinks
are retained in the old tree and the private backup. A registered current
origin is observed separately, not adopted as historical provenance.
Missing historical provenance, causes, owner/inode continuity and PIDs stay
UNKNOWN. Required index files/objects missing or unsupported deny.

The result is a READ-ONLY source view, not an updateable productive checkout.
RC5 additionally binds the **productive canonical index**, owner/mode/inode
and installed artifacts. That binding is not changed or satisfied by this
view. Lighting's 11-file deployment allowlist, target revision after its own
integration, user, write paths, backup/restore and public health still require
their own actual acceptance. No consumer is redirected, started or published.

## Writer and privilege boundary

The unchanged R6 trusted kernel/executor/tooling boundary applies. Ordinary
repository inode/namespace writers, including UID-zero with file rights but
without authority over the kernel/executor/backing device, are NOT trusted.
Read leases on every distinct regular input inode, held FDs, complete metadata
and inventory, ancestor identities and inotify detect break, mutation and ABA.
Existing writable handles, external hardlinks, mounts/special objects,
overflow, timeout or unstable inventory deny. No writer is signalled/paused.

This does NOT protect against an administrator/process modifying the kernel,
mounts, raw backing storage, interpreter/helpers or privileged reader. UID0
with CapEff=0 alone does **not** prove lack of raw-device or tooling access.
Actual actors, DAC/ACL/device access, namespace and executable integrity must
be proven during later protected Host preparation. Unknown delegation is a
blocker, never a blanket Root exception or Source-test Host acceptance.

The operator's Mac, signing key and authority directories are trusted and
outside Host repository writers' namespace. Client ancestor/custody integrity
and unchanged key must be independently checked before dispatch. Lost/moved/
restored authority state is not permission to recreate an unused slot.
Backups must never restore consumption to an earlier state; key rotation or
new slot requires a separate explicit decision, not a new Source freeze.

## Durable one-shot and create-only transition

Fixed slot `control-only-recovery-20261012-1`, independent of release names.
The trusted client writes BOTH exclusive spent records **before SSH launch**,
and BOTH signature reservations **before signing**. Authentication failure,
interruption, missing/partial copies, process/Host restart, lost result and
name reuse do not permit another dispatch, signature or retry.

The Ed25519 grant binds the actual live PID, fresh 32-byte nonce, boot hash,
machine hash, exact capsule, R6 Control/guard/quarantine endpoint objects and
every input/output ancestor. It cannot authorize a new executor. The Host
latch consumes before signature verification; any existing/foreign/partial
anchor denies. The first exclusive directory creation and immutable claim
consume the Host transaction; no automatic adoption, deletion or reset.

New files are anonymous O_TMPFILE inodes under real write leases, filled,
verified, exclusively linked and sealed before use. Namespace observation
begins before creation; a replaced directory cannot be normalised as owned.
Exact inventory/identity/content/security metadata is checked. Unknown files
remain intact and cause failure. Parent and file protections are applied only
to new owned objects, never historical paths or existing ancestors.

## Backup and tested return path

Private backup includes entire current Control, worktree/index/config/refs/
objects, symlink targets and opaque extra bytes. Held raw metadata includes
UID/GID/mode, POSIX access/default ACLs, xattrs, flags and hardlink groups.
Content-addressed files plus manifest are independently read back. A **real
logical restore from the read-back backup**, not original in-memory data, is
made in the private restore-test tree and checked before preparing the view.

Raw device/inode/ctime and ext4 extent/htree allocation are observations, not
physically restorable continuity. These two allocation flags alone are
excluded from logical flag equality. Protection flags, modes, ACLs, xattrs,
mtime, bytes, link targets and internal regular hardlink counts must match.
Unsupported metadata/features fail; no normalisation of historical objects.
FSGETXATTR also captures raw project/allocation fields; this version rejects
nonzero project IDs or extent/COW hints rather than silently losing them.
Atime effects from reading are expressly outside the unchanged claim.

No historical mutation occurs, therefore no rollback copies data over a
historical path or reinstates old markers. The tested return is append-only
client **revocation of eligibility of the new view**, retaining all Host
bytes/guards. Partial or failed revocation denies on EITHER marker. Before
acceptance every abort already leaves it ineligible. No consumer rollback is
claimed: no consumer was changed. A future consumer change needs a different
explicitly bound transition and tested return.

## Completion and provenance

The prepared receipt is written while input/preservation fences are active.
Application's complete preservation census (no semantic historical reread or
backup), guards, four exact historical evidence hashes and absent follow-up
markers are checked. Primary, Abort and Cleanup are separate and never
overwrite each other. Own FD limit is restored; no global limit changes.

`PREPARED_PENDING_CLEANUP` alone never accepts. After clean cleanup a separate
hash-bound completion is appended and CURRENT sealed release files, exact
inventory, ancestry, signature and pair are verified. A later cleanup error
still denies. The trusted client additionally needs the **received final
clean result**, exact grant/receipt binding, exit0 and durable matching
acceptance copies with neither revoked. An orphaned Host completion after
lost reply remains UNKNOWN/ineligible, not GREEN or permission to retry.

Host Git/strict fsck/status run as intended UID/GID1001, no index update or
historical Git subprocess. Main and origin/main are pinned and full target
commit/object provenance is carried so the unchanged canonical governance
script can perform ancestry checks. The actual Host instruction/global
Control context remains UNKNOWN: governance must genuinely pass in the new
CWD; missing/global path mismatch cannot be patched by invented instructions.

## Source verification boundary

Native fixture tests use a newly allocated private ext4 image, no network,
synthetic data/keys, Source read-only, no production credentials, historical
mounts, host-systemd socket or provider. Existing mandatory S8/S11/S12/R12/R15
CI gates remain unchanged. The previously blocked systemd investigation is
not repeated or repackaged here. A full mandatory CI and exact-SHA independent
review are required after new Source changes; historical GREEN is not reused
to accept these new bytes.

See `CONTROL_ONLY_RECOVERY_R1_LIVE_PLAN.txt` and the shared handoff delta.
