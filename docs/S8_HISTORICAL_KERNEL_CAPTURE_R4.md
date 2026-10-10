# Historical read R4 — kernel-excluded capture, source candidate

## Required claim and capture boundary

The claim is **current** HEAD equals the incident-pinned commit, that commit's
raw bytes hash to its object ID and name the pinned tree, and the raw tree
bytes hash to the pinned tree ID. Four independently fixed historical evidence
payloads must match their existing SHA256 digests. The `.git` barriers remain
closed. This does not attest the live worktree, every transitive blob, previous
owners/inodes, a predecessor chain, historical writers/PIDs or the incident's
cause. Those historical gaps remain UNKNOWN; no current metadata is adopted as
a historical baseline. Repository HEAD/tree on the real host remain UNVERIFIED.

The inputs include all existing real-Git nodes, configuration, HEAD/references,
loose/pack/index object dependencies, the fixed commit/tree and four evidence
files. No basename exclusion for `ORIG_HEAD`/`branches`. Config includes,
alternates, shallow/promisor fetching and external transports are refused.

## Smallest change selected

Retain the bounded whole-tree/ancestry inotify witness and exact object hashes.
Add a held **kernel read lease on every regular Git input**, acquired before
content use. The same lease-and-inode-watch protection is also mandatory for
each of the four fixed evidence files. One common 30-second acceptance deadline
covers both repositories, all four evidence files and five absent-marker
witnesses. Checks deny expiry; kernel-stalled I/O is not promised to terminate
within that time, and may never produce accepted evidence. The leases are
retained until the capture is checked and closed. Linux denies
this claim if a writable open-file description remains, including a shared
writable mapping after its original FD closes. Future write/truncate opens
break the lease before proceeding; pending break/expiry/owner loss denies the
capture. Directory/ACL/metadata/rename/creation operations remain covered by
inode/ancestor watches and fingerprints, including retained directory handles.
Loss, overflow, unsupported filesystem and interruption deny the result.

HEAD and SHA-1 loose/pack-v2-index objects are decoded inside the already
non-dumpable reader process, using only its held inputs. There is no external
Git child, fallback, include/config execution or provider access. This avoids
a same-UID child-ptrace assumption. Bounds are 4 MiB per decoded object,
256 MiB per pack, 32 MiB per index, 100000 objects per pack, 64 packs and delta
depth 50. Pack/index digests, fanout, ordering, offsets, per-read CRC and object
identities are checked; unsupported or incomplete formats fail closed.
The [Git pack format](https://git-scm.com/docs/gitformat-pack) defines the
representations; synthetic parser tests and native Git-generated packs must
independently cover their use in the actual protected reader.

This closes the specific ordinary-mapping gap of event-only R3 capture without
changing historical mode/ACL/owner/flags, pausing processes or provisioning an
on-host copy. A copy/hash alone was rejected as a coherent-capture proof.
`immutable` alone was rejected as general held-handle revocation; existing
counterevidence is retained. Whole-filesystem freeze was rejected because its
database/service/lease effects are unnecessary for this read problem.

Current observed descendant profiles can only be read within that active
whole-input witness, not by a group/ACL/UID exemption: known ACL layout and
mask, owners/groups, xattrs/defaults, regular/directory types and single-linked
regular files remain checked. The strict new-stock and historical ancestry/
guard predicates do not change. No loose historical inode binding is invented.

The accepted interval begins only after every input has been inventoried,
watched and all regular inputs claimed, and ends with final lease, namespace,
metadata and object checks. The result attests that completed interval, not
permanent source immutability after descriptor closure or a reusable admission
ticket. Each canonical precondition does a fresh capture; no partially read
capture resumes. The fixed S8 slot and all independent attempt/marker checks
remain mandatory; read replay creates neither a start nor an attempt allowance.

## Writer and privilege boundary

Cover ordinary UID1001/ACL writers, retained writer FDs, shared mappings,
directory FDs and ordinary UID0 file writers. No Root-account trust exception.
The existing kernel TCB remains necessary: kernel/raw-device modification,
privileged ptrace/FD takeover and mount replacement are not promises this
userspace reader can make safe against an unconstrained kernel administrator.
That is separate from the accepted administrative **systemd** model, which is
not extended to repository writers. Current host delegated rights remain UNKNOWN.

Only native ext4 is admitted in R4; overlay/NFS alias/lease semantics are not
inferred from the isolated ext4 proof. Same-inode ext4 aliases share the kernel
lease. The owned reader thread reserves a thread-directed real-time signal;
break indications remain blocked/latched, including delayed notifications.
No signals, resets or stop operations are sent to writers. Cleanup closes each
owned descriptor once and preserves Primary/Abort/Cleanup separately.

Kernel API basis: [Linux generic file leases](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/locks.c)
uses conflict checks before and after insertion; GETLEASE reports pending
release, not healthy admission. This is a source/API basis, not a host-kernel
acceptance. Native regressions must verify the deployed platform separately.

## Future host plan — not executed or authorized here

No permanent host path, owner/group/mode/ACL/flag or systemd change is needed
by this selected reader. No historical backup is restored or normalized.
The complete existing S8 provisioning/start plan remains separately gated.
The additional host check is one protected R4 historical read in its own
bounded, frozen-source Python process, with sufficient read-lease authority
(file ownership or CAP_LEASE), descriptor capacity and native ext4 inputs.
No productive credentials/output contents are logged.

Lease acquisition does not alter bytes but can temporarily delay a **new**
writer's blocking open. An existing writer/mapping makes the read RED; a new
conflicting open makes it RED and closes the leases, rather than pausing/killing
or waiting for that writer to become acceptable. Runtime PostgreSQL leases are
not modified. Maximum reader lifetime, observed host kernel/capabilities,
readback of private result/evidence and exact freeze bindings are preconditions.
No duration promise is inferred from small fixtures. Access/busy/unsupported,
change/inconsistency, incomplete objects and cleanup errors remain distinct.

Local native aarch64 ext4 candidate: 35/35 tests passed with no skip, including
separate UID1001 and UID0/capability-free retained FD/shared-map writers,
read-only aliases, common evidence/marker capture, Git-generated packed
commit/tree identities, synthetic OFS/REF deltas and interrupted cleanup.
Portable selection before the cleanup correction: 66 tests, 18 native-only
skips; this is not native acceptance.
An earlier four-case feasibility run had three passes and one non-reproduced
immutable-only comparison (ext4 ftruncate returned EPERM); its RED output is
retained privately, not relabelled GREEN or used as this lease proof. Earlier
overlay counterevidence remains unchanged. Mandatory amd64/native integration
and exact final-source closure remain necessary.

A subsequent synthetic double-mapping-cleanup fault exposed a dropped
secondary error in the decoder's ExitStack cleanup. That counterproof is
retained. Independent per-mapping cleanup now preserves every failure and the
original primary; a closed store/failed witness cannot resume. The earlier
35-test proof does not accept this correction. Fresh local native ext4 proof
passed 37/37 with no skips, and the corrected portable selection passed 68
tests with 18 native-only skips. Complete final-source CI/review remains
mandatory; the superseded first CI was deliberately cancelled, not GREEN.

R3 and earlier freezes/counterproofs remain unchanged. Native tests, mandatory
CI, exact-SHA independent reviews, merges/post-merge CI and R4 freeze are OPEN
until recorded for the final source. This candidate is not live acceptance.
R15 pause compatibility OPEN; Live/R15 NO-GO; S9/S10/S11/product gates unchanged.
