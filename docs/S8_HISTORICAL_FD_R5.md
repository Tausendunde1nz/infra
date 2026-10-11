# R5: process-local historical capture capacity

Source candidate; current Host acceptance remains UNKNOWN. R4 and its failed
Host attempt are immutable evidence, not superseded historical facts.

## Corrected capacity contract

The old operator rejected soft1024 before starting R4 (metadata planning7323,
not an observed Reader peak). R5 performs a bounded metadata-only census in
the actual dedicated, single-thread Reader before any historical protection
or content read. The census is NOT integrity acceptance.

The dedicated history-only entry explicitly selects this capacity context by
supplying its FD report. Existing in-process coordinator observations keep
their inherited limits and unchanged common capture. They may already hold
threaded kernel guards and are not dedicated Reader processes. No global
process limit change is permitted there; insufficient inherited resources
still fail through the original protected capture/cleanup, never via fallback.
The actual later S8 coordinator's inherited capacity remains a separate Host
prerequisite, not proved by the history-only low-softlimit result. Native full
provisioning must validate both distinct paths; a Reader admission error is
never caught and retried through the coordinator path.

Required soft limit = already-held FD high-water + every simultaneously held
Git inode + each duplicated ancestry/inotify chain + four Evidence descriptors
and lease watchers + both Git witness/lease watcher pairs + two mmap duplicate
FDs per possible simultaneously mapped pack + eight transient/cleanup FDs.
Pack/node bounds remain the object reader's64/65536 bounds. The eight-slot
reserve covers four initialization/transient handles and four independent
error/cleanup/readback handles; it is not a fixed bulk limit.

The Reader raises ONLY its own soft RLIMIT_NOFILE to that computed requirement,
within its unchanged inherited hard limit, then verifies the setting. No global
limits, PAM, sysctl, SSH or systemd configuration changes; no requested infinity,
fixed16384, hard-limit increase or unprotected fallback. Already sufficient
limits are left unchanged. Exact pre-existing descriptors and limits must be
restored after all historical guards close. Cleanup still attempts limit restore
if the FD baseline check fails. Primary, Abort and Cleanup remain separate;
resource errno is preserved without private OS messages.

The four Evidence inputs, five selected absent-marker witnesses and both Git
captures remain jointly protected through final acceptance. The observed FD
sample at the fully held aggregate is labelled as a sample, not the past peak.
Growth/resource exhaustion, loss, signals, drift and uncertain cleanup deny the
whole result. No split capture, retry, slot consumption or historical metadata
normalization is introduced.

## Exact offline scope

`tests/s8_historical_kernel_native.sh` retains the existing kernel/Git negatives
and adds real sudo -k -> frozen isolated supervisor -> GNU timeout -> isolated
stdin Reader integration over newly allocated synthetic ext4. Source is readonly,
network is disabled, no Host systemd socket or production credentials are bound.
Fixture substitutions only select synthetic historical paths/commit/tree/hash
values and synthetic public observations; authorization/kernel/metadata/FD
predicates and cleanup are not replaced by successes. Explicit low limits and
fault injection test hard denial, growth/actual EMFILE, interruption after75 real
leases, common capture and restoration. The invoking process's limits remain
unchanged. Component tests cover sparse/held FDs, set/readback/restore errors and
unknown output. Native CI and exact-SHA reviews must validate the final version.

## Later one protected Host read (NOT authorized by Source closure)

The separately pinned, pure history entry and minimal operator bundle are
rendered from the new immutable Freeze. Neither invokes installer, admission,
database or runtime. The operator independently checks machine binding, ext4,
CAP_LEASE, leases-enable, metadata/public baseline and hard-capacity admission;
only the Reader changes its own soft limit. close_fds, fixed environment and
isolated Python prohibit incidental inherited handles/imports.

Limits: census5s, common protected capture30s, own GNU timeout TERM40s + KILL5s,
supervisor wait55s; postchecks are independently bounded. Kernel-uninterruptible
I/O has no proven hard wall-clock bound. Unknown remaining own group, output,
metadata or cleanup stays RED; never signal a foreign process or relaunch.
Kernel read leases may temporarily block a competing Writer; any conflict or
signal denies capture. Pre/post service properties and HTTP must remain equal.

Host kernel functionality, current hard/soft limits, descriptor occupancy,
current HEAD/tree/Evidence aggregate, competing Writers and protection cleanup
remain UNKNOWN until the separate approved Host read. Historical owner/inode
continuity and causes remain UNKNOWN. The earlier changed S11 InvocationID is
an observation only; no cause or link to R4 is proven. New Invocation deltas
remain RED, not silently exempted as scheduled activity.

R15 pause compatibility OPEN. S9/S10/S11 RED are separate; all live/product,
Recovery, Deployment and Unlock gates remain CLOSED. A new Freeze is not a new
S8 admission slot and is not Host authority.
