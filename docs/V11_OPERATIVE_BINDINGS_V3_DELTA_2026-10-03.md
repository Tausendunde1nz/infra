# V11 operative bindings v3 — isolated preparation, no activation

Base: `b9fac72d94a0ddf7f1788131f9289f4a2844b6b7`. Control remains exactly
`2281b2b397c017bc370ba108eab3dc00c989eaa5`, tree
`3d52fe0898238e1132d8947a7e171d8086982170`; remote rechecked.

## Meaningful changes

Fixed state/action/successor mapping now separates `PRESEAL_WORKER`,
`POSTSEAL_FORWARD_WORKER`, and `SECURED_STOP_WORKER`. Each entry revalidates
transaction, recovery generation, complete context, artifact manifest, retained
base and selected slot under the same anchor/Guard lock. A wrong worker or
replayed context refuses before mutation. Worker execution uses the pinned
interpreter and source inodes via open FDs. The parent independently reads
artifact bytes/metadata, loaded systemd state, fence and durable attestations;
a successful exit alone grants no completion.

The internal systemd action IDs map to constant argv with `--` separators.
The concrete isolated Bootstrap/Installer uses the checked adapter; stored
unit snapshots and loaded manager properties are read separately, including
configured Exec/dependencies. Transport timeout, rc=0 with wrong poststate,
foreign reload and active consumer all refuse closed.

Cleanup lives in the retained phase-0 capsule. Verified unsealed state permits
exact publication/metadata/manager rollback while retaining the anchor/slot.
Verified sealed state permits only inode-bound staging cleanup and forward
continuation; unknown or sticky stop permits no directional cleanup. A legacy
stop is not bypassed. The outer validation reset is a separate operation on
newly owned **test-only** objects, never a production authority rollback.

## State ownership and recovery

| Durable state | Owner | Safe successor |
|---|---|---|
| PHASE0_VERIFIED | phase-0 Install + retained anchor | publish Phase1A or retain closed base |
| PHASE1_PUBLISHED_FENCED | fixed Installer + preseal worker | PRESEAL_READY or exact rollback |
| PRESEAL_READY | preseal worker | durable SEAL_INTENT or exact rollback |
| SEAL_INTENT | boundary engine under both locks | fresh objective unsealed rollback / sealed forward / unknown stop |
| SEALED | forward worker | POSTSEAL_COMPLETE or SECURED_STOP_SEALED |
| POSTSEAL_COMPLETE | retained anchor + read-only parent verifier | independently verified completion |
| ROLLED_BACK_WITH_RECOVERY_BASE | retained anchor + cleanup | idempotent verification, closed fence |
| SECURED_STOP_SEALED / SECURED_STOP_SEAL_UNKNOWN | stop worker + retained anchor | retain evidence and inactive consumers; no timed reopening |

The split phase-1 installer admits only the literal concrete root-validation
factory. The isolated factory uses real root file publication/rollback,
independent systemd observations and the durable Guard state engine. Its
isolated authority marker is a **test contract**; it is not proof of production
permission/token migration. Production capsules and the productive factory
remain closed. This commit does not claim live activation readiness.

## One prepared root-validation path

Stage A requires a pinned official `Adult Publishing S12.1-R9` handoff receipt,
then reads HEAD/tree/index, metadata/ACL contract, locks and active writer FDs.
No receipt means `WAITING_FOR_CONTROL_HANDOFF` **before effects**. No Control
repair, unlock, metadata adoption or privileged causal investigation exists.
A different Control descendant requires the existing explicit supersession
contract; no blanket descendant acceptance.

Stage B contains the prior real phase-0/A-B/anchor-kill matrix plus concrete
preseal, postseal and unknown-seal cases. Each direction is invoked in a fresh
pinned process, reverified, then cleanup is invoked again for idempotence.
A separate guardian retains the publisher pidfd and receives directly spawned
worker pidfds over an inherited private socket before the startup pipe opens.
It survives publisher death, terminates registered private worker sessions,
and only then restores the exact original test file/unit prestate from
inode-bound publication receipts. A timeout uses a monotonic clock; unknown
ownership/drift fails cleanup rather than removing another actor's objects.

The private root-copy bootstrap is checksum-bound and compiled; nonroot denial
was tested. It refuses pending handoff before creating its root-copy namespace.
When later rebound to an approved receipt, it copies verified bytes to fresh
`0700 root:root` storage, verifies a `0400 root:root` source FD and the interpreter
pin, then executes with `-I -B`. No command has been disclosed or executed.

Root validation has **not** run. Fresh-process continuation tests are not an
actual host reboot. The 1200-second independent bound is per isolated stage;
all test paths/units use fixed `tu1nz-v11-*-validation` names. No productive
migration, service/container change or permission/token reversal is included.

## Verified offline end state

One final complete run: 2624 V11 cases; all 108 workflow steps (585 reported
cases), exactly two Application skips because both checkouts were absent before
and after; 60 current Control regression cases; 26 Governance cases. No failure.
Totals are reported executions, including overlaps and the two allowed skips,
not a claim of 3295 unique tests. Added integration coverage includes wrong
worker, context replay, false systemd success, stored/loaded drift, directional
cleanup, sticky stop, missing attestation, crash/timeout/reboot entry, exclusive
locks and independent guardian/pidfd cleanup.

Hashsets 42/701/1125/30 and the 17 original files are byte-identical. Original
17 modes and inodes are unchanged. `1cf0d79` remains an ancestor. A comparison
initially treated an octal-string source mode as an integer; explicit parsing
confirmed no source or metadata drift. Historical records were not rewritten.

## Remaining gate

`CONTROL_HANDOFF_PENDING` → `LIVE_NO_GO / WAITING_FOR_CONTROL_HANDOFF`.
Official owning-block completion must cover clean chatops checkout, HEAD/tree,
index/metadata/ACL, no locks/writers, terminal guard/recovery, no unintended RC5
activation and no unresolved content drift. V11 does not perform that recovery.
Only after accepted handoff and a freshly rebound launcher is Daniel asked once
for MacBook availability for isolated root validation. Production admission
requires its own verified authority/permission binding and is still closed.

No sudo/root run, live configuration, watchdog activation, service/container,
network, firewall, SSH, Tailscale, token or detached-checkout change occurred.
No PR or merge. Private originals, rollback metadata and launcher artifacts
remain outside Git. JSON beside this document carries pins and compressed
validation results.
