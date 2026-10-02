# V11 persistent Guard fence and recovery preparation — 2026-10-02

Base `9c8c9cbb93e5c273085c891ee229b6b4cd58e7b4`. GOVERNANCE_V1_1_ACTIVE.
**OFFLINE_COMPONENTS_TESTED; LIVE_NO_GO.** Nothing in this delta is installed.
The requested common production transaction is not yet complete. No root reader,
watchdog, service, container, token or network operation was activated.

## Persistent fence and boot topology

`scripts/v11_guard_recovery` adds standalone, embedded standard-library runtime
code intended for `/usr/local/libexec/tu1nz-v11-guard-recovery/runtime.py` (root:root
0600), isolated Python `-I -B`, and root:root 0700 state at
`/var/lib/tu1nz-v11-guard-recovery`. Immutable 0400 intent/state generations carry
checksums, predecessor hashes, transaction/boot/process identities, monotonic
deadline and contract pin. A fsynced immutable SEALED latch precedes the sealed
phase generation. A crash between these publications cannot reopen legacy access.
STOP takes precedence; missing/corrupt/unknown state denies starts. Short flock
sections serialize state readers/writers; the condition opens its lock read-only
so ProtectSystem=strict does not itself cause a write failure.

The Guard drop-in installs a fixed ExecCondition. It checks protected ancestor
paths, owner/mode/ACL/link count, payload and exact unit bytes, loaded ExecStart,
ExecCondition and dependencies. Legacy is allowed only before arm or after a
verified preseal rollback; UNARMED already denies starts. New access requires the
NEW_CONSUMER_VERIFIED record to match the consumer, authority and loaded unit pins.
A second descriptor walk detects pathname replacement after a read. This covers
starts through the **service unit**, including timer/manual/dependency/boot starts.
It does not claim to prevent an arbitrary already-privileged root process from
executing the old script directly outside systemd.

`tu1nz-v11-guard-recovery.service` is an early oneshot, After=local-fs.target,
Before=timers.target and Guard service/timer, WantedBy=sysinit.target. Both Guard
units Require and follow recovery. The independent watchdog is a separate root
service, Requires/After recovery, Restart=on-failure, WantedBy=multi-user.target.
A private heartbeat proves its distinct PID/start ticks, boot/transaction/pin,
monotonic freshness, state write and fixed D-Bus access before seal. Neither runtime
imports the productive checkout. The sandbox permits only fixed state writes;
commands are closed allowlists. Failed recovery blocks dependent starts, while the
persistent ExecCondition still denies unsafe starts independently of watchdog liveness.

Actual `systemd-analyze --root=<isolated fixture> --man=no verify` passed using the
installed distribution's target units. Deliberate ordering cycles and a missing
fixed executable failed as expected. No system manager reload or live unit start
was performed. This validates topology, not runtime privileges in production.

The new Guard unit candidate needs CAP_CHOWN in addition to CAP_DAC_READ_SEARCH:
its existing fixed publisher sets root:chatops ownership on the status file.
The candidate still has strict filesystem confinement. Only the candidate builder
changed; the historical unit and installed unit are untouched.

## Cutover ordering and recovery matrix

The coordinator performs preflight and originals backup; installs fence/recovery
candidates; reloads and verifies loaded definitions; enables/starts recovery and
watchdog and checks the heartbeat; publishes UNARMED; drains any already-admitted
legacy invocation; arms the fence; proves a controlled service start does not
execute ExecMain; publishes the SEALED latch/state; stops the timer; installs new
consumer/authority/unit/checksum; reloads and verifies; runs the fixed new consumer
directly; verifies its protected result; publishes NEW_CONSUMER_VERIFIED; restores
the timer; verifies again; publishes COMPLETED. Every event requires 300 seconds of
remaining monotonic recovery margin. A direct fixed probe avoids circularly granting
service admission before the first verified result exists.

| Crash interval | Current implemented decision | Remaining admission condition |
| --- | --- | --- |
| Before/during fence installation or reload | Coordinator can restore owned verified postimages; independent dispatcher stops closed | Durable receipt hydration and unattended exact rollback are not connected |
| Fence loaded, unarmed or armed but unsealed | Legacy denied until verified rollback; unknown originals remain denied | Same preseal rollback integration requirement |
| SEALED latch/state, timer still active | Persistent condition denies legacy; dispatcher records STOP and requests timer stop | Shared host dispatcher must preserve this barrier |
| Timer stopped or any consumer partly replaced | SECURED_STOP; never restore legacy authority | Optional forward installation is not falsely claimed |
| New bytes installed but not verified | SECURED_STOP | New verification required before any admission |
| NEW_CONSUMER_VERIFIED before/after timer start | Revalidate bytes, unit and proof pins; probe/status; restore timer; COMPLETED or STOP | Real host admission still blocked |
| COMPLETED | Revalidate installed binding without replaying mutations | No transaction restart |
| Corrupt/missing journal or foreign postimage | Persistent denial / SECURED_STOP | Do not infer original integrity |

Exact preseal cleanup is **not** claimed for an interruption between file replacement
and durable postimage receipt, or partway through support-unit cleanup. Unknown
ownership refuses restoration. The independent dispatcher currently takes the safe
STOP path instead of reconstructing all original files. This is a remaining recovery
requirement, distinct from the now-modeled persistent post-seal start fence.

The concrete file backend refuses foreign byte, inode, mode and timestamp changes,
even when hashes still match. Verified restored postimages are idempotent. Atomic
replacement restores content/ownership/mode and supported times, not old inode/ctime.
No parent ACL or live metadata was modified.

## Common host progress and remaining phases

A new standalone Agentmode root prologue in `scripts/v11_host/agentmode_claim.py`
binds a one-use START_INTENT to boot, transaction, deadline, fixed source/unit hashes,
actual systemd InvocationID/ControlPID and the service cgroup. It publishes the claim
atomically before main admission; wrong identity, duplicate use or failed fsync refuses.
It is tested preparation, **not yet installed or wired into the unit/transaction**.
The productive Agentmode was not started.

| V11 part | Status after this delta |
| --- | --- |
| Shared backup / original pins | Fixed Guard receipts implemented; shared cross-phase restoration not complete |
| Dedicated Control Gitdir | Existing e60aa2f candidate adapter retained; new live baseline drift blocks binding |
| Docs authority | Independent 883-file authority unchanged; candidate included in Guard contract |
| Delete Guard / checksum | Persistent fence, unit topology and ordered concrete adapter prepared; unattended preseal restoration remains open |
| emoji_map.sed | Existing sealed-descriptor component retained; common consumer installation not complete |
| Mommyramona | Closed Case-A semantic network contract retained; full production lifecycle composition still open |
| Agentmode | New single-use root claim added; prologue/unit/journal handoff and 660-second host validation not complete |
| Broker / bootstrap | Existing bounded components retained; common installer and root capsule wiring open |
| sudo / Docker rights | Four protected originals unread; no candidate originals invented |
| Trendwatch hardening | Existing transformations retained; dedicated output/consumer ordering not fully bound |
| Token rotation | Existing forward-only barrier retained; provider/consumer handoff not fully bound |
| Final verification | Component and workflow tests pass; not an end-to-end host transaction proof |

The old V9 host was reviewed as reference only and was not executed or imported.
Its paths, state and recovery semantics cannot silently stand in for a V11 host.
No readiness request is appropriate: the four protected files are not the sole gap.

## Validation and scope of evidence

- 1,945 targeted tests passed: previous 726 + 1,201 Guard tests + 18 Agentmode claim tests.
- The Guard count includes 1,160 model cases: 29 coordinator events × two edges ×
  20 fault labels. They exercise real state/coordinator/fence/recovery logic with a
  modeled host; they are not 1,160 actual reboots or root service executions.
- All 108 workflow run blocks passed sequentially from step 1 in a fresh isolated clone.
- Two existing optional application tests remain skipped; paired checkout absence
  was checked at canonical/worktree and isolated locations.
- All 35 original PR #68 functions passed unchanged from the pinned e60aa2f archive.
- All 42 Hardening files, 701 historical tracked files, 1,125 private evidence files
  and 30 V9 sources remain byte-identical; 1cf0d79 remains an ancestor. Docs index and
  the independent Docs authority are unchanged. Historical records were not rewritten.

The JSON companion pins the exact tested sources, generated payloads and private
results. Private artifacts/backups remain under
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-fence-20261002` (not committed).
No activation CLI or sudo command is supplied. No PR/merge is requested.

## Newly observed baseline blocker

The final preservation check at 2026-10-02T18:18Z found the detached productive
Control checkout at `05b127033d734aa4abce10b2e5b7d513b99ed5d2`, tree
`5459b09c4f986ac947dff1466b490a61238cb676`, rather than the expressly accepted e60aa2f.
It is eleven commits ahead, zero behind, merge-base e60aa2f. Seven paths differ:
four governance documents and three MyChatBuddy state-metadata-repair artifacts.
The tracked diff is clean. Index remains chatops:chatops 0600, regular/nlink 1, but
inode is now 1460594 and SHA-256
`7c5fd653decbfa3a3c89ad00662245ea0147c51e93c7b1a20cb825d6c86cced3`.
It stayed stable during the bounded follow-up. Index mtime is 17:25:33Z and ctime
17:30:52Z. No actor is attributed: UNATTRIBUTED_CHECKOUT_UPDATE.

This work issued no production checkout/index mutation. **It is therefore false to
claim that the productive baseline remained unchanged.** The authorized e60aa2f pins
were not silently advanced and no historical checkout was restored. Admission is
blocked on explicit reconciliation of this new source delta as well as the remaining
composition requirements. No further broad inventory or privileged read was started.
