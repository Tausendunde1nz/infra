# V11 pre-seal/post-seal boundary v2 — 2026-10-03

**LIVE_NO_GO. Tested offline directional model and file/Guard integration.**
The prior full-rollback-after-seal requirement is superseded by the current
explicit user contract; previous reports remain unchanged historical evidence.
Root validation and the production unified transaction are not ready.

## Binding and durable states

Infra parent: `cd4a10320fe935fd615570a3e90d3fa6127c0fa5`.
Control: `2281b2b397c017bc370ba108eab3dc00c989eaa5`, tree
`3d52fe0898238e1132d8947a7e171d8086982170`.
Verified separate clones only. Preflight with actual Mac task CWD:
`GOVERNANCE_V1_1_ACTIVE`.

New `seal_boundary.py` freezes a root-store-compatible context binding transaction,
origin boot, recovery generation, Control/Infra, Guard version/code/contract,
artifact-map and candidate-plan digests, retained base and approved worker pins.
Original receipts, sources and historical completion attestation remain.

Three immutable linked attestations: `PRESEAL_READY`, `SEALED`,
`POSTSEAL_COMPLETE`. Each has a separate immutable fsync commit receipt.
`SEAL_INTENT` is written after verified PRESEAL_READY; file and parent fsync plus
the commit receipt are validated before the barrier action. Intent never proves
actual seal. Existing data must match exactly; no overwrite or rebind.

## Direction contract

| Fresh objective evidence | Allowed recovery |
|---|---|
| Verified unsealed; no intent | Exact pre-seal rollback |
| Valid PRESEAL_READY; no intent | Controlled prepare/run or pre-seal rollback |
| Valid durable intent; verified unsealed | Pre-seal rollback |
| Valid intent; verified sealed without outer SEALED receipt | Verified forward repair |
| Valid SEALED | Forward repair only |
| Valid POSTSEAL_COMPLETE | Reverify target; no replayed installation |
| Unknown/conflicting boundary or corrupt binding | SECURED_STOP_SEAL_UNKNOWN |
| Verified sealed but forward repair/check fails | SECURED_STOP_SEALED |

Invalid or incompletely durable intent/attestation does not silently become
authorization. Such cases may stop even when a journal suggests an earlier
phase. A root-store path replacement fails before mutation; if the trusted
pathname itself is unusable, no new durable stop receipt is claimed.

The objective adapter reads the existing immutable Guard SEALED marker and
checks its binding, inode/path, ownership/mode/ACL/link protections. Absence must
be corroborated by an independent original-authority/start-fence audit; journal
status alone is insufficient. Fresh observations are checked again under the
same outer-anchor then Guard-writer lock. Reboot changes the fresh observation
boot, not the immutable transaction/generation. Timeout calls this same
classifier; elapsed time cannot choose a direction.

## Bootstrap/installer delta

`split_guard.py` splits the existing Guard coordinator immediately before its
barrier. Pre-seal prepares and verifies the fence, watchdog and blocked legacy
start. Post-seal advances only through owned postimages/new-consumer verification.
An interrupted or unreadable Guard generation refuses repair and stops sealed.

The split installer composes the actual file publication engine with this
Guard bridge. Candidate bytes, original snapshot and activation-plan digest
must match before publication. A practical shadow roundtrip of the publication
engine provides the offline rollback test. The isolated integrated tests prove
exact original-byte restoration while phase 0 and worker A remain, and prove
that sealed forward completion/failure never restores old originals.

The old publication rollback now requires the directional adapter and its
lock whenever a new boundary context exists. Both the journal seal flag and
the fresh objective classifier prevent rollback. Historical completion-based
Bootstrap admission is disabled outside historical non-root fixtures.
The retained anchor refuses directional contexts until its fixed directional
worker transport is bound; it cannot accidentally dispatch the old rollback
worker. Production constructors refuse before any action.

## What the tests prove, and what they do not

New 60-case matrix includes real process deaths around ready/intent/sealed/
complete publication and fsync, four deaths inside actual Guard-latch
publication, missing/invalid receipts, intent with unsealed/sealed/unknown
markers, marker contradictions, fresh reboot observation, pre/post timeout,
concurrent lock contention, idempotent rollback/completion, manifest drift,
path substitution, symlinks, hardlinks and accidental old rollback calls.

The Guard state store and isolated filesystem publication are real. Host
service/permission/consumer observations are controlled fixtures, not production
migration or real root/systemd execution. Therefore COMPLETE in these tests is
a model result; it is not evidence of the final production V11 target.

The one final complete offline suite passed: 2,572 targeted cases, including
187 anchor cases/all original 78, and 108 workflow steps with 585 reported
cases. Exactly two Application checks skipped: both expected checkouts absent.
Current Control: 60 regression cases by direct runpy execution with exact
parameterization adapter (no omitted cases/skips; pytest not installed).
Governance: 26 tests. Result hashes are in the adjacent JSON.

42/701/1,125/30 historical hash sets and the 17 old anchor originals/private
backup copies remain byte-identical; old anchor inodes are unchanged.
`1cf0d797ab025fb08466b92aed156ca5d7d63035` remains an authoritative Infra
ancestor. New edits affect only the independent clone's versioned copies.

## Remaining root/integration boundary

The old postseal/full-rollback contradiction is resolved. Remaining work is
concrete and separate: fixed production observer/forward adapter, directional
retained-worker transport, isolated directional root profile, and independently
surviving outer-timeout cleanup. The root artifact builder still emits
`root_validation_ready=false` and exits before effects. A complete bundled
root validation command has not been issued or claimed ready.

The later root run must first audit protected production Control metadata and
the unclassified sealing/removal mechanism without repair. It must then test
isolated pre-seal rollback and post-seal forward/stop paths plus independent
cleanup. Production Control remains UNRESOLVED_PRODUCTION_DRIFT and untouched.
No MacBook-readiness request is made while offline bindings remain.

Private backups/logs:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-seal-boundary-20261003T081023Z`.
No raw private evidence is committed. No sudo, production service/container/
configuration change, token action, Control repair, PR or merge.
