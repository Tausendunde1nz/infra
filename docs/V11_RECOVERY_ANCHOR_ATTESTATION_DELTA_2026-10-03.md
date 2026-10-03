# V11 recovery anchor: attestation delta, 2026-10-03

**LIVE_NO_GO — tested partial offline integration.** Neither production
transaction nor root-validation launcher is activation-ready.

## Authority and preservation

Infra parent: `8fcd4aaacd6c497ff50e4964733c9e0350e3a781`.
Development uses an independent verified remote clone; the earlier worktree and
all 17 original uncommitted anchor files are retained byte-identically and
backed up. No development through production Control.

Control: `2281b2b397c017bc370ba108eab3dc00c989eaa5`;
tree `3d52fe0898238e1132d8947a7e171d8086982170`. The actual integration branch
is `main`. Verified same-repository PRs #74 and #75 are linear merges, 11
commits beyond `998b8c…`, changing six RC5/metadata-repair code, test and plan
paths. PR #74 uses an immutable private index snapshot; PR #75 limits inherited
mode normalization to new private checkpoint directories. Guard and governance
contracts are unchanged. Automatic supersession updates only offline pins.
Governance preflight on the verified clone with the actual Mac task CWD:
`GOVERNANCE_V1_1_ACTIVE`. Remote basis was freshly reverified from the Mac.

42 hardening, 701 tracked historical, 1,125 private historical and 30 root-only
source hashes passed. `1cf0d797ab025fb08466b92aed156ca5d7d63035` remains an
ancestor in authoritative Infra history. Historical evidence is not rewritten.

## Passive production classification

**UNRESOLVED_PRODUCTION_DRIFT**. Production Control Git remains root:root/0000.
Zero process references were visible without privilege; 10 unit-file references
exist. Root process visibility is incomplete. No actor, retirement or absence
of an external transaction is inferred.

Blocked-summary SHA-256:
`a189312a65d8e9816ebc8bbbf6ed296af8222c102e05d8929783118854bd8d13`.
Unchanged original: `/tmp/tu1nz-v11-authority-y6qov3d6/blocked-summary.json`.
Unchanged private copy and tests:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-offline-20261003T073605Z`.
Private raw evidence is not committed.

## Offline delta

The original retained anchor, A/B slots, scoped phase-0/phase-1 publication and
receipt rollback, fixed systemd adapter, watchdog scaffolding and
`ROLLED_BACK_WITH_RECOVERY_BASE` are preserved. The delta adds:

- Completion producer using the actual existing Guard hash-chained state store,
  independently verified artifacts and closed fence. Root-owned immutable
  context binds transaction, boot/generation, both baselines, Guard version and
  code/contract, artifact-map and activation-plan digests, base and worker pins.
- Atomic immutable attestation plus separate fsync commit receipt. Missing,
  inconsistent or uncommitted evidence cannot admit Bootstrap.
- Single-use consumption and exact resume. Bootstrap pins original snapshot
  and candidates; production phase-1 admission requires its matching receipt.
  Failure holds the closed fence and `SECURED_STOP`.
- Fourteen process interruption points around publication/fsync; replay,
  boot/generation/context, symlink/hardlink/mode/parent and contention tests.
- Import-inert, fixed-scope root-only Control audit draft: typed read-only Git
  queries, disabled optional locks/hooks/fsmonitor, null alternate index,
  metadata and hashes rather than payloads. It never repairs or unseals.

Fixture tests use the actual Guard state-chain implementation, not live Guard
execution. They do not confer production admission. Production capsules still
refuse execution before effects; root-validation rendering remains false.

## Concrete phase-contract blocker

Existing Guard reaches `COMPLETED` only after `SECURITY_BARRIER_SEALED`,
replacing and verifying the new consumer/authority. Its rollback rejects that
sealed state; interrupted postseal recovery yields `SECURED_STOP`.

An honest Guard completion attestation therefore cannot simultaneously be
required before phase 1 and prove full rollback of Guard changes assigned to
phase 1. Two tests demonstrate completion rollback refusal and interrupted-seal
stop. No fabricated early completion, weakened Postseal rule or silent business
migration into phase 0 was introduced.

Phase ownership, retained postseal recovery and phase-1 rollback scope must be
made consistent before production binding. Cross-boot revalidation/rebinding
also remains unbound: stale-boot rejection tests are not successful reboot
continuation proof. Independent outer-timeout cleanup proof is incomplete.

## Validation and remaining boundary

16 targeted groups: 2,512 cases passed, including 221 dispatcher and 127 anchor
cases, all original 78 retained. All 108 workflow steps returned zero; 585
reported cases with exactly two Application checks skipped because both
expected checkouts are absent. Current Control regression functions: 60 passed
by direct runpy with an exact three-case parameterization adapter, no omitted
cases or skips; pytest was not installed. Governance: 26 passed. Aggregate log
hashes and preservation results are in the adjacent JSON.

No sudo, root audit, installation, systemd call, service/container change, token
rotation, Control repair, permission/group/sudoers/socket/firewall/SSH/Tailscale
change, PR or merge occurred.

The future privileged audit must still establish protected HEAD/tree/index/
reflog/configuration, transactions and the sealing/removal mechanism. The draft
does not close those historical questions or constitute the complete bundled
launcher. No root command or MacBook-readiness request is issued while offline
integration blockers remain. Production restoration and activation stay
separately prohibited.
