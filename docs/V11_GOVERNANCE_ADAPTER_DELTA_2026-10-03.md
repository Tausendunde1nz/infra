# V11 Governance basis, systemd transport and watchdog delta — 2026-10-03

Status: **LIVE_NO_GO**. Infra base: `b1b2845c512f0df07cb38e796508cd83da1cb092`.
This is verified progress, not completion of the requested bootstrap/installer.
No root-validation readiness or production admission is asserted.

## Governance and authorized Control transition

The provenance repair was already merged externally as Control PR #73:
- merge `998b8c2321e5741b85a6e320930e24826d6a62d9`;
- tree `8384fc6f2a6d34fb5f4e9199735e0f66bac33213`;
- reviewed PR head `3e7d836b918447c0e504d8659411e8e72b64aeb3`;
- predecessor/merge-base `c13358d9adaf783f42feb5c627b6f12825f5805e`, ahead 3 / behind 0;
- exactly `AGENTS.md`, `governance/SUPERSEDED.json`, `governance/preflight.py`,
  `governance/test_preflight.py` changed.

The canonical v1.1 content is bound to PR #70 merge
`414ce1bba87f71016d3c72618d07784c6524b97f`, blob
`4c9fc8b70c2a76b08bf91ebc273349eea616c812`, SHA-256
`183b768a6bc8ff83ecd1679af09c878b692c7ee9a0ebf3257eaf6bf22ff07c90`.
26 governance tests and the actual Mac task-CWD preflight pass:
`GOVERNANCE_V1_1_ACTIVE`. GitHub exposed **no CI checks** for PR #73's head;
this is not evidence of green CI. No duplicate PR or merge was performed here.

The explicitly authorized clean fast-forward of `/opt/tu1nz_repos/control`
was executed to the four-file governance merge only, with hooks/fsmonitor
disabled and umask 077. No service was restarted. Private backup:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/governance-sync-20261003T055245Z`.
It contains original files/index, before/result manifests, transfer bundle and
`ROLLBACK.txt`. The conditional recovery uses a checked reverse `read-tree -m -u`
and compare-and-swap `update-ref --no-deref`; no reset-hard or untracked deletion.
The reverse operation has not been run on production. Inode/ctime recreation is
not promised by file restoration.

Post-sync tracked integrity is clean; index is UID/GID 1001, mode 0600,
no ACL/xattrs, inode 1459619, SHA-256
`4da50648a6283b717cefe9c7e8a77fff1dee1fff0342c0087bfaa841b5509b83`.
The five V11 baseline references were advanced under the existing adoption
contract. Control/main was subsequently observed at PR #74 merge
`265f126af7eac3f018950c0eb8908980d6d4c311`; its application changes were not
included in this governance-only sync. The late activation freeze must revalidate
current refs and cannot treat the adopted governance basis as a fresh freeze.

## Implemented and tested

`systemd_adapter.py` implements fixed-unit, fixed-action systemctl execution,
clean environment, option separation, timeout/nonzero/D-Bus error handling,
durable event callbacks and independent post-action observations. Loaded
configuration is compared separately; only execution history/order of set-like
properties is normalized. Failed or ambiguous actions close the fence. No
arbitrary shell command/unit is accepted. Self-stop is rejected using both
MainPID and actual cgroup membership, including helper descendants.

`watchdog.py` is embedded into the capsule. It independently evaluates leases,
boot identity, monotone progress, worker state and a bounded restart budget.
Worker/watchdog locks are separate; dispatch is recorded as queued, never as
completed. Unknown state, sealed failure or exhausted recovery becomes a durable
secured stop. No elapsed deadline opens the fence. Terminal outcomes are
independently rechecked. Watchdog source-state and event records are durable.

## Concrete remaining safety boundary

The outer publication rollback calls `quiesce_owned` / manager restore, which
stops the outer worker, and restores/removes the installed dispatcher artifacts.
When invoked from that worker, this can terminate the only recovery executor
before terminal verification; removing its executable also prevents restart.
The new adapter rejects that execution context **before mutations**.
Five regression cases cover self MainPID, helper cgroup, restore precheck,
cgroup descendants and malformed cgroup data. This is not resolved by another
sudo run or by a mocked successful manager response.

A separately pinned root recovery anchor outside the publication removal set,
with explicit boot lifetime and verified final cleanup/observer semantics, is
still required. It must be wired into the actual publication Manager protocol.
No permanent residual recovery unit may be silently called an exact rollback.
The bootstrap entry still refuses with
`INSTALLER_PUBLICATION_RECOVERY_NOT_VERIFIED`; publication remains fixture-only.
The outer forward-success fence release and inner production preseal binding
also remain uncompleted integration work. Existing guards remain closed.
Therefore bootstrap, full installer and the one bundled root-validator are NOT
finished. Root validation is NOT the only remaining task; no sudo/readiness
request is appropriate for this revision.

## Verification and preservation

Final isolated run: 2,385 targeted tests pass; all 108 workflow steps pass.
Workflows report 585 test cases, including exactly two permitted skips because
both Application checkout locations are absent. PR #68/#69/#72 regression:
35 + 7 + 10 tests pass; governance: 26 pass. Dispatcher group: 221 tests,
including 17 transport and 14 watchdog tests. The initial run preceded the
self-stop guard; the final run includes it.

All 42 hardening files, 701 historical tracked files, 1,125 private historical
file hashes and 30 root-only-v9 sources remain byte-identical. Integration
`1cf0d79` remains an ancestor. Docs index/authority pins remain unchanged.
Private results and pre-edit backups are under
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-completion-20261003`;
full final suite logs are under `/tmp/tu1nz-adapter-final-exrc5hal/results`.
No private raw evidence is committed. Aggregate result pins accompany this note.

No production V11 activation, token rotation, watchdog start, service/container,
Docker, group, sudoers, firewall, SSH or Tailscale change was performed. The
explicit four-file Control fast-forward above is the sole production checkout
change. No Infra PR or merge is part of this revision.
