# S11.2 access simulator: deterministic isolated fixture permissions

## Finding and scope

Step105 of Control validation failed deterministically twice, each time with120 tests and the same one error. The grouped shell returned1; its simulator child returned2. In simulator main(),2 is explicitly returned for ContractError, OSError or ValueError; it is not an argparse convention and does not by itself prove an access violation. Instrumented read-only diagnosis captured ContractError at the pre-matrix fixture check: `umask 077 did not produce source mode 0700`.

The source fixture is created with O_CREAT|O_EXCL, requested0777 and umask0077 beneath TMPDIR. The inherited Default ACL grants group rwx and mask rwx, producing0770. The real source/controller files were readable and complete. An ACL-free isolated control parent produced0700 and the original simulator passed all cases. No production path or parent ACL was normalized.

Before editing, simulator, calling test, controller, gate, units and manifest matched Git index, integrated HEAD and freshly fetched origin/control-main9bef420 byte-for-byte. The workflow differs solely by the already prepared Agentmode-v2 validation step. The simulator takes no arguments, resolves its repository root from __file__, and does not import the uncommitted Agentmode files. Both repeats use the same input hashes, cwd, interpreter and environment; only temporary fixture names differ. Python is /usr/bin/python3, version recorded verbatim in BEFORE.json. The new regressions also launch it from an unrelated cwd. Missing/unknown arguments, absent inputs, cwd and relative-path assumptions were excluded.

## Minimal correction

After writing its own newly created, open fixture, the simulator calls os.fchmod(handle.fileno(),0700). This pins access mode and ACL mask on that one synthetic inode. The existing exact0700 assertion remains; its error text now describes the actual invariant. No decision algorithm, expected allow/deny result, runtime source, unit, manifest or live permission changed.

Two regressions explicitly create an isolated parent with or without Default ACL. A probe first proves that uncorrected creation yields0770/0700 respectively. Both then execute the real simulator and require the complete exact outcome matrix. Before the fix, the inherited-ACL regression failed with2 and the ACL-free one passed. Both pass after the fix. ACL removal in tests applies only to their own private temporary parent.

## Decisions

| Case | Expected | Actual |
|---|---|---|
| Modeled runtime UID0, groups0/1001, source UID/GID1001 mode0700 | deny, RED_EXIT_126 | same |
| Modeled source owner UID1001, source0700 | allow | allow |
| Installed runtime0755 with exact SHA256 | allow | allow |
| Missing runtime | deny | deny |
| Runtime hash mismatch | deny | deny |
| Nonexecutable runtime0644 | deny | deny |
| Unit must reference installed runtime, not repository | dependency rejected | same |
| Installed one-shot launched without action | usage, no exit126 | same |
| Offline rollback of bytes/modes/absence | exact restore | same |

The first two are explicitly abstract mode-bit models, not a claim about Linux root capability bypass. Seven access/model/verification decisions are additionally recorded individually in INDIVIDUAL_CASES.json. Natural launch and rollback are exercised by the complete simulator in both ACL environments.

## Evidence and results

Private server evidence root: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/s112-diagnosis-20260927T081328Z`.

BEFORE.json and COMMAND.txt preserve exact shell argv/order, cwd, Python/version, shell, umask, environment variable names only, known temporary paths, input SHA256 and numeric modes/owners/groups/ACLs. EXTRA_INPUT_METADATA.json expands fixture/parent metadata. repeat-1/2.stdout/.stderr and REPEATS.json preserve both unchanged-input runs. EXCEPTION.json and fixture.acl capture cause. ACL_FREE_CASES.json, INDIVIDUAL_CASES.json and regression-before/after.log preserve expected/actual results. No environment secret values are included.

All S11.2 workflow steps105–107 PASS after correction. Extended discovery:144 tests,141 pass and3 pre-existing skips because the fixed external Application source checkout is absent. Those cross-repository cases are not represented as executed. The whole Control workflow then ran from step1: all107 runnable steps PASS (`full-suite-20260927T081513Z`). Agentmode targeted total28 remains PASS. Supplemental historical tests pass on their intended platforms:35 Linux and36 macOS. Mac evidence: `/Users/daniel/.codex/tu1nz-recovery/s112-tests-20260927T081938Z/mac-tests.log`.

Supplemental harness diagnostics are preserved: initially missing PDF fixture variable, then an old report date, then incomplete Python import paths, and the macOS-only caffeinate test on Linux. They were corrected solely by proper invocation, a new synthetic current-date fixture and the actual Mac platform. No historical file or assertion was edited for these setup issues; no real OAuth/API call was made.

## Backup and rollback

EDIT_BACKUP.json records original hashes, modes, ACLs and inodes. Original simulator/test bytes are saved as their basename plus .original in the evidence root. Restore only these two scoped edits after checking for subsequent changes, and remove this newly added diagnosis if reverting this candidate. Do not restore whole-worktree metadata or touch production. Agentmode-v2 backups are documented separately. No live rollback is required.

All42 original hardening files and historical install evidence remain byte-identical;1cf0d79 is retained; detached checkout is unchanged. This change does not activate Agentmode provisioning, alter Tailnet/Hetzner/SSH, restart services or modify MyChatBuddy. CI and PR merge remain a separate required gate.
