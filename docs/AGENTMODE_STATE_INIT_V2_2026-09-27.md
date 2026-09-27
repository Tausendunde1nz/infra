# Agentmode state initialization v2 — candidate, not activated

Status: all 107 Control validation steps PASS; 28 Agentmode/maintenance tests PASS; existing production state root and integrity validate unchanged. Repository-only candidate ready for PR/CI. Earlier stop records below are retained as history and superseded by the final validation section.

## Exact contract

The failing M4.29.2 test expects the freshly created isolated `runtime-state` directory to be exactly0750. The production `/var/lib/tausendunde1nz/agentmode` directory is chatops:chatops2750. The access bits are identically rwxr-x---; production setgid additionally preserves the chatops group on newly created entries. The isolated test profile has no setgid requirement. Neither expectation was relaxed to0770. A separate regression demands2750 when setgid is selected.

Production state root: UID/GID resolved from chatops (observed1001:1001), mode2750. Access ACL: user::rwx,user:1001:rwx,group::r-x,group:1001:r-x,mask::r-x,other::---. Default ACL: user::rwx,user:1001:rwx,group::r-x,group:1001:r-x,mask::rwx,other::---. The default named user is the directory owner; the mask does not independently grant group write. Both group entries are read/search only. This exact deployed profile is validated without changing it.

Fixture root: current UID/GID, mode0750. Explicit Access and Default ACLs are owner rwx, group r-x, mask r-x, other---. New objects are first created0700, then their inherited ACL entries are checked before setting the exact profile and mode through an opened directory descriptor.

Known state files: control_update_state.json, last_sync.ok, docs-checksums.txt, notification_state, monitor_last.txt. Expected regular file, same UID/GID as state root, exactly0640, no unknown named ACL principals, no effective group write, no Default ACL. No existing file is changed by this stage. Existing objects with unexpected metadata abort; no automatic repair.

Historical references remain unchanged: `scripts/tu1nz_sync_all.sh` SHA25696a03614f5c5eacc94576975a7d38251b5cc3da7c673a690914942b298d359df and its existing M4.29.2 artifact/install evidence. The new stage must provision state before first observation; the historical mkdir fallback is not represented as newly hardened. No automatic installation or service wiring was added.

## Allowed shared paths — outside provisioning scope

| Path relative to /var/log/tausendunde1nz | Owner:group | Mode | Basis |
| --- | --- | --- | --- |
| ape-approval/ingress/inbox | tu1nz-ape-broker:tu1nz-ape-notify |2770| Consumer rename from inbox |
| ape-approval/ingress/staging/.producer.lock | tu1nz-ape-broker:tu1nz-ape-notify |0660| Producer and consumer O_RDWR/flock |
| ape-approval-notifier-state | root:tu1nz-ape-notify |2770| Notifier temp/create/replace/unlink |
| ape-approval/ingress/staging | tu1nz-ape-broker:tu1nz-ape-notify |2770| Preserve current exact broker contract; not claimed minimal |

No shared-write exception applies anywhere beneath the Agentmode state root. The matrix confers no mutation capability. Correction to earlier ACL review: UID993 is broker/GID982; UID994 is notifier/GID983. Both dedicated accounts use nologin.

## Implementation and rollback

New script `scripts/tu1nz_agentmode_state_init_v2.py`: CLI permits only the fixed production path, --check is read-only, --create refuses a different execution identity. Fixture entrypoint is restricted to runtime-state below a private0700 parent. All parent components are opened without following symlinks. New directory identity is pinned; ACL operations use its open FD. Existing targets are validated, never normalized. On failure only the same newly created empty inode may be removed; changed identity or concurrent contents prevent removal. No recursive cleanup, chown, service command or Approval path write.

Before edits, affected existing files were backed up with metadata and SHA256 under `/opt/tu1nz_repos/network-hardening-private-2026-09-22/agentmode-v2-20260927T071744Z`. Repository rollback is limited to restoring those exact backed-up files and removing only the new candidate files after checking for later edits. No live rollback is needed because no live mutation occurred.

## Explicit integrity profile

`/var/lib/tausendunde1nz/agentmode/integrity` is the output directory of the unchanged `scripts/tu1nz_integrity_consolidation.sh`. `systemd/tu1nz_integrity.service` specifies User=chatops, Group=chatops, UMask0027 and read-only Control/Docs paths. The script first requires a fresh sync marker, hashes tracked Control files and Docs PDFs, records the Control HEAD/tree/refs and writes a transition-aware notification marker. It does not modify Control.

Permanent contents are exactly `control-checksums.txt`, `docs-checksums.txt`, `integrity_state.json`, `notification_state`. These are regular chatops:chatops0640 files. There are no supported nested subdirectories. The writer temporarily creates `<destination>.tmp.XXXXXX` files with mktemp, chmod0640 and atomic mv; they are removed by its trap on failure. The initialization check is a stable-state preflight: an in-progress or leftover temporary file is not silently deleted or accepted. It aborts for review/retry after the writer completes.

The integrity directory is chatops:chatops2750 and has the exact same Access/Default ACL profile as the production state root described above. Group entries have no write permission. Setgid preserves chatops group inheritance. The new stage creates a missing integrity directory with this exact profile, validates existing correct directories without any metadata changes, and rejects unknown children, symlinks, files/FIFOs in place of a directory, incorrect owners/groups/modes or ACL entries. The parent root retains0750 in fixtures; integrity independently requires2750.

The historical runtime scripts, Units, manifests and installed checksums remain unchanged. The observation test invokes the versioned provisioning stage before exercising the historical observer; its original strict0750/0640 assertions are unchanged. The fixture provisioning stage now includes integrity so the historical integrity writer runs within the explicitly prepared layout.

## Validation and current stop

All28 targeted tests pass: the previous25 plus three integrity test groups cover missing/existing directories under both parent ACL profiles, repeated runs, owner/group/mode/ACL rejection, unknown children preserved, and symlink/file/FIFO/nested-directory rejection. Real production `--check` returned VALIDATED_UNCHANGED for both state root and integrity. No live migration is required for these checked paths, and no --create was executed against production.

The complete control-validation workflow was started sequentially. Steps1–98 passed, including the previously failing M4.29.2 maintenance contract, its bound historical hashes and the new provisioning tests. Step99 (`Validate Commercial S10.2D runtime diagnosis Control SSOT`) failed in `test_scripts_avoid_destructive_shortcuts_and_personal_data`: `scripts/tu1nz_adult_public_s10_2d_aggregate_contract.py` has worktree mode0770 but the test requires0755. Its content matches HEAD byte-for-byte; no correction was made. The failing grouped invocation ran57 tests: one failure and two skips. Later workflow steps were not run after this requested stop condition.

Evidence and logs: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/integrity-v2-20260927T072502Z`. The failure is saved as FULL_SUITE_FAILURE.diagnose with exact ACL, Git mode and SHA256. This is not an overall suite pass. No commit, push, PR, merge or Bot branch followed. The new script/tests remain candidate files (the repository ignores new files by default; they must be deliberately included when integration is allowed).

## Latest validation — 2026-09-27, 07:46 UTC run

The user-authorized exception for cAdvisor's read-only host-root monitoring mount was verified: Docker RW=false and kernel /rootfs mount read-only, no script references in inspected container configuration/entrypoint/command, process command lines or systemd unit sources. Only the two exact historical Worktree files were normalized0770→0755 after metadata/ACL/inode/content backup. Their contents matched HEAD and current Remote100755 entries, the inherited ACL behavior was reproduced, and after chmod their effective group write was absent. Inodes, complete index checksum and pre-existing Repository diff were unchanged. cAdvisor ID/start time/restart count stayed unchanged. No parent ACL or other mode changed.

Files: `scripts/tu1nz_adult_public_s10_2d_aggregate_contract.py` and `scripts/tu1nz_adult_public_s10_2d_backup.sh`. Backup and rollback metadata: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/worktree-mode-normalization-20260927T074542Z/BEFORE.json`.

Current upstream dbed49d183c0310242b51e785c51c28294ada95f was integrated with merge564a3a270721f50a53d119906afc5139e702a134. Only the two saved, agent-authored test/workflow edits were temporarily restored and reapplied without conflict. The detached checkout was not switched. The integration merge is local, not pushed; the Agentmode fix remains uncommitted.

A new complete workflow run began at step1. Steps1–104 passed, including the previous rights failure in99. Step105 failed: S11.2 `test_r15_4_source_only_simulator_covers_access_and_rollback_matrix`, simulator exit2. This grouped test invocation ran120 tests with one error. The failing simulator matches HEAD and current upstream byte-for-byte. The underlying simulator reason is not present in the captured test traceback, so it is not guessed or attributed to ACLs. No further correction or normalization was attempted. Later workflow steps remain unexecuted. Full-suite evidence: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/full-suite-20260927T074634Z`.

This latest result supersedes the earlier step99 stop. Overall suite remains RED. No Agentmode commit/push, PR, merge to control-main or Bot branch. All42 original hardening files, historical Agentmode install bindings and integration1cf0d79 retained. No live configuration or service change.

## Final local validation — 2026-09-27 08:15 UTC run

All107 runnable Control validation steps passed from step1 through107. Evidence: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/full-suite-20260927T081513Z/results.json` and `PRESERVATION.json`. Current upstream9bef420 was merged without rewriting history; original1cf0d79 remains an ancestor. All42 baseline Hardening files retain their exact SHA256. Detached Control remains7c634d3b82572e8459d51c69f04dce82c624d766 with clean status. No live configuration, ACL, service or container was changed in this investigation. Read-only production v2 preflight still returns VALIDATED_UNCHANGED for both directories; no migration is required.

The remaining S11.2 failure was a synthetic fixture relying on umask despite inherited Default ACL. A descriptor-based fchmod0700 was added only to its freshly created fixture; strict mode checks and all decisions remain unchanged. See `docs/S112_ACCESS_SIMULATOR_ACL_2026-09-27.md` for reproducibility, regressions and validation limitations. No historical runtime/install artifact or binding was rewritten.

Additional historical hardening tests:35 Linux tests PASS with a newly generated, explicitly synthetic current-date PDF fixture;36 macOS tests PASS using FakeAPI, including real watchdog timeout control flow. Initial supplemental invocations lacked fixture/import setup and incorrectly ran the macOS caffeinate test on Linux; logs are retained, not counted as passing. Correct platform/setup runs pass without edits to these historical tests or their source. This is separate from the all-green107-step CI-equivalent run.
