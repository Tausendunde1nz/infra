# Final v3 disposition and v8 quarantine preparation

No fourth reader. The immutable result was collected successfully with SSH rc0; source and reader hashes match. The private result is not committed. Its SHA-256 is db7805a3b35f0ee241df90ee976157b9613ebe27b7f954bc23017bbf23d204ee.

## Decision

ACTIVE_ROOT_CALLER_UNSAFE_OR_UNKNOWN is a precautionary disposition, not a claim of proven active execution: active_root_call_proved=false, zero exact caller chains, 3027 fixed sources checked, two missing live candidates, 2360 uncertain root-entry candidates. These 2360 candidates are NOT a change or quarantine list. No active root caller was established and no inactive/historical classification is justified. The approved rule treats .env as untrusted irrespective of parser semantics.

Twelve command rows identify the fixed lock helper at lines2/31, data reading/parsing at8, status-related operations at14/18, time at17 and an unknown operation at22 with UNKNOWN and FILE_DERIVED argument origins. No complete notification/argument contract is established. No guessed replacement is created. The approved alternative is exact-path quarantine, not another parser or source reader. The target is presently root:root0700 with root-owned nonwritable ancestors, no reported ACL influence, and live bytes equal the archived source. It is not chatops-writable directly.

## Implemented exact-path quarantine primitive

scripts/tu1nz_quarantine_v8.py has no CLI or activation entrypoint and is not installed. In production mode it requires root and the single fixed target/hash; fixture mode is prohibited for root. It checks regular type, owner/group/mode, single link, xattrs, protected ancestors and stable descriptor metadata. It creates private original bytes and metadata, fsyncs them, writes durable INTENT, then atomically installs a fixed Python exit78 guard. No .env, shell evaluation, network call, token or notification is involved. Parent write permission is never granted.

An idempotent repeat must use the same private transaction proof. Automatic security rollback verifies the original backup but retains/reinstalls the guard. Foreign target bytes, changed inode before replacement, corrupt backups and unexpected links cause refusal rather than overwrite. Original bytes are exclusively for a separate manual recovery; automatic rollback cannot restore unsafe root execution. Functional loss: the old backup-notification path will fail with78; its upstream consequences remain UNKNOWN and must be reported at activation.

Failure injection covers before backup (no mutation), after backup, persisted intent, atomic replacement and verification. Fixture files really are created/replaced/fsynced in isolated temporary directories. These tests prove the primitive, not a combined live installer or host-wide rollback.

## Other confirmed migration boundaries

Root Compose unit archive hash fad12c044b08f691ad1fa6a0afb40c748bfba81b4fbb1ef6240d5a442a213c01: later mask without ExecStop; preserve the created container, networks and missing working directory. Root doc cron build c7beada82a5a09b29e1db6d9a4c828b3c87c16fb4a405d41d34488898121515e and check aff2cc9afd2078142ca10ab2e1f3012c537f1b170be385b38c7006e396332789 must be quarantined together to avoid root execution and failure-notification spam. Trendwatch source 467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264: unsafe root triggers remain quarantined on failure; do not fabricate a provider transport or restart unrelated services. These are archive bindings, not fresh live approvals.

The existing v7 broker and journal remain offline components. The combined host installer, independent installed watchdog, complete reachable-authority validation and service handover are not implemented by the exact-file primitive. No activation-ready marker is issued. The JSON records scope and disposition, not a falsely complete executable transaction.

## Fresh service evidence and unresolved handover

Unprivileged read-only systemd/proc queries after V3 show tu1nz_agentmode.service active, MainPID1389949, UID/GID1001, inherited groups4/27/100/987/999/1001. Its source remains hash96a03614f5c5eacc94576975a7d38251b5cc3da7c673a690914942b298d359df. The loop calls observe_once immediately (line258) then sleeps (259); observe_once performs docs sync, checksums, state and transition handling (209–220). There is no implemented pause/resume or migration handoff in that loop. Removing /etc/group membership alone cannot remove GID987 from this running process. A blind restart is therefore not a validated no-extra-sync handover. No signal, stop, restart, state edit or group mutation was performed. A live quiescent handover still requires a controlled design and validation; fixtures alone cannot certify a currently running iteration has finished.

Two S8 unit files also differ from the old candidate archive: health currently524dcb965e6b03afde3953780bb531177bd55a8607d175131986555f3d06d91b, telegram currentlyfcad30a40a51ac9d45472cbe3e5eb607ccf117f820fe7f9a5d581f455aa63665. Current single-unit queries show both User/Group chatops; health inactive/static, Telegram active/enabled PID1249502 with Docker GID987. All three queried units report NeedDaemonReload=no. These are actual external revisions, not a reason to restore old unit files. No foreign change was overwritten. Future service handling must bind the current implementation and preserve its delivery/idempotence contract.

Docker removal is limited to chatops and proven inherited carriers. UID10001's explicit Docker contract is not removed; MyChatBuddy, Mommyramona, Jellyfin and cAdvisor remain untouched. Current Control checkout was only observed, never switched or modified.

## Status

V3 evaluation is complete and the backup_notify disposition is settled as quarantine; it is no longer a request for a fourth protected semantic reader. The broader migration remains NOT_READY because the live Agentmode/Telegram identity handover and combined host transaction are not yet validated. This report does not imply those engineering tasks are complete. No sudo/grants, group membership, service, live file, firewall or application data changed in this follow-up.

## Full verification

457 offline tests passed on the server (438 existing plus19 exact-file quarantine tests). All42 Hardening baseline files and1125 historical evidence files remain byte-identical. All previously tracked files, including the final V3 reader and its manifests, remained unchanged. The private production result was not copied into Git.
