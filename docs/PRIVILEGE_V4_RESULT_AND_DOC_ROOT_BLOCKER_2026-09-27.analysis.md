# V4 read-only result and independent root-execution blocker

Status: NOT ACTIVATION READY. No installer, watchdog or live migration was executed. No second privileged collection was performed. No PR is authorized.

## Immutable evidence

The once-executed collector at commit a05c6a935da4c31c421c7729efed951fb98052cd has SHA-256 15d0a3209928b455853aad64b33c4d8cf8e1d5ce976ada94b0e0ceb11ee49af4.
Root-private output: `/var/lib/tu1nz-privilege-audit-v4/run-20260927T135236Z-8445154b5332d068`.
Original status remains INCOMPLETE: 50 successful sections out of 51.
Manifest SHA-256: 08bb33bcdf2df280d8d0296619d97fc90475d2e67354bb38f32adeb8cf0f0841.
The sanitized export reconstructs that exact manifest, including 98 file hashes. This verifies export consistency, not a fresh read/hash of the protected raw files.
The original collector, manifest and section classifications remain unchanged.

The rejected file-0022 is `/etc/cron.d/system_summary`, a symlink to `/etc/cron.daily/system_summary`. The target was collected separately. An unprivileged no-write reproduction reports input_link. This explains the rejection without weakening the no-symlink rule or changing INCOMPLETE to COMPLETE.
Root crontab was absent. The open-descriptor snapshot is instantaneous; absence of a writer does not prove that transient privileged writes do not occur.
Observed root Python writes under `/opt/agentmode` belong to agentmodus_tu1nz.service and root-owned parents. They must not be conflated with chatops tu1nz_agentmode.service.

## Independent legacy documentation blocker

Cron is active. `/etc/cron.d/system_doc_build` schedules root at `0 22 * * *` to execute `/usr/local/bin/build_system_doc.sh`.
Cron SHA-256: c7beada82a5a09b29e1db6d9a4c828b3c87c16fb4a405d41d34488898121515e.
Script SHA-256: ec2d68bd0406d86bcc2a91e96f7a1ad4329d32a61fcdcbfe9fc8911f737dea79.
The root-owned 0755 script directly executes `/opt/tu1nz_repos/docs/system_manifest/render_kapitel3.sh` without dropping privileges, conditional on executable presence. That executable and its parent resolve into `/tausendunde1nz/07_docs/system_manifest` and are chatops-owned and writable; the executable is 0755.
The same root script writes documentation below `/opt/Tausendunde1nz/_Doku`. Although `_Doku` itself is root-owned 0755, `/opt/Tausendunde1nz` is chatops-owned 0755, allowing replacement of the child directory entry.
This proves a configured root execution/write path, not observation that the next scheduled run reaches every command. No job or exploit was triggered.
Trendwatch isolation plus removal of Docker membership and the five sudo grants would leave this independent escalation path intact. The complete migration must therefore remain blocked pending a separately verified functional replacement for the legacy documentation job.

## Distinct integrity findings

The active root codex_syscheck_heartbeat cron appends to `/var/log/tausendunde1nz/codex_syscheck.log`, which is chatops-owned 0775. Its direct parent is root:chatops 2750 and not writable by chatops. This is user-mutable root output, not proof of the same replaceable-parent attack.
No active non-comment trim_upload_log cron entry was found; its historical script must not be described as a confirmed active root writer.
No shared functional ACL, file mode, cron job, service, container or live configuration was changed.

## Tests and preservation

The full selected privilege suite ran 128 tests: 127 without error, one ERROR in the pre-existing test_privilege_inventory_v2.Tests.test_descendant_timeout_cleanup. Reading /proc/<pid>/stat raised ProcessLookupError (errno 3) after the process disappeared. This is not a green suite; the historical test was not edited or weakened and no retry is substituted for the failed result.
The eight new pure review tests passed within that run. They cover exact manifest reconstruction, tamper/source/status/duplicate rejection and distinction between mutable output and replaceable ancestors. They perform no privileged or live operations.
All 42 original hardening file hashes and all 1125 V3 evidence hashes match their historical manifests. Collector V4 bytes remain unchanged.
Fresh canonical checkout inspection found clean detached f1c3b9a323761f71c80dadd9b5a1dad3a968d582, whereas the previous recorded baseline was 7c634d3b82572e8459d51c69f04dce82c624d766. This external drift was not reverted. No claim of an unchanged HEAD is made; a later transaction must re-establish its current baseline.

## Remaining gate

No final activation command is provided. The combined installer, independent watchdog, exact rollback and full failure-injection matrix are still incomplete. Resolve the independent root documentation path, review the failed process-lifetime test without weakening its cleanup assertion, and revalidate current drift before representing any preparation as activation-ready. Existing Trendwatch/broker components remain offline preparations only.
