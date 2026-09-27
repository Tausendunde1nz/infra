# Root trust V5: preparation and protected-information gate

Date: 2026-09-27. Base commit: 29ce14e2510a616a91c1ccdb5dbf9d8beef7eefe.
Status: INCOMPLETE; NOT ACTIVATION READY. No live migration, service action, watchdog, countdown, Telegram message or PR.

## Scope and preservation

The original V4 result remains 50/51 and INCOMPLETE. No historical sampler or raw evidence was edited. The only existing repository file corrected is the V2 test harness; its sampler remains byte-identical. Test backup: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/root-trust-v5-edit-20260927T140712Z/test_privilege_inventory_v2.py`, original SHA bfe52e62570594787ea7cdb2f83b2fce5e5e33e78fc5403838a9085d0f70fe85.

## Process cleanup regression

The original failure occurred in Path.read_text on /proc/PID/stat after discovery of a process that subsequently disappeared. The old harness accepted ENOENT but not ESRCH. It did not retain a start-time identity, so simply adding another broad exception would be inadequate.
The corrected isolated test has parent and child report their own PID, start ticks and process group before timeout. Both identities and the complete process group must be non-executing in two observations. A zombie is terminated but not necessarily reaped; this distinction is explicit. ESRCH from a proc read requires a subsequent signal-zero ESRCH and another absent proc read. A still-running process, changed identity, permission failure or group member prevents success. PID reuse is rejected rather than treated as cleanup success. No live process is signalled by this evidence helper.
Deterministic cases cover the read/exit race, reappearance, wrong start time, live/zombie state, permission/probe errors, timeout, cleanup error and group members. The real timeout test uses only its own isolated parent/child. No test is skipped or weakened.

## Separate symlink supplement

Path: `/etc/cron.d/system_summary`; expected canonical target: `/etc/cron.daily/system_summary`.
Result: EXPECTED_SAFE_SYMLINK. lstat/readlink and ACL metadata are recorded separately for the link chain and fixed target chain. The fixed absolute target is read with directory descriptors and O_NOFOLLOW, and identities are compared before/after. No execution or unsafe copy was used. Directory identity is used rather than inventing a directory-content checksum; link text and regular target have SHA-256.
Target SHA: c0db6ec740c1cb361c3adc3417b24ea1f73e346b6c1d41f5a64c0e204f104d8b.
Private supplement: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/root-trust-v5-review-20260927T141127Z/symlink-supplement.json`.
Supplement SHA: 6c750cabdd06e843cf9937029871f7103ff46fbf164d074eac99c3a8491342b4.
This result concerns this path relationship, not the semantic safety of every command in its target. It does not rewrite the V4 manifest.

## Inventory and concrete information gate

The unprivileged enumeration found 338 service, 76 timer, 29 socket, 9 path and 10 mount unit files (plus targets, scopes, slices and an automount). These are file inventory counts, not counts of active root services.
`/var/spool/cron/atjobs` is daemon:daemon 1770 and cannot be enumerated by chatops. `/var/spool/cron/crontabs` is root:crontab 1730 and cannot be enumerated. Current `/etc/sudoers`, its include directory, and `/etc/polkit-1/rules.d` are unreadable. Existing V3/V4 evidence cannot prove their current complete state.
`/etc/anacrontab`, `/etc/rc.local` and `/etc/NetworkManager/dispatcher.d` were absent; other network dispatcher directories exist. Absence of those paths does not mean the entire mechanism is absent.
The machine-readable preliminary graph is `ROOT_TRUST_GRAPH_V5_PRELIMINARY_2026-09-27.json`. It explicitly retains BLOCKER and REVIEW_REQUIRED, including Docker authority. It is not the requested complete trust closure. No untested REQUIRED_CONTRACT is used to bypass a blocker.

## Legacy documentation execution chain

`/etc/cron.d/system_doc_build`: `0 22 * * * root /usr/local/bin/build_system_doc.sh`.
The script uses `/usr/bin/env bash`, `set -euo pipefail`, PATH-resolved date, python3, wkhtmltopdf and cp. Python imports sys, markdown and pathlib. It reads System_Dokumentation.md under `/opt/Tausendunde1nz/_Doku`, writes HTML, a minute-stamped PDF and replaces System_Dokumentation_latest.pdf. It then directly calls `/opt/tu1nz_repos/docs/system_manifest/render_kapitel3.sh` if executable. No locking is present in the inspected script, so overlapping runs are not prevented. Repeated runs in the same minute reuse the PDF name. No direct Git commit/push appears in this script.
The renderer (SHA 5b338fe604c5a8df22caeec7069c80c8218fb04e1e49fd7199c265c4234634e1) uses env bash and PATH python3; imports yaml/pathlib/textwrap; reads TU1NZ_DokuKernel_v7.3.yaml via yaml.safe_load and writes TU1NZ_DokuKernel_v7.3_block.md in the chatops-controlled repository. The output block was absent at inspection; this does not prove why it is absent. The PDF and HTML existed, but their mtimes alone do not prove a successful complete cron run.
`/etc/cron.d/system_doc_check`: `0 */2 * * * root /usr/local/bin/check_system_doc.sh`. This checks the latest PDF's age against 90 minutes, appends /var/log/system_doc_check.log through tee and performs a curl Telegram call. The daily build versus 90-minute age threshold is documented, not silently repaired. The notification statement and its credential values are not included in this repository.
Governance files in the Docs repository reference the renderer/block. The full external consumer set, retention requirements, effective cron PATH/cwd, root Python module resolution, and historical success/failure remain REVIEW_REQUIRED. The main /etc/crontab says SHELL=/bin/sh; this does not establish all per-file runtime environment values.

## V5 collector: prepared, not executed

`scripts/tu1nz_root_trust_v5.py` is self-contained and not imported from a user-writable repository by root. It requires an injected verified source hash. The inert launcher embeds the exact reviewed bytes, checks HEAD and source SHA before sudo, then verifies those bytes again inside isolated root Python. It never installs anything.
Only new evidence beneath `/var/lib/tu1nz-root-trust-v5` is written. Root-owned ancestors, no writable parent or ACL, 0700 result directories, 0600 atomic/fsync files, unique names and no existing-file replacement are required. Protected raw configuration/code remains in this root-private store. Terminal output contains graph metadata, classifications and hashes, never source bodies, environment values or journal messages.
Categories include systemd effective states and definitions, cron/spools, at/anacron, sudo includes, Polkit actions/rules, package/logrotate/network/udev/boot hooks, runtime loader/profile inputs, local scripts, Docker security metadata and host mounts, and root/capability/Docker-GID process identities. Fixed Docker ps/inspect is read-only; no container exec/start/restart. Fixed systemctl calls only list/show. Seven bounded daily cron journal queries reduce messages in memory to known-command mention counts. A mention is not proof of job success.
Inputs use canonical metadata and separately opened absolute paths with nofollow and drift checks. Writable components are reported as risk, not automatically assumed to be executable edges. Literal references are candidates; shell source, imports, globs, PATH and dynamic behavior remain unresolved until semantic review. Collection budgets (30,000 nodes, 300 MB total source, 2 MB/file, bounded command streams/timeouts) fail closed. Budget exhaustion or unreadable input cannot produce SAFE. Signal interruption preserves completed sections and an INCOMPLETE manifest where output remains writable.
The collector always returns evidence status INCOMPLETE (exit 2), even when enumeration finishes; exit 3 means unsafe initialization. This is intentional: collection is not a security proof. It does not run arbitrary discovered programs, imports, hooks, At jobs or cron jobs. The prepared launcher has not been executed.

## Joint transaction gate

Future ordering remains fresh protected backup and independent root watchdog -> 1A isolated Trendwatch -> 1B isolated documentation function -> Phase 2 broker, five sudo grants and Docker/GID revocation -> fresh SSH, all services and recomputed trust graph -> finalize. Every started phase must roll back on failure.
A dedicated documentation account, immutable installed program and private StateDirectory are the preferred design, but publication destinations, consumers, notification handling and import closure are not yet proved. It would be unsafe to manufacture an installer or claim a complete rollback before resolving those facts. No maximum outage or activation command is claimed. The existing Trendwatch/broker components remain offline components; the combined installer/watchdog/failure matrix is not complete.

## Validation

The selected full privilege regression suite is recorded in the final verification record. Initial complete run: 164 tests passed, including prior 128 and new process, collector, symlink and launcher regressions. Subsequent changes require a fresh full run before commit. Only intended scripts, tests, this analysis and the preliminary graph may be staged. Private evidence and historical source bodies are excluded.
