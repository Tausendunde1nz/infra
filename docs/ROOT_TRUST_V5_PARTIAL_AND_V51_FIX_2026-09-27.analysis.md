# Root trust V5 partial result and V5.1 preparation

Status: INCOMPLETE, NOT ACTIVATION READY. No second sudo invocation, no live configuration/service/container/group/sudo/ACL change, no watchdog, no PR.

## Original evidence is immutable

V5 source commit a58fb974de3fed9728c9d0083b301fbf092ccc10 and source SHA 9f45b7d28dfd6c1e0ff41c0ed3e2f6b1d51109de08cdd9508052849e521009f8 remain unchanged.
Protected result: `/var/lib/tu1nz-root-trust-v5/run-20260927T142818Z-73234b450b2919bf`.
Reported manifest SHA: 48f97e3414fa567e135178724e831939f7138d710c8ecf83ff14cc6ba207321e. This reported hash was not independently re-read from the protected manifest in this turn.
Local sanitized export: `/Users/daniel/.codex/tu1nz-recovery/root-trust-v5-preparation-20260927/readonly-v5-terminal-output.log`; SHA 1bcacc1778d33340b39a022c51f4cdf0bbb6f669d731a27de4a35590ea211f4f.
The export is 15,189,191 bytes. Its graph contains 3,883 nodes, 9,707 edges, 3,861 REVIEW_REQUIRED and 22 NOT_PRESENT nodes. Original `collection_finished` is false. Neither that flag nor the original section statuses have been rewritten.

## Reproduced cause, not a timeout hypothesis

Collector.docker writes its sanitized payload to docker-security.json. Store.section subsequently appends an in-memory OK entry and attempts to write its section envelope to that same filename. Store.write refuses to overwrite it with ValueError(output_exists). Main catches that exception and finalizes a partial manifest without recording the exception class.
The exact duplicate-write path is reproduced offline using the unchanged V5 Store. The existing docker-security.json payload remains unchanged. The exported OK section therefore does not prove a successfully persisted section envelope.
Execution stops before process-identities, the seven cron journal windows, the repeated expected-symlink check and the transitive-candidate pass. Those stages must not be described as collected.

## Usable findings and limits

614 effective-unit rows were exported; 45 unit queries remain failures. 556 rows have root or empty User, but this includes non-service units and does not mean 556 active root services. No directly indexed executable in the exported root/default-user service rows had a chatops-writable component. This narrow negative observation says nothing about interpreter arguments, imported code, sourced files, output paths or the known root documentation/Trendwatch blockers.
The At-job spool enumeration contains only .SEQ; the crontab spool contains chatops and a historical chatops backup, no root entry. These are point-in-time directory observations, not proof that every scheduling mechanism is absent.
The current /etc/sudoers, 99-dokuagent-pandoc and chatops-nopass hashes equal the previously recorded originals. Other include files and policies still require semantic review. The local /etc/polkit-1/rules.d directory was empty in this enumeration; vendor rules/actions remain part of the graph.
Docker inspection returned 15 existing containers, including stopped containers. None has HostConfig.Privileged true in this export. This does not eliminate authority through sockets, host mounts, capabilities, user namespaces or inherited Docker GIDs. No container was executed, restarted or modified.
Known blockers remain open. A complete root trust closure, functional migration installer and proven rollback cannot yet be claimed.

## V5.1 fix, not executed

A new version is introduced; V5 and all its evidence remain historical. V5.1 writes section envelopes only as section-NAME.json, separating them from payload files. A failed envelope write produces an INCOMPLETE entry with a sanitized persistence_error_class rather than an in-memory false OK. No existing file is overwritten. Unexpected outer exceptions are also recorded by class in the manifest/export.
V5.1 has its own root-private base `/var/lib/tu1nz-root-trust-v51` and a separate inert hash-bound launcher. Its permissions, fixed queries, nofollow reads, private raw-source retention and INCOMPLETE security gate are unchanged. No old result directory is reused. No privileged rerun was performed.

## Regression coverage

203 tests pass: the complete previous 167 plus V5.1 collision/persistence/interruption tests, full component and launcher matrices, and whole-main orchestration fixtures. The whole-main fixture executes all 12 mocked sections beyond Docker and verifies the final manifest and collection_finished flag. Another fixture injects a later process-section error and confirms that journal/symlink stages still complete and the failure is preserved. These are fake-command/isolated-directory tests, not a root collection or production health test.
All 42 hardening file hashes and 1,125 V3 file hashes remain unchanged. The canonical checkout is still clean and detached at f1c3b9a323761f71c80dadd9b5a1dad3a968d582 and was not modified. See ROOT_TRUST_V51_VERIFICATION_2026-09-27.json for the new script hashes.

## Next gate

Only the revised, committed, hash-bound read-only V5.1 collection may be considered next, after renewed user readiness for the single terminal sudo step. Do not launch it automatically from an old launcher or a cached sudo session. After collection, resolve the remaining semantic graph edges before designing or activating the joint transaction. No live activation command is provided.
