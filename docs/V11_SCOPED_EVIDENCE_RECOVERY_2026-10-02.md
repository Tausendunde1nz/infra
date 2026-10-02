# V11 delta: scoped evidence and durable recovery protocols — 2026-10-02

Base: `3285fda95d0a11e28fb1ee58a644e9e08299b4f1`. Governance: GOVERNANCE_V1_1_ACTIVE.
Overall status remains **LIVE_NO_GO**. This delta prepares one read-only privileged evidence run;
it does not deliver an integrated production migration, activation launcher or installed watchdog.
The SIGTERM attribution and closed network/AppArmor/n8n investigations were not reopened.

## Scope correction: no general empty-Approval gate

The reviewed observer uses these standard paths:

| Path | Role |
| --- | --- |
| `/opt/tu1nz_repos/control` | Pinned detached Git observation; no fetch/reset/checkout |
| `/opt/tu1nz_repos/docs` | Read-only status/checksums |
| `/var/lib/tausendunde1nz/agentmode` | Own observation, success, checksum and notification state |
| `/var/log/tausendunde1nz/health/control-transitions.log` | Own transition log |
| `/run/tu1nz-agentmode/control-observer.lock` | Own per-cycle flock |
| `/etc/tu1nz/notify.conf` | Existing notification configuration, baseline-bound |

No direct Approval/APE path, queue API, Telegram update consumer or lease protocol occurs in
this observer or the current durable V11 coordinator. The coordinator's root transaction Store
uses its own state and lock. Arbitrary future host-adapter behavior is not proven by that fact:
concrete adapters must still preserve this explicit boundary and bind configuration/environment
paths. The observer sources the existing notify configuration, so its trusted hash remains part
of admission; arbitrary replacement configuration is not authorized by this analysis.

The unreadable APE approval/guard/notifier directories from the old broad scan are **not** a
requirement to prove that all approvals are empty. Do not open their payloads, traverse them,
drain queues or introduce an empty-queue condition. Check only conflicting own instances,
locks and root transaction metadata. A general historical unreadable-path list is not evidence
that every listed private file is a Trendwatch consumer.

## Last bounded read-only collector

New sources are under `scripts/v11_scoped_evidence/`. The allowlist is literal and versioned.
It contains 21 specific Trendwatch-related configuration/script paths, 14 known service/timer/
drop-in file paths, effective properties of 10 fixed units, the Agentmode observer lock metadata,
and only names/metadata of V11 transaction-shaped directories. No recursive private scan.

The four previously unreadable `/etc/t1nz` files are explicitly included: trendwatch_demo2.env
and the 2025-11-02_08-57 backup's trendwatch_post.conf, notify.conf and trendwatch_rank.conf.
The specifically named historical Trendwatch sources file from the private manifest is included.
Known direct posting, fetch, compose, clone and daily-post script variants are included; unrelated
private application secrets, APE payloads, databases, journals and shell histories are excluded.
No source is executed or sourced. A reference is a reference, not proof of runtime consumption.
Known effective units supply active/inactive and identity information for subsequent correlation.
Unexpected drop-ins or credential/config references mark the report INCOMPLETE rather than
silently extending the read scope. Backup filenames do not count as references to the live script.

The old token is extracted only in memory from the hash-pinned live posting script. Exact byte
comparisons return booleans; output contains known technical paths, reference type, migration
classification, numeric metadata/ACLs and SHA-256. No token, environment value, command line,
message, surrounding text or private payload is exported. Unknown exception messages are
replaced by exception class. There are no provider/network/API requests in the root collector.

The bootstrap is a new fixed-source derivative of the earlier reviewed copy primitive:

1. Inline bootstrap is hash-bound by the renderer; Python runs with `-I -B` and a clean environment.
2. Create a fresh root-owned `/var/lib/tu1nz-v11-scoped-evidence-*` directory; never reuse a prior run.
3. Copy the one permitted chatops-owned source through descriptor-relative, no-symlink traversal.
4. Stage as root-owned 0600; verify owner, link count, size, ACL and SHA-256 on the root copy.
5. Execute only that verified root copy; never import/execute the writable worktree source as root.
6. Keep authoritative reduced results root-private (0700/0600), fsync and publish each record atomically.
7. Publish identical sanitized records separately, root:chatops 0750/0640 under a 0710 root:chatops parent.

Even the root-private records contain no raw configuration or secret payload. A later failure
preserves earlier sections and creates an INCOMPLETE manifest. Exit 0 = complete collection,
2 = incomplete evidence, 3 = fatal bootstrap/output failure. COMPLETE is not activation approval
or proof that the reference graph is closed. Existing files, symlinks and hardlinks are not reused.
Read-only service commands have fixed names, bounded timeouts and no mutating verbs. The lock
is not acquired or released; only metadata and its matching kernel-lock indication are examined.
Orphan-instance checks available to chatops remain nonprivileged; they are not a reason to read
all root process payloads. Admission will require fresh instance checks at the later live window.

Only this collector needs the next personal sudo step. Expected duration: approximately 1–3
minutes, with a 10-second bound for each systemctl query. No service downtime or rollback of live
configuration is involved; interruption leaves private partial evidence. Its authorization is
separate from the later V11 live window. The rendered command is withheld until fresh MacBook
availability for this read-only step. No sudo or collector execution occurred in this preparation.

## Recovery protocols advanced offline

New `scripts/privileged_v11_recovery/recovery_protocol.py` supplies tested protocol primitives:

- persist START_INTENT from a checked stopped state;
- require a single-use root-owned ExecStartPre claim before the main process may start;
- bind transaction, boot ID, unit/source hashes and invocation before startup;
- bind MainPID, kernel process-start ticks and monotonic start time in the main receipt;
- recover a failed post-start receipt write only from the durable pre-start invocation claim;
- never infer ownership from time proximity alone or stop a foreign invocation/PID reuse;
- require at least 660 monotonic seconds, identity/health checks and no sample gap over 30 seconds;
- persist a forward-only provider-handoff intent **before** the human can change the token;
- after that boundary permit only a verified new credential or a secured stopped state;
- reject unknown reversible phases, integer-as-boolean proofs and private fields in handoff state.

These are protocol tests, not an installed ExecStartPre helper or a complete systemd adapter.
The existing production adapter is not silently replaced. The root prologue, durable Store wiring,
independent watchdog executable/unit, recovery executor and complete host adapter integration are
still pending. Phase-decision cases named watchdog restart/boot change are **not** an independent
daemon crash/restart proof. No end-to-end production rollback proof or launcher is claimed.
The complete suite must be repeated after that integration, with real isolated process failures.

## Trendwatch target and forward-only boundary

The nonprivileged current unit read confirms the four scheduled posting services still have
implicit root identity; the disabled/inactive fetch service uses chatops and references the
posting/compose scripts. No unit was changed. Both unsafe behaviors remain live and must be
removed by the later migration: the embedded token and root tee into a chatops-controlled path.

The target remains a dedicated unprivileged service identity, root-owned immutable scripts,
explicitly limited writable directories and LoadCredential from a root-protected file. Do not
finalize path ownership or clone/variant retirement until the bounded evidence is evaluated.
Do not call the existing candidate a completed least-privilege deployment.

An independent watchdog must be armed and verified before the first actual mutation, including
quiescing consumers. This is stronger than waiting until after services are stopped. The provider
handoff marker must be durable before BotFather is opened for replacement. Uncertain provider
state is forward-only; do not optimistically resume the compromised token. The old notification
mark-before-send semantics remain at-most-once intent, not an exactly-once delivery guarantee.

### Deferred screen instructions for Daniel — not a request to act now

1. Wait for the fully validated live transaction to display its protected input prompt and identify
   the verified bot. Open the verified BotFather account in Telegram.
2. Perform only the agreed token replacement for that exact bot. No dual-token phase is assumed.
3. Enter the replacement only into the waiting echo-disabled root terminal input; never into this
   chat, a shell command, environment variable, screenshot or saved text file.
4. If the protected prompt is absent or the transaction reports an error, do not paste the token.
   The recovery route is a verified new credential or a secured stop, never the old token.

Bot identity/role confirmation, old-token rejection and function checks are still to be integrated.
No BotFather action, external login or token input is requested during the read-only collector run.

## Validation / preservation / CI

Final targeted suite: **488 tests** (39 scoped collector, 73 recovery, 57 core, 10 n8n offline,
70 V11, 53 V12, 130 V9, 56 V10). All **108 workflow run blocks passed** in an isolated clone
created under umask 0022. Two existing paired-application tests retained their missing-source skip;
those integrations are not claimed as passed. No test/security expectation was relaxed.

Coverage includes source/hash drift, leaf/parent symlinks, hardlinks, FIFO, size bounds, content/
rename races, numeric ACL masks, unexpected ACL, wrong owner, atomic publication/no overwrite,
secret/PII suppression, error/timeout/interruption preservation, unknown unit/config scope,
missing input, copied-code immutability, startup claim/receipt failures, foreign invocation,
PID reuse, boot change, observation gaps, 659.9-second refusal and irreversible-boundary failures.
These do not substitute for the still-pending common transaction's complete failure matrix.

Byte preservation verified: 701 baseline files, all 42 hardening files, 1,125 historical collection
files and 30 V9 sources. All previously tracked files are unchanged; only new delta sources/docs
are added. 1cf0d79 remains an ancestor. Detached checkout remains clean at
`9b383960291da469671c3888cfa4fdcc3c33cf01`. No live configuration or service mutation was issued.

GitHub API confirms zero check-runs and zero status contexts for base 3285fda (combined status
pending means no checks, not a failing check). Existing validation triggers cover pull requests
and pushes to control-main, not this branch; no workflow_dispatch is defined. No workflow trigger
is changed, no PR created, and local workflow success is not relabelled GitHub CI. New-head status
will be queried after push and retained in private evidence; absent CI remains an explicit limit.

Private preparation/test evidence:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-scoped-preparation-20261002`.
Historical 2026-10-01 evidence and sources are retained. After the one read-only run, evaluate the
bounded results and continue concrete host/watchdog/forward-recovery integration autonomously.
A new, separate availability confirmation is required only when the later live transaction is
actually ready. V11 remains LIVE_NO_GO until then.
