# V11 delta: unexpected Agentmode stop and exposed Trendwatch credential

Status: **OFFLINE_PROGRESS / LIVE_NO_GO**. Base: `0b7e9c10a674f28de3d0b62a9377f1b1e0d9d7d3`.
Governance: `GOVERNANCE_V1_1_ACTIVE`. Investigation date: 2026-10-01.
This is a new delta, not a replacement for historical evidence or `V11_OFFLINE_PROGRESS`.
No production start, sudo, credential rotation, watchdog activation, policy change or PR occurred.
Closed n8n, NAT, AppArmor and Mommyramona findings were not reopened.

## Unexpected stop: UNATTRIBUTED_SIGTERM

Daniel explicitly states that the stop was unintended and unauthorized. The service was enabled,
`inactive/dead`, MainPID 0, Result success, ExecMainCode 2, ExecMainStatus 15. Last invocation:
`1abc4b00ddcb43f19881c3000abce90b`. Start: 2026-08-28 21:31:14 UTC; exit:
2026-09-30 22:19:16 UTC (2026-10-01 00:19:16 Europe/Berlin); inactive since 22:19:17 UTC.
`Restart=on-failure`, RestartUSec 30s, NRestarts 0; successful SIGTERM termination does not
establish who requested it. PID 1 authored the deactivation/accounting journal entries; this
is not evidence that identifies the initiating actor.

The narrowly bounded journal window 22:18:30–22:20:00 UTC contained deactivation and
resource accounting, with no attributable shutdown, deployment, migration or watchdog cause.
Classification is **UNATTRIBUTED_SIGTERM**. No further broad forensic search is justified.

Unit: `/etc/systemd/system/tu1nz_agentmode.service`, root:root 0644, no drop-ins,
NeedDaemonReload=no. Type=simple, User/Group=chatops. ExecStart is
`/usr/local/bin/tu1nz_sync_all.sh --loop`; script root:root 0755. Both match repository bytes.
PartOf/BindsTo/BoundBy/ConsistsOf/Triggers/TriggeredBy are empty; StopWhenUnneeded=no;
Conflicts=shutdown.target. Requires system.slice/sysinit.target/-.mount; Wants
network-online.target/tmp.mount. WantedBy multi-user.target and tu1nz_integrity.service.
Only Agentmode and integrity units referenced the Agentmode unit in the scoped unit scan.
Integrity is active/exited with success. The separate monitor service was inactive/dead;
its named timer had no loaded schedule. This is not a blanket all-services-health claim.

A readable /proc command-line scan found no instance of the observer (zero unreadable processes).
`/run/tu1nz-agentmode` and its observer lock were absent. The source uses a per-cycle flock,
not an approval lease/queue consumer. It does not poll Telegram updates or process approvals.
State was inspected through metadata/checksums, not private contents. Actual protected APE
state paths are under `/var/log/tausendunde1nz`, not the nonexistent `/var/lib/.../ape-approval`.
They were inaccessible to chatops; no claim of globally empty approval queues is made.

Agentmode and integrity directories remain chatops:chatops 2750. State files are 0640.
Existing named-owner ACLs and default ACLs are retained; access masks prevent effective group
write. No recursive chmod/setfacl or historical installer change occurred. Exact metadata,
ACLs and six state-object hashes are in private evidence. chatops memberships were recorded
numerically without changes. notify.conf is root:chatops 0640 and unchanged.

## Restart preparation and its limits

The documented maintenance baseline requires active/running Agentmode. A blind restart is
unsafe: the installed observer requires branch control-main, but the preserved canonical
checkout is intentionally detached. It also resets a separate docs checkout to its upstream.
These are restart incompatibilities, not an explanation of the historical SIGTERM.

New `scripts/privileged_v11_recovery/agentmode_observer_v11.sh` is an uninstalled candidate:

- accepts a detached checkout only with an exact, explicit 40-hex commit pin;
- preserves Git state and treats docs as a read-only status observation (no fetch/reset);
- retains single-instance flock, atomic state files and transition deduplication;
- refuses root execution; a proposed drop-in runs it as the existing chatops service;
- tests actual isolated start/health/SIGTERM/stop/restart and repeated observations with fake curl.

The existing mark-before-send notification sequence has at-most-once intent, not an exactly-once
delivery guarantee: a crash/send failure may lose delivery. No approval payloads were read or
replayed. Production pending-state safety cannot be inferred from offline tests alone.
The fixed-command systemd adapter binds start/stop to InvocationID and MainPID, refuses foreign
instances and does not perform a blind rollback stop. Receipt-persistence failure still requires
an integrated durable ownership reconciliation path before production admission.
The intended stability window is at least 660 monotonic seconds, covering two full 300-second
cycles plus margin. It has not been run against production.

## Exposed Trendwatch token

The token value is never included here. Provider: Telegram Bot API. The literal is embedded in
`/usr/local/bin/trendwatch_post.sh`. Authenticated read-only getMe/getWebhookInfo/getChatMember
checks succeeded without token argv/logging, messages or update consumption. The bot has no
webhook and pending_update_count was zero. It is a channel administrator with message posting,
editing/deletion and additional moderation/invitation/story rights. That is broader than proof
of sendMessage-only access. Expiry is **NOT_EXPOSED_BY_READ_API**, not a proven future expiry.
A replacement token for the same bot must not be described as independently least-privilege.
Consumer and channel-role requirements must first establish which permissions can be reduced.

Known scheduled consumers are the four trendwatch2 morning/midday/afternoon/evening services.
They were inactive one-shots, timer-triggered, with implicit root identity. A disabled, inactive
trendwatch-fetch service (chatops) has a compose drop-in referencing the posting script.
clone_trendwatch.sh references copies/variants and `/etc/t1nz`; these must not be omitted.
No literal match was found in inspected Docker configuration or the already available private
n8n export. That does not prove the absence of indirect or protected consumers.

Exact token-location results (no token values):

- live posting script and `/usr/local/bin/trendwatch_post.sh.bak_2025-11-30`;
- private `privilege-v3-20260927T120945Z-9867d70d/raw-00717.bin` (0600);
- Mac Codex session `rollout-2026-09-22T18-56-59-01a0ca0c-9efd-7602-b6b4-a162375b01fa.jsonl`
  under `/Users/daniel/.codex/sessions/2026/09/22` (0644). Full ancestor access was not established,
  so mode alone is not presented as proof of access by every other user.

97,184 server plaintext files were scanned in the scoped roots, followed by full streaming
checks of the initially oversized auth.log/syslog. All 3,853 reachable local-ref Git blobs had
no match. On the Mac, 1,812 scoped files and an additional 72 Codex application log files were
checked. The application logs had no match. Eight readable files under the subsequently
identified `/etc/t1nz` had no match; four protected files were unreadable:
`trendwatch_demo2.env` and the 2025-11-02_08-57 backup's trendwatch_post.conf, notify.conf,
trendwatch_rank.conf. Other protected locations are listed in the private scan manifest.
Missing `.codex/log` is absence, not a permissions failure. Compressed/encoded archives,
unreachable Git objects and unreadable protected files are outside the achieved proof.
PDFs and Doku.zip were not evaluated. Historical traces were neither rewritten nor deleted.

## Rotation contract and provider boundary

Official references:
- https://core.telegram.org/bots/features#botfather
- https://core.telegram.org/bots/api#getme
- https://core.telegram.org/bots/api#getwebhookinfo
- https://core.telegram.org/bots/api#replaceManagedBotToken

BotFather documents generating a replacement token for a compromised bot. There is no established
same-bot dual-valid-token staging guarantee. The managed-bot replacement API explicitly revokes
the current token, but managed-bot eligibility here is not established. It is not an implemented
rotation route for this bot. An external owner/BotFather action is therefore a pending dependency.

Prepared ordering: prove all consumers and recovery; quiesce affected senders; perform the verified
provider cutover; install the new credential atomically; verify identity/permissions; restart only
confirmed consumers; validate function; verify old-token rejection without exposing either token;
repeat the secret scan. Do not assume the old token can be revoked only at the very end.
Before provider cutover, abort without mutation. After cutover, recovery is forward to a valid new
credential or a secured stopped state. Never restore the compromised credential as an operational
rollback. Necessary notification downtime and provider interaction duration are not yet proven.

`trendwatch_secret_candidate.py` transforms only the pinned historical posting-script bytes in
memory. It removes the embedded token, reads a systemd credential and supplies the URL to curl
through stdin; it neutralizes xtrace before secret handling and rejects unknown curl/sudo shapes.
The proposal uses LoadCredential with a root-protected source and removes selected inherited shell
variables. This is not an installed secret store or a complete same-UID isolation proof. Tests use
synthetic credentials only. A transform of the live bytes passed bash syntax in memory, with no
live write. Existing application/source bytes remain unchanged.

## Bootstrap / watchdog / common V11 progress

New primitives validate fresh monotonic time, hashes, fixed paths, ancestry, ownership, ACLs and
existing transactions before persistent creation. Payload dictionaries are frozen before callbacks;
a nonblocking directory flock serializes publishers without creating a lock file. Publication uses
renameat2 NOREPLACE, private staging, fsync, deterministic 0700/0600 and a first ROOT_STARTED marker.
Failed staging is retained as evidence and blocks reuse; its presence must not be called
NO_ROOT_TRANSACTION_STARTED. A hash-envelope state is compatible with the existing durable Store.
The temporary directory becomes the final root transaction through atomic publication.

The watchdog decision function fails closed on unknown state/types, uses monotonic deadlines and
boot identity, and distinguishes reversible rollback from post-credential-cutover secured recovery.
No timer, service, watchdog or root transaction has been created. These are tested primitives, not
an integrated production bootstrap or independently running watchdog. The complete host adapters,
crash-safe service-start ownership receipt, watchdog executor and end-to-end provider handoff still
need integrated proof against the protected consumer/state facts. V11 is **not activation-ready**.
No activation command or executable launcher is delivered by this delta.

## Validation and preservation

429 targeted tests passed (53 recovery, 57 existing core, 10 n8n offline, 70 V11, 53 V12,
130 V9, 56 V10). All 108 existing workflow run blocks passed in a fresh isolated clone.
Two paired-application cases retain their explicit unavailable-source skip; they are not counted
as passing integrations. No claim of GitHub CI is made for this branch-only push.

One intermediate rerun stopped at workflow 100: the isolated clone was created under umask 0002,
producing 0775 instead of the unchanged exact 0755 historical-file requirement. getfacl showed no
ACL there. A new clone created with umask 0022 passed the unchanged test and all 108 blocks.
No historical source or physical production/worktree mode was normalized. The failed run and its
logs remain private evidence. A mistyped HostKeyAlias on one read-only connection attempt was
rejected by strict host verification before connection; no host key was accepted or changed.

Preserved byte-for-byte: 701 baseline tracked files, all 42 hardening files, 1,125 historical
collection files and 30 V9 source files. 1cf0d79 remains an ancestor. Detached control remains clean
at `9b383960291da469671c3888cfa4fdcc3c33cf01`. Agentmode unit/script and Trendwatch posting script
retain their prior hashes; Agentmode remains inactive/dead with MainPID 0 and the same invocation.
No live mutation commands were issued. This is not a fresh privileged all-host health attestation.

## Admission remains closed

Protected consumer/approval evidence, provider replacement/recovery semantics and integrated
production transaction/independent-watchdog recovery remain unresolved admission requirements.
Offline unit-test success must not replace those proofs. Do not request a live MacBook window or
present an activation command on the basis of this commit. No claim that all requested offline
integration work is complete is made. The next safe progress is to close these precise facts and
integration gaps, not reopen the historical signal attribution or closed network investigations.

Private server evidence: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/agentmode-token-v11-20261001`
(0700; evidence 0600). Private Mac evidence: `/Users/daniel/.codex/tu1nz-recovery/agentmode-token-v11-20261001`.
Only code, synthetic tests and this redacted delta/manifest are versioned. No raw protected data.
