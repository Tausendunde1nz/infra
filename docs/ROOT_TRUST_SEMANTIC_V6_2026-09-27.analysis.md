# Semantic review V6 — NO-GO, offline-only

Base: `a0016bf213cc8d5bfce147a8a163dda85852570f`.
This supplements, and does not rewrite, V4/V5/V5.1 evidence. No live action,
privileged collection, service restart, watchdog, timer, countdown or PR occurred.
The new Python module is an **offline gate and in-memory failure model**, not a
finished installer, persistent checkpoint engine or independent root watchdog.
Its green tests cannot establish live migration readiness.

## Evidence and graph boundary

The existing V5.1 export has SHA-256
`339684d21fdd56046fcc76143aad816a8a409150dd629cf7547e5aeeb2baf484`.
Its 26 collection sections completed, but collection success does not establish
semantic trust. It contains 6,349 nodes and 13,296 edge records: 13,251 literal
candidates plus 45 systemd query failures. Uninstantiated templates and the
misparsed `-.mount` query must not be classified as absent execution mechanisms.
The active root mount was separately confirmed using the option delimiter.

Every edge has a stable ordinal in a private review ledger, bound by SHA-256 in
the JSON companion. The exact source/target mapping remains in the private V5.1
export; no raw script, environment, credential or journal content is committed.
The ledger deliberately retains REVIEW_REQUIRED wherever execution semantics
have not been proved. **This is not a completed semantic classification of all
13,296 edges.** Missing literal paths do not prove absence of a root mechanism;
root-owned files do not prove their imported inputs are trusted. Permission to
read the exported metadata does not make its protected source bytes available.

Root archive reported manifest hash:
`17ab9113ec1cfa8f88379e18c68418cab5c028647a90f68554e6783e9b3280e7`.
This is the exported claim, not a fresh independent read of the protected archive.

## Root Compose: BLOCKER

`/etc/systemd/system/tu1nz-bot.service`, SHA-256
`fad12c044b08f691ad1fa6a0afb40c748bfba81b4fbb1ef6240d5a442a213c01`:
root oneshot, enabled but inactive/dead, no drop-ins, no pre/post commands;
WorkingDirectory `/home/chatops/bot-template-telegram`; ExecStart
`/usr/bin/docker compose up -d`; ExecStop `/usr/bin/docker compose down`;
RemainAfterExit=yes, Restart=no, KillMode=control-group, TimeoutStartSec=0,
TimeoutStopSec=90. Reverse dependencies show only multi-user/graphical targets.

The working directory is absent. Its chatops-owned 0755 parent permits recreation.
Consequently absence is not mitigation: creating a Compose file and implicit
`.env` would control a later root Docker invocation. No explicit `-f`, project or
config/environment binding exists. No such directory was created here.

The sole container with project label `bot-template-telegram` is
`tu1nz-bot-template`, state created, PID 0, zero start/finish times. Its image is
`sha256:508c343a95455e15bcded66ecd99a57f06080ccc8c1879057d0e82ede2b0630a`;
no mounts, planned port 3000, restart always, project default network with no
assigned IP. It does not own the running production containers.

Preferred later treatment: disable/mask the inactive obsolete entry **without
ExecStop**, retaining the created container and network. First confirm that this
never-started test project has no intended future operator role. If retained,
replace implicit discovery with root-owned absolute config and env paths, pinned
image and explicit project; compare every endpoint/mount/port before any action.
Rollback restores exact unit bytes, link/enablement metadata and prior inactive
state; never reconstruct with compose down/up and never start the unsafe unit as
an automatic rollback side effect. This final point needs an explicit accepted
rollback contract before activation, because blindly restarting unsafe root code
would conflict with the trust objective.

## Container-root is not automatically host-root

Mommyramona: Python runs host UID/GID 0 with identity UID mapping, but no privileged
mode, Docker socket, host-root bind, host PID or host IPC. The writable bind is
`/opt/telegram_chatbot` -> `/app`, rprivate. Both current networks and their exact
endpoint attributes must be retained; no recreation is prepared. Its root identity
alone is a separate container-hardening concern, not proof of host escalation.

Concrete unresolved edge: `/usr/local/bin/backup_notify.sh` references
`/opt/telegram_chatbot/.env`. The former is not readable by chatops; V5.1 recorded
SHA `878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311`
in `source-02923.bin`. The graph has no incoming literal edge proving activation.
It does not tell whether root sources/evaluates the environment, safely parses it,
or never calls this historical utility. Git search finds only prior review and
collector references, not implementation. Do not claim an active root consumer
from this reference alone. Exact archived source semantics and activation context
are required; never export the `.env` itself.

Jellyfin: root s6 init/supervisors coexist with the actual Jellyfin process at
UID/GID **1001:1001**, matching PUID/PGID. No privileged mode, devices, socket,
host-root bind, host PID/IPC or additional capabilities were configured. Writable
rprivate mounts are config, cache and media; port 8096 is bound to loopback. The
application is already unprivileged. No blanket chown or speculative video/render
group is justified. Complete host-consumer closure remains unproved; no concrete
host-root execution edge was established. Both container reviews remain
REVIEW_REQUIRED, superseding prior overbroad UID-0 reasoning without changing
historical evidence.

cAdvisor's read-only host-root/runtime mounts remain a separate explicit trust
contract. A read-only filesystem mount is not proof that every API reachable
through that mount is read-only. No socket calls or escape attempts were made.

## MyChatBuddy: explicit Docker authority and restart blocker

`mychatbuddy-private-alpha.service` uses dedicated UID/GID 10001 and explicitly
sets SupplementaryGroups=docker. Removing chatops membership cannot revoke it.
Its root-owned runtime.env/credentials are not chatops-writable. `+`-prefixed
ExecStartPre install commands execute with elevated credentials despite User=.
Docker CLI runs on the host; application/init processes inside the container are
10001, without the host Docker group. The unit uses a mutable rc5 image tag and
runs with KillMode=process and docker stop as ExecStop.

The current image `sha256:cda7116fc1e48ce35fb537dac8e447cf60b6bbd0c98db2b82e9c96f2809f422f`
was matched to the existing frozen Docker archive without executing application
code. Config and every layer digest were verified before reading selected source
files into a new private evidence directory:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/semantic-v6-20260927T151726Z`.
Runtime SHA `35d2dfe525475d09b43ca65a3bc7b4739ea4d3d5ac53c82206571eb95c4c27ba`;
polling SHA `26294663af7837adc3f41d5cd594653d65576e5748c836720d98653a427b82c4`;
runtime-state SHA `63d772d34c9398b9b6bed223d5b89e54db1def8ea88ee96f331d2dadefb4dbfc`.

Each startup gets a new random poller holder. Acquisition rejects an unexpired
other-holder lease (TTL 180 seconds); finalization disposes the database but does
not explicitly release the lease. Polling delivers before recording delivery,
then advances the offset. A stop between external delivery and bookkeeping may
leave an ambiguous resend. Startup also runs alembic migrations and validates
Telegram ingress. Health requires a signed heartbeat no older than 90 seconds.
Therefore waiting for a process to exit alone does not establish safe restart,
no duplicate messages, or unchanged database state. No provider call was made.

The data leaf is 10001:10001 0700, but its ancestor
`/var/lib/tausendunde1nz` is chatops-owned 02775: leaf replacement and subsequent
root/systemd/daemon traversal require their own contract. Do not fix this with
recursive ownership changes. A proven quiescence protocol or a separately bounded
root-owned Docker lifecycle replacement is required; neither is currently proved.

## All observed Docker-GID carriers

The companion JSON preserves all 17 V5.1 PID/start-tick/UID/group/unit identities.
They include the four public s7/s8-landing/s8-telegram/s10-wms services, Agentmode,
MyChatBuddy, user@1001, dbus and session/collector processes. Snapshot identities
are not a current kill list. No broad kill-by-UID is permitted.

Later handling: drain and restart public services individually only after their
function-specific no-message health contract; Agentmode must preserve observer
lock, CONTROL_LOCAL_STATE_INVALID, DOCS_SYNCED, state-aware notification state and
the detached checkout. Never reset Control or start a second synchronization.
MyChatBuddy is separately blocked as above. User manager/dbus and each session
require PID/start-time/cgroup binding and a replacement Tailscale connection before
retirement. A service restart does not revoke explicit SupplementaryGroups.
Final revocation checks must include all principals, not only chatops processes.

## Staged campaign contract (not executable installation)

| Phase | Required proof before checkpoint | Rollback unit |
|---|---|---|
| 0 | All graph edges closed; fresh exact metadata/content/endpoint snapshots; recovery tested; independent watchdog verified | No live mutation until complete |
| 1 | Trendwatch, root-doc and Compose each pass positive/negative tests independently | Current automation only; preserve others |
| 2 | Only proved host-authority blockers; one container at a time; exact endpoints, aliases, image, data, mounts and health | Current container only; no generic Compose reconstruction |
| 3 | Per-service quiescence, fresh session, GID absent from every relevant identity | Exact membership and affected service states; do not restart ambiguous poller |
| 4 | Pinned root broker, fixed op IDs, mutual exclusion, audit, exact sudo removals and visudo; password sudo retained | Exact files/ACLs and former grants |
| 5 | Semantic graph diff, services, PackageKit, SSH, listeners and monitoring match contract | Reverse verified checkpoints |

Each durable checkpoint must bind bytes, owner/group/mode/ACL/default ACL, symlink
identity, unit/timer state and container endpoint configuration. Resume must first
verify the previous checkpoint; unexpected state stops forward progress. A failed
partial apply must restore the pre-part state even if its endpoint is temporarily
missing. Rollback success must be measured independently, never inferred from a
successful command exit. A disconnected initiating SSH session must not cancel a
future root systemd transaction or its independent watchdog.

Existing V4 broker/Trendwatch components remain uninstalled. This review adds
fail-closed gates and exercises phase-boundary/rollback state semantics with fakes;
it does not silently promote those components into a production installer.

## Precise stop condition

NO-GO. Protected source semantics (notably the pinned backup_notify edge), full
root-consumer closure, and a duplicate-free MyChatBuddy pause/resume contract remain
unproved. Available metadata and unprivileged reads cannot settle the protected
source edge. Additional broad inventory will not solve it. A future narrow review
must use the already archived pinned script, prove its caller context, and expose
no secrets. One such read is not presently claimed sufficient to close the entire
graph. No readiness request or sudo command is issued prematurely.

## Validation

New targeted tests cover root-only vs host-authority classification, unknowns,
missing/recreated Compose paths, env/hash binding drift, restart contract refusal,
every phase failure, exact in-memory partial/total rollback, endpoint preservation,
concurrent start, SSH disconnect and residual Docker GID. They do not simulate
external providers or assert a duplicate-free MyChatBuddy restart. Full existing
203-test privileged-preparation suite is rerun with the new tests before commit.
Historical files, the original 42 hardening hashes, V3's 1,125 hashes and detached
checkout are checked separately. No historical collector or evidence is edited.

### Actual validation result

216 tests passed on the server (203 retained plus 13 new); the new 13 also pass
on local Python 3.9. All 42 original hardening files and all 1,125 V3 files match
their pinned SHA-256 values. No tracked historical file differs from a0016bf.

**External drift:** the canonical checkout was earlier observed detached at
f1c3b9a323761f71c80dadd9b5a1dad3a968d582; final read shows clean detached
7c634d3b82572e8459d51c69f04dce82c624d766. Reflog records transitions through
3ef3d5cca1bd99d39402d924edb81100efb58b95. This task issued no mutation against
that checkout. Its byte-for-byte constancy cannot be claimed. This is an additional
preflight drift blocker; no foreign changes were reverted.
