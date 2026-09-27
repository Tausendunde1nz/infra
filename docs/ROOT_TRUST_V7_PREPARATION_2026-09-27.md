# V7 — chatops authority scope, reachable-edge engine and targeted archive reader

Base: `7b24db9286e85200efde4981d5f21b6d717e6e04`.
Preparation only. No live mutation, sudo execution, container/service restart,
watchdog, countdown, provider call, PR or checkout switch in this run.

## Superseding V6's overbroad gates

The goal is removal of chatops-controlled root authority, not elimination of all
privileged service identities. V6 remains historical; its global Docker-carrier
closure and automatic cAdvisor/MyChatBuddy blocker labels are not the new policy.

| Subject | Correct decision for this migration |
|---|---|
| Mommyramona | UID 0 alone does not block. The protected backup_notify host-consumer edge still needs a proved active caller and dangerous interpretation. |
| Jellyfin | Actual application UID/GID 1001:1001; root s6 alone is not a blocker. No identity migration or speculative device group change. |
| cAdvisor | Read-only monitoring mounts require their own contract. Only residual chatops control of definition/image/API/mount configuration after Docker revocation is relevant here. |
| MyChatBuddy | Explicit Docker GID of UID 10001 is independent of chatops. Retain it; no restart/pause or 180-second lease wait in this migration unless a host-lifecycle control edge is actually proved. |
| Detached Control | An external checkout change is not intrinsically blocking. Only an actual automation dependency matters. No reset/switch; record fresh relevant hashes before a future transaction. |

MyChatBuddy's root-owned Unit, runtime.env and credentials and fixed Docker run
arguments were already checked. Writable application state does not by itself
prove control of Docker arguments or host execution. Its 10001-owned leaf below
chatops-owned `/var/lib/tausendunde1nz` does require a narrow distinction:
application state integrity is a separate follow-up; whether systemd's privileged
StateDirectory preparation safely rejects a substituted ancestor/leaf is not yet
proved by the exported metadata. This is not asserted to be an exploitable edge.
No change to that directory is authorized by the scope correction.

Prepared follow-up (not an issue created in this run): **MyChatBuddy application
state integrity below a replaceable parent**. Record parent/leaf identity,
root/systemd path handling, lease/delivery ambiguity and safe maintenance design.
Do not change governance, Alpha visibility, data, containers or provider state.

The V7 Docker gate rejects group membership, new sessions with GID 987, remaining
inherited carriers (including root processes descended from chatops sessions),
unknown carrier provenance and broker passthrough. A separately verified independent
service contract can retain Docker GID. UID alone is not inheritance proof.

## Reproducible reachable-edge analysis

`tu1nz_trust_scope_v7.py` accepts explicit root-capable entrypoints, semantically
proved EXEC/IMPORT/CONFIG/PRIVILEGED_WRITE/TRIGGER edges and source-closure proofs.
It follows reachable edges transitively, handles cycles and distinguishes failed
queries, unknown privilege contexts, verified quarantine and uninstantiated
templates. Inactive does not mean unstartable. Dynamic resolution on a reachable
path fails closed; unrelated dynamic nodes do not block a closed graph.

A text match is not an execution edge. UNREACHABLE_LITERAL is emitted only after
all relevant source resolution is closed. Otherwise the result is
UNRESOLVED_LITERAL, rather than falsely declaring a dangerous call unreachable.

The existing V5.1 projection has 403 entry candidates, 239 reached source records,
85 failed/unknown queries, and 58 unknown privilege contexts. In particular,
nonroot User does not settle `+`/`!` Exec privilege prefixes when the export only
contains command hashes. The 13,251 text edges therefore remain unresolved in this
projection. The other 45 records are query failures, not execution edges.
This is a tested reachability engine, **not a claim that production semantic
closure has already been achieved**. The hash-bound private projection and input
hash are recorded in the JSON companion. No second broad inventory was run.

## Targeted protected read

Only this file can be opened by the reader:
`/var/lib/tu1nz-root-trust-v51/run-20260927T145810Z-09700d05ed357f5d/source-02923.bin`.
Its required source hash is
`878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311`.

The reader checks root ownership, private regular-file mode, single link,
ancestor ownership/type/mode, absent unexpected ACL/xattrs, descriptor identity,
metadata stability, size and SHA-256. No alternate path or arguments. It reads
no `.env`, invokes no subprocess/interpreter on archived code, writes no server
file, and loads no repository module as root.

Output: line numbers, allowlisted program candidates, fingerprints of other
commands/paths/variable names, redirects, assignment dependencies and source/eval/
substitution indicators. All values and raw lines stay protected. Parse ambiguity,
transforms and dynamic source paths stay REVIEW_REQUIRED. A safe parser or active
caller is never inferred from lexical shapes. Caller proof is joined separately
from the reachable graph: V5.1 has no direct incoming literal call to backup_notify;
this is not proof of historical unreachability while dynamic roots remain open.

The one-command launcher verifies reader bytes in memory before SSH, embeds those
same bytes, and verifies them again inside isolated root Python after sudo.
The route is pinned to Tailscale `100.121.130.51`, OpenSSH 2222, strict known-host
checking. Password entry is directly into the concealed terminal sudo prompt.
No password argument, environment value or terminal transcript is stored.
Only the redacted result is stored locally in a new 0700 directory, file 0600.

Reader and launcher SHA-256 are in the JSON companion and final handoff. They are
not executed during preparation. The old launchers remain unused.

## Implemented additional components

`tu1nz_codex_broker_v7.py` retains the four fixed diagnostic operations and exact
NOSETENV sudo syntax from V4. No shell, path, Docker argument, deployment or restart
passthrough. It adds bounded streaming of both helper output channels with a
monotonic timeout and failure cleanup before reaping, plus a fail-closed quota on
private backup/audit files. Raw Docker environment and journal messages are never
returned to chatops. Existing V4 bytes remain untouched. V7 is not installed.

`tu1nz_campaign_journal_v7.py` adds a durable private transaction kernel: exclusive
lock, fixed step order, checksum envelope, fsync+atomic checkpoint replacement,
INTENT persisted before adapter mutation, rollback after partial apply, recovery
from persisted intent, verified rollback and STOPPED/ROLLBACK_FAILED states.
Unsafe Trendwatch/root-doc/root-Compose restoration explicitly requests quarantine;
non-security state uses exact restoration. It has no executable host adapter or
activation entrypoint. A checksum detects corruption, not authorization: the root
ownership/private directory boundary supplies authorization.

## Required real installation work after semantic review

The combined live installer, independent installed systemd watchdog and full
replacement-function adapters are **not complete**. The new durable kernel and
broker tests do not substitute for those adapters or end-to-end installation tests.
No synthetic model is described as a tested production rollback.

The confirmed remediation contract is:

1. Root Compose: preserve original Unit/metadata privately, disable/mask without
   ExecStop; never create its missing WorkingDirectory or touch container/network.
2. Trendwatch/root-doc: bind exact trigger/script backups; remove root execution
   of chatops-controlled renderer/write targets. On failure keep unsafe triggers
   quarantined. A temporary fail-closed function outage is safer than reactivating
   archived unsafe bytes. Restoration of unsafe code is a separately documented
   manual recovery operation, not a watchdog default.
3. Revoke chatops Docker membership and inherited identities only. Restart public
   services individually; Agentmode requires state/lock/notification preservation,
   no checkout repair and no second sync. Replace sessions under an independent
   root transaction. Do not restart MyChatBuddy merely to remove chatops rights.
4. Install root-owned pinned broker/manifest and exact grants; remove the five
   unsafe grants using the existing hash-bound transformer; validate full sudoers
   and retain password-protected recovery sudo.
5. Validate the new reachable authority graph, required service contracts and
   functional endpoints. The future watchdog must retain quarantine on rollback.

Until protected semantics and reachable contracts are closed, no live plan is
marked executable and no readiness marker, service or watchdog is created.

## Tests and limits

New tests exercise scope, provenance-aware GID closure, reachable vs unrelated
unknowns, templates, query failures, cycles, quarantine, archive path/hash/mode/
link/race constraints, output secret suppression, launcher binding, broker argument
rejection, bounded timeout/size/stderr/exit handling, durable phase-boundary failures,
rollback verification, checkpoint corruption, links, drift and mutual exclusion.
Only controlled fixture commands run; no application, network or message tests.

Local macOS Python lacks os.listxattr in this environment. The journal fixture
supplies a test-only empty-xattr provider there. Production code is not relaxed;
server Linux tests use real listxattr. The initial local failure and this platform
fixture correction are recorded here; no test is skipped. Fresh Linux suite result
and historical hash verification are appended before commit.

### Verification before commit

The initial complete Linux run passed 274 tests. Three further negative cases were
added for empty entry coverage, a false independent-account claim for UID 1001,
and malformed numeric group data; final full run is required before commit.
All 42 hardening hashes and 1,125 V3 hashes match. Historical tracked files remain
unchanged. Canonical Control is still clean/detached at
7c634d3b82572e8459d51c69f04dce82c624d766; no command changed that checkout.

One later terminal command for the protected read (not run during preparation):

```sh
python3 /Users/daniel/.codex/tu1nz-recovery/root-trust-v7-20260927/tu1nz_backup_notify_launcher_v7.py
```

It invokes exactly one `sudo /usr/bin/python3 -I -c` with hash-checked in-memory
reader bytes on the confirmed server. It cannot activate the migration.

Final Linux result: **277 tests passed** (216 retained plus 61 new), 3.362 seconds.
No test skipped or weakened. The targeted reader has not been run with sudo.
