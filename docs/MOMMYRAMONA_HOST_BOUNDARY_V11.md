# V11: Mommyramona host boundary, 2026-09-30

Base: `11557dabb25878a17693055211293d0ac7df1da3`, branch
`security/codex-privileged-ops-2026-09-27`.

## Binding result

**C — CONTAINER_BOUNDARY_UNRESOLVED.** This supersedes the literal
container-UID-zero activation criterion in `V11_CURRENT_STATE_RECONCILIATION.md`
and `scope_gate_v11.py`. Those files remain historical evidence, not the current
admission rule. The user's boundary is host-root or comparably privileged host
manipulation. V9 UNRESOLVED remains final and is not a gate.

The remaining unknown is specific: the effective file/capability decisions of
the enforcing, currently loaded AppArmor profile `docker-default.119`.
Its name, enforcement mode and policy digest are readable:
`df4af4ca290fd03237a7e50b674bf9b3c23fbbc1fd8e18702730778c92447d0a`.
Its `raw_data` and the global profile listing return EACCES to chatops.
Neither `/etc/apparmor.d/docker` nor `/etc/apparmor.d/docker-default` exists.
No further archive, actor, journal or general inventory search was performed.

The profile name alone does not prove that its effective rules equal Docker's
published default template. An earlier progress message provisionally called
the chain confirmed before checking this final restriction; the final result
corrects that overstatement. We do not assume either permission or denial from
an unreadable rule set. No exploit or permission-probing payload was executed.

## Proven current chain and restrictions

The evidence JSON records the sanitized effective configuration, its full
in-memory inspect hash, process identities, kernel capability mask, profile
digest, mappings, mounts, network endpoints and relevant path metadata.
Environment values, application contents, credentials and messages are absent.

* Host PID 2444 runs `python /app/main.py` as UID/GID 0, with identity UID/GID
  mapping (`0 0 4294967295`). No user-namespace shift.
* `/opt/telegram_chatbot` is a **directory** bind to `/app`, writable, rprivate.
  It is not a single-file bind. File and parent are owned by chatops; main.py
  is 0664, parent 0755. Chatops can replace application code and sibling files.
* `/app` and its host backing ext4 filesystem are `rw,relatime`, without nosuid
  or noexec. The host chatops process is unconfined with NoNewPrivs=0.
* Effective capabilities include CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETUID,
  SETGID and SETFCAP; no CAP_SYS_ADMIN. NoNewPrivs=0; seccomp filtering is active.
* Privileged=false; no extra devices, host PID/IPC/UTS mode, runtime socket,
  host-root bind or sensitive host mount is configured. `/proc` is a container
  proc mount, `/sys` is read-only; default masked/read-only paths are recorded.
* Restart policy is `always`. Changed host code would be read on a later
  application/container restart. This does not assert hot reload or restart it.

Subject to the loaded LSM permitting the relevant operations, this is a
specific escalation chain: chatops-controlled Python becomes host-mapped
container UID 0, writes a root-owned executable with privileged metadata through
the directory bind, and a host caller executes it on the suid-enabled host
mount. No downstream cron consumer is necessary for that chain. No such file
was created, chmodded, executed or searched for as part of this investigation.
Creation/chown/metadata capabilities do not by themselves override AppArmor.

This is not a claim of an unrestricted namespace escape. Existing direct Docker
access is the separately known V11 revocation target, not circular evidence
that this application path would remain exploitable after that revocation.

## Narrow compatibility work already completed

Image: `sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db`.
Application SHA-256:
`f7119919cd3bff8193b72782ec984633cd222abad87281df011455fb7313a8bd`.

The unchanged application imports os/json/requests/Flask. Its optional loader
reads `/opt/system_status_bot/.env` and catches read errors; that is a container
path, not a host mount discovered here. Production Compose loads `.env` via
`env_file`; its host metadata is root:root 0600. No secret content was read or
printed. Application code reads BOT_TOKEN and SECRET and listens on 8080.
No application file-writing call was found. The image disables Python bytecode.
There is no configured Docker HEALTHCHECK; `/health` is an application route.

Four isolated runs passed: two starts as `20001:20001`, two as `0:0`.
Each passed import, Flask test-client GET /health, real startup, and three
loopback HTTP health samples. The test containers had network=none, no host
mounts, no published ports, no capabilities, no-new-privileges, 128 MiB RAM,
0.5 CPU and 64 PID limits. They received only dummy credentials. No webhook was
called; requests was disabled during import, and network isolation prevented
external communication throughout. Both variants used root-owned 0644 copies
of the exact source in disposable container layers. All test containers were
removed. Production ID, image, state, restart count, mounts and endpoints were
equal before/after; the host main.py hash stayed identical.

The first harness attempt could not docker-cp into a read-only container layer.
It failed before application execution and cleaned up. The corrected isolated
harness uses a writable disposable layer, with no host binds. This is not a
production read-only-rootfs compatibility claim. Private first-run traceback
and script checksum remain preserved locally; no production configuration was
changed to accommodate the test.

## Conditional remedies, not an activation plan

Preferred if B is established: dedicated numeric non-root UID/GID, drop all
capabilities and no-new-privileges. The tested UID is a candidate, not a newly
created host account. Preserve image, application, env values, ports and both
network connections; do not use an unreviewed Compose recreate. Current Compose
does not represent the additional tausendunde1nz_net endpoint. A production
recreate/rollback still requires a tested endpoint-preserving transaction.

The alternative is immutable, root-owned code plus all import/search parents,
with a digest-pinned atomic deployment and a broker accepting only the fixed
approved artifact. Merely chowning main.py inside a chatops-owned directory is
insufficient; sibling import injection and parent replacement remain. A host
read-only bind does not make the host source immutable. The root comparison
test establishes import/start compatibility of the source in an immutable-to-
chatops container layer; it does not validate a deployment broker or rollback.
That variant has greater deployment and provenance scope than the demonstrated
non-root execution and is not selected as an unnecessary workaround.

No production activation, rollback, restart, owner change, Compose edit,
watchdog or sudo run occurred. The old launchers remain invalid. Reintroducing
an unsafe root-writable-bind configuration must not become automatic recovery.

## Tests and remaining evidence boundary

Twelve new classifier regression tests cover confirmed chains, incomplete
evidence, the current unreadable profile, non-root without assumed isolation,
other host paths, input integrity, and absence of activation authority.
The previous 16 scope tests are retained as historical-contract tests; they do
not override the new host-boundary classification.

The prior 108-step/659-test results remain historical and are not advertised as
a new complete V11 transaction proof. Phase 4's A-or-remediated-B prerequisite
is not satisfied. Therefore there is no new full transaction, launcher, rollback
engine or readiness request. This is a specific C stop, not an open-ended
inventory request: resolve the effective loaded profile's rules, bound to the
digest above, through an authorized source or a separately authorized narrowly
scoped read. No privileged read is started or requested by this run.

References for kernel semantics (not substitutes for effective local policy):
[Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html),
[mount flags](https://man7.org/linux/man-pages/man2/mount.2.html),
[Docker AppArmor](https://docs.docker.com/engine/security/apparmor/).
