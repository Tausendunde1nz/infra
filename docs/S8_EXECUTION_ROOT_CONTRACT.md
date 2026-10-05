# S8 isolated execution root — construction checkpoint

## Current delta (supersedes older construction checkpoints below)

Private CI `37357353325` is GREEN at Application
`febeddf3c8046587dd5043548ff93c3bd9619449` and Control
`98f7fe542eefcfb8b25f70f9296dd62f85888567`: 43 native components, 23 S11/S12
checks, and both PostgreSQL 17/18 sealed initial-claim/poll/replay chains.
The append-only inode already rejects chmod/access-ACL/default-ACL mutation;
the test now proves those syscall denials rather than inventing a watcher event.

The next, **not yet accepted**, candidate adds the production provisioning,
observer and PID-1 coordinator functions. A single original process snapshots
the authenticated inputs, creates new fenced immutable stock and a new
immutable S8 drop-in, then consumes dispatch before one transient coordinator
request. No resume/adoption API, historical edits or ordinary-claim rollback
exists. Ambiguous starts remain consuming. Only a proven owned coordinator
invocation may be stopped on abort; primary/abort/cleanup errors stay separate.

The release envelope separates unchanged historical Git/journal bindings from
the new image/Application pair. It requires source-closure provenance and a
separate time-bound human grant. A tag alone is not permission. The readonly
observer preserves separate S9/S10/S11 RED and never imports the locked checkout.
Configuration and an explicit validated OS DNS snapshot use independent
readonly RAM interfaces; Docker's build resolver is not a runtime dependency.
The permit mount and sealed import paths are unaffected. Initial component
tests (including actual Linux/PID-1 tests) are GREEN; the new complete
provisioning/unknown-start/replay fixture remains a mandatory CI gate.

That fixture substitutes only synthetic incident/history identities, its
disposable database address, public HTTP responses and the existing empty
provider/unrelated-store harness. No lease CAS, permission, journal, systemd or
kernel protection predicate is replaced. It must not be reported as live
acceptance or as exercising real Telegram/provider interactions.

Still required: native full candidate CI, authenticated launch packaging,
retained private-image provenance, coordinated final Same-SHA reviews/merges,
post-merge CI and a new immutable freeze. **No source completion or live plan
approval is claimed yet.** All live actions remain NO-GO.

SOURCE ONLY, INCOMPLETE. No live adapter, source acceptance, merge or freeze is
claimed by these prototypes. Historical R12/ABORTED roots remain untouched.

## Prospective protection boundary

The execution stock must include the full Linux userland, ELF loader/libraries,
Python standard library and hash-locked application dependencies, not merely
three S8 files or a venv pointing at host packages. A private build constructs
the exact Application commit/tree and a dependency inventory. A new freeze must
bind its final complete image hash and reviewed Control/Application provenance.
Neither present metadata nor an unreviewed build is authority.

The kernel prototype copies that complete image to a memfd, checks its digest,
seals write/grow/shrink/seal changes, attaches an atomic readonly/autoclear loop,
and mounts SquashFS readonly in a private namespace. ACLs are omitted from the
image. A chroot and `python -I -B -S` with explicit sealed import paths exclude
host or historical checkout fallback, `.pth` startup and environment injection.
Only narrowly defined read-only runtime interfaces may cross the boundary.
The final unprivileged poller must have no capabilities or inherited writable
journal/source/device handles. This complete launch chain is **not yet proven**.

The trusted host kernel, PID 1, privileged namespace/device administration and
privileged ptrace remain the OS trust boundary. A userspace image cannot defend
against a malicious host administrator replacing the kernel or PID 1. Ordinary
source/image-path writers cannot change sealed execution bytes. Native tests
must attest actual bytes, mounts and process identity, not caller booleans.

## One-shot boundary

Operation, activation and execution consumption are separate durable records.
The activation record precedes the lease observation; failure, an empty/partial
record, lost output, grant expiry or a new process never recreates authority.
The reviewed Application initial CAS remains distinct from normal renewal.
An initial receipt plus fresh stable-owner lease/poll evidence are both needed.

The systemd prototype has a one-shot, RemainAfterExit coordinator. Its failure
stops the bound runtime. Direct starts and automatic restarts are disabled;
durable records, not the volatile systemd rate limit alone, must exclude replay
across reboot or manager state loss. The complete coordinator/installer/observer
adapter and its crash boundaries remain an integration gate.

## Verified delta / still open

- Local native Linux: sealed image write/chmod/xattr/rename resistance and
  unchanged mounted bytes despite replacement of the original image: GREEN.
- Actual PID 1: successful dependency lifetime, coordinator kill, condition kill
  before journaling, repeated starts and manager re-exec: three cases GREEN.
  The success case now also proves readable synthetic systemd credentials after
  the privileged launcher drops to the configured non-root identity. `!` keeps
  the filesystem sandbox; `+` is not permitted. The disposable container needs
  its own shared `/run` tmpfs for systemd's credential-mount propagation; this
  never changes the host's `/run` or its private parent mount.
- Namespace ownership is proved by the successful unshare transition and the
  current process/namespace identity. Reading PID 1's namespace is unnecessary;
  no `CAP_SYS_PTRACE` was added to make that observation possible.
- Native durable journal/protocol predicates: seven cases GREEN.
- Application exact-directory Git reader: 16 focused and 1,123 portable tests
  GREEN; new revision still requires CI and a new exact-head review.
- These are component proofs, **not** integrated Application/PostgreSQL/S11/S12
  acceptance. The live adapter, fresh component attestation, coordinated CI and
  reviews, merges, post-merge CI and new freeze remain mandatory.
- Local Docker has no amd64 execution support. Complete amd64 image/integration
  proof belongs in private Application CI. No host emulation/kernel alteration.
- A full sealed-image negative probe now exercises the real unprivileged
  Application entrypoint with no credentials/network/database interfaces. The
  empty permit must reject before any claim. Its first native CI reached all
  eleven component tests GREEN but rejected the full capsule at the launch
  boundary; no acceptance was claimed. The new image root must explicitly have
  mode 0755 (not inherit a private unpacking-directory mode). Child error
  reporting must not import modules or run parent cleanup after a failed drop.
- Private CI 37338680062 is GREEN: the explicit root mode also passes the full
  sealed-image/unprivileged-entrypoint negative probe. This remains distinct
  from a successful initial claim or complete recovery.
- A real existing failed systemd unit can enter the candidate one-shot path
  without `reset-failed`; the additional local native regression is GREEN.
- Persistent-journal protection is still a construction gate. Native evidence
  proves that immutable flags do not revoke retained writable descriptors.
  Consequently a fresh, empty, append-only directory and an exact-thread open
  permission fence must precede record creation; no adoption of existing files
  or ancestry/root exemption is allowed. All unexpected metadata events are
  fatal, including chmod-and-restore. The new guard is not yet integrated.
  Docker's local 6.12.76-linuxkit rejects the required fanotify permission mark
  with EINVAL; the exact x86-64 native CI must decide support. No kernel change,
  permission bypass or weakened alternative was used. Kernel administration
  capable of removing inode protections is not an authorized writer operation.
- Private Application source/images must never be uploaded to public Control.
- Private CI 37341237050 is GREEN at Application
  `60b6516c691566775f50ef2b0905757367749b07`, Control
  `e4127209c8449afb2ae4975722e558ea9f5ae66f`: all 18 native component cases,
  PostgreSQL 17/18 suites and the full sealed-root negative probe passed.
  This establishes x86-64 support for the permission fence, not support on the
  live server or completed recovery. The next protected-journal adapter binds
  creation, fsync, writable-descriptor closure and immutable handoff under that
  fence. Its parent must already be append-protected; even an interrupted empty
  child directory permanently consumes the one-shot name. No adoption/reset.
- Private CI 37342786816 is GREEN for that protected-journal integration at
  Application `713cdf2d2b3685ed680039dd8a6369a6e29dee2b` / Control
  `814847948b866c7a53406b4503675e8850605266`. Five new native cases cover sealed
  handoff, missing parent protection, lost write acknowledgement, SIGKILL and
  empty-directory replay. The next channel ties its single coordinator writer
  to actual PID-1 ControlPID/MainPID roles and stable process identities; helper
  processes receive sealed responses and never obtain journal write authority.
  This new PID-1/channel combination still requires its own native evidence.
- Private CI 37344071969 is GREEN at Application
  `b7f5e02206db86a14ede3fb8820498a99663716d` / Control
  `bd2a88c00dc11d3b486a0712a6fd09748cebd943`, including actual PID-1 peer roles
  with durable journal consumption and foreign-lease rejection. No App claim
  was inferred from that synthetic channel-only result.
- A real isolated systemd-255 credential probe returned directory 0500 and
  file 0400, both owned by the configured runtime uid/gid. This differs from
  the existing strict App reader's accepted private-file 0600 contract. The
  candidate constructs a private readonly RAM copy with prescribed 0600
  ownership; it never changes the source credentials or relaxes that reader.
  The private permit similarly has a single root-owned nlink=1 readonly RAM
  instance, preserving the App permit contract instead of accepting arbitrary
  memfd/host-path replacements. Both mounts are confined to the owned namespace.
- The next native fixture connects these interfaces to the real App permission
  loader, full tree check, runtime admission branch and original PostgreSQL
  polling trigger. Only external Telegram transport and unrelated notification
  storage are stubs. The same strict loader and SQL path must pass on PostgreSQL
  17 and 18. This is not yet a production-entrypoint/live-adapter acceptance.
- Integrated private CI 37347441485 identified the second real systemd
  credential layout: root 0550/0440 with precisely one read-only named-user
  ACL. Both observed layouts now have exact metadata/ACL checks; extra readers,
  writes, default ACLs, mixed ownership and hardlinks fail closed. Five native
  synthetic regressions pass. The source mount must itself be read-only RAM;
  no arbitrary root-owned file becomes trusted input.
- A native persistent unit-overlay component rejects ordinary startup and
  automatic restart even after a legacy base-unit replacement. Its immutable
  drop-in and directory reject root file writes/deletion/chmod and a later
  bypass drop-in. This is not proof of the still-missing fenced provisioner;
  setting an immutable flag after an unprotected write would be insufficient.
- Native integration reached the credential handoff but caught chmod after
  chown without CAP_FOWNER. The prescribed transition now sets mode before
  ownership; capabilities remain unchanged. The real unit fixture proves that
  ordering with CAP_FOWNER absent. No input credential metadata is changed.
- Canonical S11/S12 source now rejects a separate S8 execution root (including
  incomplete provisioning) before promotion/recovery/deployment/containment.
  Historical application identities remain unchanged. Neither an S8 receipt
  nor an old GREEN can satisfy these other release roles. The metadata-error
  path must not write historical evidence for this pre-admission rejection.
  The actual legacy S11/S12 compatibility suite plus the three new role-boundary
  cases pass natively: 23/23. The isolated fixture needs an executable scratch
  filesystem, not the container's noexec /tmp; no host mount policy was changed.

R15 pause compatibility remains OPEN. Historical causation remains UNKNOWN.

The actual native PID-1 check now passes. The next full-tree read failed because
the exported root has no `/dev/null`; an isolated Linux namespace reproduces
Git's exact O_RDWR failure with that device absent. The candidate exposes only
the descriptor-pinned Linux character device 1:3, metadata read-only, with a
sealed empty mountpoint. No host `/dev` tree or `mknod` permission is added.
CI 37352350907 reaches actual initial admission and subsequent PostgreSQL polls.
Its remaining failure is the test-only targeted reset of already unloaded
synthetic units, reproduced locally. The revised disposable-container replay
case clears volatile counters and requires the exact durable marker rejection,
unchanged protected records and unchanged SQL state. It does not add a live
reset API or treat a generic failed start as replay evidence.
Private CI 37353300488 is fully GREEN at App
`f126fcca6584da2ec488b92080b523a3184a457b` / Control
`4ef37ebd6ce7d7c286af45015baed6fd2d479412`: 31 native components, 23 actual
S11/S12/role regressions, and real initial admission, subsequent polling and
durable replay rejection in the sealed root on PostgreSQL 17 and 18. The
provider transport remains a no-network stub; this is not live recovery.

The candidate bootstrap renderer embeds the exact digest-bound Control modules
in PID 1's loaded Python `-I -B -S -c` command. It does not import a mutable
Control checkout. Three local checks, including real PID 1 with a malicious
PYTHONPATH module, pass. The integrated native fixture now uses this same
renderer; its new complete CI result is still required. The final installer,
dispatch consumption before the PID-1 start request, reviewed role manifest
and actual observer adapter remain construction gates.

The next dispatch boundary consumes a fresh protected directory and sealed
intent **before** the PID-1 start request. Only the original live dispatcher
can hand a sealed response once to the actual coordinator MainPID/invocation.
An unknown start result, process loss or repeated dispatcher cannot recreate
that channel. The native integrated fixture now exercises this boundary before
its existing condition/execution/SQL protocol; four additional native cases
cover interrupted pre-start, lost acknowledgement, replay and a foreign root
peer. Their native CI evidence is pending. There is still no live CLI/grant.

CI 37354719304 is GREEN at App `40aef25e5007e2f7cd8a94cba4766733d772d302` /
Control `c4b705e425c55cf2307b38bc9555a99aecddf5d3`: all 38 native component
cases and both real PostgreSQL chains pass with the frozen PID-1 command and
pre-start durable dispatch boundary.

The provisioning candidate now watches the parent before creating a new stock
name, durably records the exact content/mode/ACL plan, fences file creation and
seals each inode only after closing its sole writer. Interrupted/preexisting
paths cannot be adopted. Its optional append-only state child does not make
sealed execution files writable. Parent rename-and-restore is locally detected;
the complete five-case native stock suite is pending.

The integrated fixture is also tightened to load the unchanged historical S8
unit (SHA-256 `fcad30a40a51ac9d45472cbe3e5eb607ccf117f820fe7f9a5d581f455aa63665`)
with the actual candidate drop-in. That base has `PrivateDevices=yes`, which
hides required loop interfaces. The candidate explicitly permits only loop
devices to the privileged launcher under closed device policy. The final
non-root capsule still has zero capabilities, no loop descriptors and only the
validated null-device interface. All other compatible historical hardening is
retained; native full-image proof over this exact base is required before GO.
S9/S10/S11 RED is not cleared by this work. Recovery, deployment, unlock,
R15 containment and every product hard gate remain NO-GO. No live steps are
executable or authorized until the full source contract and a separate live
approval exist; failed attempts must retain consuming evidence and stop.

The production provisioning integration exposed a read-only SQL type error:
the canonical owner is UUID. The adapter now hashes its explicit text form;
no SELECT-only, admission or ownership predicate changes. Native full-chain
verification remains mandatory. The deterministic self-contained installer
offers only `preflight` and `execute`, never grant generation or resume. A
preflight result is not reusable admission. Preparation requires absent
coordinator/dependency units; cleanup errors survive a later successful close.
