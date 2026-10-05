# S8 isolated execution root — construction checkpoint

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

R15 pause compatibility remains OPEN. Historical causation remains UNKNOWN.
S9/S10/S11 RED is not cleared by this work. Recovery, deployment, unlock,
R15 containment and every product hard gate remain NO-GO. No live steps are
executable or authorized until the full source contract and a separate live
approval exist; failed attempts must retain consuming evidence and stop.
