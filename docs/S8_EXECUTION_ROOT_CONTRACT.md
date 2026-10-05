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
- Native durable journal/protocol predicates: seven cases GREEN.
- Application exact-directory Git reader: 16 focused and 1,123 portable tests
  GREEN; new revision still requires CI and a new exact-head review.
- These are component proofs, **not** integrated Application/PostgreSQL/S11/S12
  acceptance. The live adapter, fresh component attestation, coordinated CI and
  reviews, merges, post-merge CI and new freeze remain mandatory.
- Local Docker has no amd64 execution support. Complete amd64 image/integration
  proof belongs in private Application CI. No host emulation/kernel alteration.
- Private Application source/images must never be uploaded to public Control.

R15 pause compatibility remains OPEN. Historical causation remains UNKNOWN.
S9/S10/S11 RED is not cleared by this work. Recovery, deployment, unlock,
R15 containment and every product hard gate remain NO-GO. No live steps are
executable or authorized until the full source contract and a separate live
approval exist; failed attempts must retain consuming evidence and stop.
