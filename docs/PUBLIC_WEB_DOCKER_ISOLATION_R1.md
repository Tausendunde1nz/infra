# Public web service Docker isolation — R1 source contract

Applies only to `tu1nz-adult-public-s7`, `tu1nz-adult-public-s8-landing` and
`tu1nz-adult-public-s10-wms`. Not the S8 Telegram recovery/atomic-admission
mechanism. No R2 slot, historical release, application source or base unit
is changed. No live change is authorized by this document.

## Reason and boundary

Existing `User=chatops` processes inherit administrative NSS groups even
with `SupplementaryGroups=` and `NoNewPrivileges=true`. The three public
runtime paths do not use Docker. Their UID/GID1001 data/credential/DB-peer
contracts are retained instead of changing global account membership or
migrating shared S9 state. Public application code must run with groups[],
all five capability sets zero and NNP1. It must not borrow the same-UID
operator's process-root namespace or home credentials.

Three additive `zz-public-isolation-r1.conf` profiles invoke one finite,
root-owned bootstrap through systemd's `!` prefix. This skips the manager's
early credential drop ONLY for that helper; the inherited mount/filesystem,
home/device/kernel/network protections stay in place. `PrivateUsers=no`
avoids a manager-created namespace that forbids the necessary group drop.
It does NOT authorize an unnamespaced application: the helper first clears
groups, creates one owned child user namespace, installs ONLY maps
`0:0:1` and `1001:1001:1`, denies setgroups, joins and reaps that child,
then drops UID/GID, all caps and bounding/ambient caps before application
imports/exec. Missing support, wrong identities/maps, interruption or any
failure denies; no fallback/initgroups/arbitrary command/user/PID exists.

Bootstrap trust is explicitly limited to the reviewed helper/interpreter,
systemd manager, exact unit configuration and immutable administrator-owned
installation paths. It initially needs namespace/mount/credential-drop
privileges. Applications never inherit them. It is NOT a blanket root
exception or protection from a compromised host TCB. The helper becomes
non-dumpable before reading credentials. It signals only its unreaped child;
primary, abort and cleanup error codes are separate and data-free.

S7's two manager credentials are read from the exact read-only private
credential inventory. A namespace-local, noexec/nodev/nosuid tmpfs view is
filled with exact bytes, UID/GID1001 mode0600, sealed read-only and read back.
This preserves the unmodified application parser instead of accepting a
new credential profile. Original manager input files/mounts are unchanged;
no persistent secret file is created. The manager tears down the private
namespace on stop/failure. No memory-zeroization guarantee is claimed.

Common Docker/containerd/rootless-runtime paths are also masked in the
service namespace. DAC group removal is independently tested against an
unmasked synthetic administrative socket. Arbitrary alternate TCP/UNIX
brokers, ACL-based grants, retained activation descriptors, account-based
sudo/polkit delegation and host configuration are NOT proven absent by
offline tests. Socket activation is rejected by the helper. These remain
fresh Host admission gates; discovery of effective alternate authority
blocks application/R2 admission, not an excuse to rename it trusted.

## Evidence and release gates

`tests/public_web_isolation_native.sh` is mandatory in Control validation.
It uses a pinned Ubuntu source image, disposable isolated PID1, network none,
read-only source, synthetic data/credentials/daemon sockets only. It does
not mount host systemd, credentials or historical repositories and does
not repeat the previously blocked systemd ancestor/name-reuse investigation.

Native assertions cover actual groups/caps/maps/NNP, default and unmasked
administrative socket denial, operator proc-root/home denial, state atomic
replacement/ownership, S7 read-only0600 material, DB peer1001:1001, all three
profiles across a controlled stop/start, nonroot/nested/missing credentials,
kernel namespace denial and actual SIGTERM creator cleanup. Portable tests
cover finite inputs/account/maps/group failure and separate error provenance.
The native functions use synthetic application stand-ins: they do not prove
real provider behaviour, current Host isolation or full application HTTP
health. Existing application runtime code is unchanged; targeted function
regressions and later actual Host acceptance are separate evidence.

Source closure requires full existing mandatory CI plus this native gate,
independent review on the final exact head with no open valid findings,
regular merge and full post-merge CI. Old R2 GREEN and frozen tags do not
accept this change. Host rollout still requires the separately confirmed
[Host plan](PUBLIC_WEB_DOCKER_ISOLATION_R1_HOST_PLAN.txt), current gates and
fresh functional/rights acceptance. Live/R15/RC5/Telegram/Runtime remain NO-GO.
