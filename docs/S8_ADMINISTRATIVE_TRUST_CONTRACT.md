# S8 administrative systemd-integrity boundary — accepted Source decision

Decision date: 2026-10-09. Model: `TU1NZ_S8_ADMIN_SYSTEMD_INTEGRITY_V1`.
**Intentional residual-risk acceptance, not equivalent technical protection.**
This decision authorizes Source changes and conditional Source closure only.
No host observation, runtime grant, provider action or live acceptance results.

## Provenance and narrowly replaced guarantee

The user's Source decision SHA256 is
`4f25541e8d56c012154f6880079faf481dc00abf7c455403a3247cc0fbd674f3`.
It accepts **all conditions**, including section 6, of the unchanged private
`SECURITY_MODEL_DECISION-20261009.txt`, SHA256
`925c75e2486b1a7bb79c119497533e3894fd16989c55b8aeaa9cf0adae448d86`.
The private decision and original evidence are retained, not publicly copied.

Only the release guarantee Q against **identified, explicitly administratively
namespace-write-authorized actors**, including capability-free root filewriters,
is replaced by the administrative integrity assumption. Mistake or compromise
of those actors is accepted residual risk. There is no blanket UID0 exemption.
The entire effective systemd configuration selection is an administrative TCB
input: paths and ancestors, aliases, unit/prefix/type drop-ins, generators,
transient inputs, actual loaded execution and administrative/helper APIs.

Original synthetic component visibility remains **FALSIFIED**; original Q
remains **historical OPEN / PLATFORM_BLOCKED**. Actual S8 transfer and complete
admission/lease bypass remain **NOT PROVEN**. Neither the decision nor a green
new CI rewrites those results. The blocked investigation is not run indirectly
through a fixture, code review or CI. The different retained `/etc/tu1nz`
counterexample/anchor regressions are not evidence of systemd namespace Q.

## Rights boundary and mandatory pre-live acceptance

Every administrative actor needs a concrete identity, named role and documented
authorization. All nonadministrative services, **including UID0 helpers**, must
have **no effective authority** to modify configuration selection, directly or
through systemd/PID1 or privileged helpers. Capability absence is not evidence
of read-only DAC; UID0 ownership may still confer direct namespace write.
Unknown, conflicting, incomplete or insufficiently separated rights deny live.

Grant V3 requires `TU1NZ_S8_SYSTEMD_ACCEPTANCE_V1`, bound to the same fixed slot,
exact freeze digest and host/machine/boot/root/mount/namespace digest. It carries
an independently accepted current rights inventory, not a default GREEN:

- `configuration_selection`: enumerate every actually effective input/search
  source, aliases, generators, transient sources and relevant ancestors.
- `loaded_execution`: retain exact loaded fragment/drop-ins/Exec commands,
  cleared auxiliary hooks/environment inputs, restart/dependency/sandbox and
  credential settings; compare with the frozen renderer and historical unit.
- `ancestors_dac_acl_flags_mounts`: effective read/write/delete/replace rights,
  ownership, ACL masks/defaults, security xattrs/flags and mount overlays.
- `actors_credentials_namespaces_fds`: all relevant services, jobs and helpers;
  process/start/boot identities, UID/groups/capabilities, namespaces and open FDs.
- `sudo_polkit_dbus_helpers`: effective delegated administrator/PID1/helper
  authority, not only executable access or effective capabilities.
- `maintenance_exclusion`: documented window, identified administrative roles,
  no competing unit/package/restore jobs or unrestricted TU1NZ/Codex root shell.

Each scope has a protected evidence digest. Every actor has unique identity,
role, authorization and rights-evidence digests and explicit effective direct,
manager-API and helper-API authority. A nonadmin with any such authority denies.
Missing/unknown fields, duplicate/conflicting identities, unbound host/release,
missing roles or incomplete inventory deny. Inventory observation precedes
grant issue by at most 300 seconds; its expiry cannot exceed the grant expiry.
The same acceptance is checked at existing pre-mutation and pre-admission grant
checks, never inferred from a future successful poll or a new stock name.

**The parser cannot prove truthful or complete inventory collection.** The
operator must independently inspect and accept protected raw evidence before
binding it to actual human live authorization and pinning the complete grant
digest outside staging. No tool here generates a live acceptance or grant.
Synthetic fixtures only prove schema/admission behavior. Rechecking an
attestation/time window is not continuous namespace protection. Observed drift
still denies; monitoring cannot guarantee timely prevention of external effects.

If a nonadmin writer is found, do not reclassify it merely because it is root:
stop and separately decide its exact rights/sandbox/helper correction. No new
host file/privilege change or protection of existing ancestors is authorized.

## Preserved guarantees and consequences

The slot remains `s8-same-release-20261004-1`, irrespective of freeze or stock
name. The only planned path exception is `/tu1nz-s8-admission-anchor-v1`.
Early durable consumption, canonical one-shot dispatch, actual SQL first CAS,
separate renewal, interruption/lost acknowledgement/process end/boot-bound
replay refusal, object/ACL integrity, observed configuration selection checks,
Primary/Abort/Cleanup separation and historical ABORTED/Git evidence remain.

If administrative integrity fails, PID1 might select the old ordinary entry,
which need not run the anchor check. One-shot/abort/restart/lease and protection
from Telegram actions could then fail. This is a conditional consequence, not
a demonstrated full bypass. Replies, notifications, community/moderation and
retention effects are not fully reversible. No automatic reset, AVAILABLE
restore, new slot, old-consumption backup restore or recovery after trust loss.

Before any live mutation: independent current writer acceptance; actual host
kernel/filesystem/fanotify/flags/fsync/mount/sandbox/credential/handoff evidence;
protected and read-back-verified metadata/DB-consistent backups; exact incident
lease/release/history, public-service and current S11/S12 binding checks; actual
queue/provider effects assessment and separate explicit human live permission.
Physical reboot/power-loss/restore evidence is not synthetic changed-boot proof.
These host gates are **UNKNOWN, LIVE NO-GO**, not failed Source tests.
S9/S10/S11 RED, R15 pause compatibility OPEN, historical cause UNKNOWN and
product gates CLOSED remain separate. R15 and all live operations remain NO-GO.

## Exact assessment delta and Source closure gates

Proposal inputs: Control `5c6275b4177710280f4b4890b039590960f90da5`,
Application `e0070ef37285d714973462bccd9347f8256b93cc`.
Verified session inputs: same Control; Application
`db08c37b207d51663e4dddb84b29d8bcfb6239be`, tree
`e93435f6d52689141ac78cde750951ea5a280639`.
The Application diff is exactly two Control pins and integration documentation.
Both `src` subtrees are `1e2283c75bbf517e147a29f1cc83807e9971e75a`;
runtime, configurations, migrations and dependency locks have no delta.
Thus the proposal's runtime consequence analysis remains applicable; its CI
bindings are not transferred. db08's full paired CI37932813769 and exact review
issuecomment-6081382038 are separately verified historical inputs.

New changed-model closure still requires full native Control and paired private
Application Linux/PID1/PostgreSQL CI, unchanged protection tests, independent
exact-final-head reviews without open P1/P2, merge trees equal to reviewed
trees, post-merge CI, and a new create-only Source freeze with exact model,
sources/image/configuration/history and review/CI provenance. Historical tags
remain unchanged. Correct status is **Source GREEN under changed model** only
after those gates, never original-Q GREEN or current host/live acceptance.

## Review correction: path-witness cleanup provenance

Review of Control `22cf352fa85d98a0f8faa55a51858ead4ffa2aeb` identified a
descriptor-close error that could stop remaining closes or mask the original
integrity failure. Path-chain and parent-creation witnesses now attempt every
owned resource once, detach each descriptor before close (no ambiguous-close
retry on a reused FD), aggregate redacted cleanup errors, and preserve the
original exception including any separate abort record. Cleanup-only failure
remains RED. Portable multi-error cases and native real-FD/lost-acknowledgement
and constructor-failure regressions cover this correction, not namespace Q.
This correction requires new exact-head CI/review; earlier GREEN is historical.

A subsequent exact-head review found the same masking pattern in parent
metadata and the protected-journal constructor's final descriptors. The shared
descriptor/resource scopes now preserve the body's primary error, attempt all
owned closes independently, and make cleanup-only failure RED. This also
replaces that identical pattern in adjacent S8 journal, stock, authenticated
input, mount/image and handoff lifetimes. Descriptor/owner references are
detached before ambiguous closes; sealed-image ownership is transferred only
after its input closed successfully. Redaction failure cannot skip cleanup.
Synthetic portable faults and real native metadata/journal/sealed-FD cases
cover primary, abort, multiple cleanup, consumed-name retention and no retry.
No admission, rights predicate, host path, privilege or namespace-Q test changes.
The worker retains its original failure and mounted-image cleanup never
unmounts a foreign object or treats an ambiguous close as successful release.
New exact-head native CI and independent review remain required; these local
fault injections are not host acceptance or a rerun of the historical Q probe.
