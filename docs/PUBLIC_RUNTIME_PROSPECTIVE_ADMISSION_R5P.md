# R5P: finite prospective Hostpolicy/role addendum

Implementation extension: the **CONTEXT_V1** section at the end is a separate,
strict schema. The original V1 four-role contract below remains unchanged for
its closed Source bytes; it does not attest this extension or accept contexts.

This addendum amends only the **origin/legitimation basis** for the finite rows
below. It is not a Host capture, an acceptance of unknown present state, a new
execution attempt, or publication permission. Original contracts remain:
`PUBLIC_RUNTIME_REPLACEMENT_R5.md` and `PUBLIC_WEB_PRODUCTION_OPERATOR_R4.txt`.
Their fences, Source authentication, privileged execution, backup/restore,
Owner and HOLD contracts are NOT replaced. Current Lighting admission is
separate: original R2 or complete WMS product readiness is not added as a
Lighting prerequisite by this addendum.

## Authority and risk (required in every actual acceptance)

For machine SHA256
`a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae`,
the exact captured boot and transaction `public-rights-20261014-1`, an
independently reviewed, explicitly human-accepted **present** configuration and
role set may first become normative prospectively. This does not assert its
historical installation or historical integrity. No general UID0, system.slice,
process-name, administrator-role or `trusted=true` exception exists.

Trust is placed in the selected Host kernel/PID1/authenticated maintenance TCB
as measurement and enforcement substrate. A previously privileged-compromised
Host could falsify the read, process view or policy view. Independent semantic
review, matching Publisher bytes and off-Host hash copies do NOT exclude that
possibility or prove unchanged process memory or historical integrity. The
human must accept this exact residual risk for the actual annex hashes, not
merely choose this preparation path. Required literal risk identifier:
`CURRENT_HOST_TCB_MAY_FALSIFY_CAPTURE_NOT_HISTORICAL_INTEGRITY`.

## Finite annex scope and normative limits

### B-H: Host configuration, not executable provenance

Exactly `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, `/etc/sudoers`,
`/etc/hosts`; and **every** named regular leaf of exactly these policy roots:

* `/etc/polkit-1/rules.d`
* `/usr/share/polkit-1/rules.d`
* `/etc/sudoers.d`
* `/etc/dbus-1/system.d`
* `/usr/share/dbus-1/system.d`

Root membership is an exact, sorted, unique basename list, at most64 per root.
An actually verified empty root is representable; missing root/list is not.
Every effective include and authorization effect must be explained in review.
Unknown include paths, executable policy, unreadable entry or rules outside the
unchanged parser/negative-authorization contract remain DENY. This schema does
not make arbitrary sudoers/Polkit semantics safe. NSS keeps the original exact
numeric subjects1001/chatops and33/www-data, without duplicate subject aliases.
No shadow/password/private-key file is in the read scope.

The existing three systemd fragments plus Landing `s9-growth.conf` are the
only four original Unit/drop-in files. Their bytes still match the four
frozen Git blobs pinned by `PROSPECTIVE_UNITS`; their prospective contribution
is metadata, NOT a waiver of Git origin. Extra loaded drop-ins, UnitPath input,
hooks, environment overrides, manager authority or unknown policy still DENY.

Regular B-H/Unit values: exact SHA256,uid/gid0:0,integer mode0000..0777,
no group/other write and no execute bits; attrs exactly empty; filesystem flags
only0 or0x80000. No chmod, ACL/flag removal or normalization is authorized.
A mismatch requires a concrete decision, not silently wider accepted values.

### B-R: every required actor, exactly four existing role classes

Each profile includes **all**: role,exe,exe_sha256,uid,gid,groups,caps,nnp,
argv_sha256,cgroup,initial_env_sha256,lsm_sha256,namespaces,max_instances.
The baseline additionally points `origin_sha256` to the prospective binding.
Every profile has a32..2048-character independent justification of its actual
task, necessity and minimum privileges. A UID or cgroup alone is not one.

UID/GID are exact four-integer vectors; groups are an exact nondecreasing list
of unsigned32-bit integers (at most65536), **including duplicate entries**.
Neither schema, measurement nor comparison deduplicates/sorts a measured list:
membership, multiplicity and any additional GID remain bound. No NSS/primary-GID
inference substitutes for the measured supplementary list. A narrower/different
list is also a mismatch, not an automatic permission to proceed.
All five capability sets are exact unsigned64-bit integers; nnp integer0/1;
argv/environment/LSM represented by exact SHA256, not published raw values;
pid/mnt/user/net namespace identities are exact. Executable canonical paths
are finite under /usr/bin,/usr/sbin,/usr/lib,/bin,/sbin with separately
authenticated byte origins. No name glob, extra role, omitted actor or wildcard.

`cgroup` means the **complete structured `/proc/PID/cgroup` contents**, removing
exactly its final LF, not an extracted path. Each record is
`hierarchy-ID:controller-list:absolute-path`; LF separates multiple records.
The same bounded parser is used by the annex schema, leader/thread measurement
and exact actor comparison. Hierarchy IDs, named/v1 controllers, their order,
all records and paths are retained; values are never sorted, reduced to one
hierarchy, trimmed or rewritten to an assumed `0::` prefix. v2's record has
ID0 and an empty controller list; positive IDs require nonempty controllers.
Duplicate hierarchy IDs/controllers, malformed numbers/records, control
characters and noncanonical/relative paths fail closed. Paths may contain
colons or printable spaces; these are data, not field/whitespace normalization.
Bounds:64 records,262144 characters total,4096 characters per absolute path.
The full value must match exactly, including hierarchy/controller changes even
when paths agree. An administrative-service role additionally requires **every**
parsed path to start with `/system.slice/`; a substring or one chosen row cannot
hide another context. This grammar does not authorize v1/hybrid execution or
change the existing v2 unit/invocation checks, role/ancestry/namespace/instance
limits, Unknown-Deny, publisher origin, claims or any execution permission.
Old path-only profiles are rejected, not silently upgraded or reaccepted.
Only synthetic fixtures enter public source/CI; real context decisions and
specific prospective annex acceptance remain separate private human decisions.
Format reference: [Linux kernel cgroup documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#organizing-processes-and-threads).

Instance limits are additional ceilings, never permissions to add processes:

| Existing role | Per exact profile ceiling | Additional condition |
| --- | ---: | --- |
| kernel_manager | 1 | exactly one total; exact UID/GID0 vectors; actual PID1 check retained |
| authenticated_maintenance | 8 | original authenticated ancestry/invocation/namespace checks retained |
| administrative_service | 16 | exact /system.slice/ cgroup **and** independently justified task |
| nginx_reader | 16 | UID/GID33 vectors,groups[33],no active/inheritable/permitted/ambient capabilities |

All four classes must be represented;4..256 profiles, total declared instances
at most256. Actual exact profile counts and full process/thread/FD/mapping/broker
census remain compulsory; these maxima do not waive the original rules.

### B-M: selected metadata and no-follow namespace graph

`metadata` is exactly B-H + four Unitfiles + cache + every canonical actor/
probe/operator executable, Stdlib/DSO source and dependency alias row. Existing
baseline/operator rows must match; additional selected TCB rows have exact
annex values, not a second looser set.
Operator executables/DSOs may have execute bits but never group/other write;
uid/gid0:0,attrs empty,flags0/0x80000. Their **bytes** retain Publisher/Git origin.
This does not convert other application configuration rows to prospective rows.
The cache remains non-executable. Every selected regular metadata row is compared
before claim and freshly on the existing loader checks, including filesystem
flags; alias rows must agree on their canonical file. No optional partial set.

`names` is the exact no-follow directory/link graph derived from all baseline
files, all actor/probe/operator executable inputs, dependency aliases and all
five policy roots, including every intermediate alias target and ancestor.
No unrelated path can be added. Directories:0:0,no group/other write,attrs empty,
flags only0/0x1000/0x80000/0x81000; links:0:0,0777,attrs empty,exact target,
actual single-link identity enforced by existing R5 loader fence. Existing
Paths and loader-name watches bind these before following, before claim, and
retain exact identity/events during the transaction. No alias is rewritten.
Unexpected graph, cycle, missing parent or unsafe profile is DENY. Not all
directory flags imply a security error; only this explicit finite profile is
accepted, with existing live normalization/check rules unchanged.

## Private material and exact schemas

Use existing repeated `--origin FILE`; no new generic Host reader/collector or
acceptance flag. All selected original evidence is preserved. Inputs private
regular files0600 owned by the caller, single-link, no-follow. No actual Host
annex, raw policy, credentials, argv/environment or private hashes belong in
public Git, public CI logs, artifacts or caches. Synthetic test fixtures only.

New approved scope `TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5P_V1` has every R5
field unchanged and exactly two additional SHA256 fields:
`prospective_binding_sha256`, `prospective_acceptance_sha256`.
The final independently approved Scope SHA still selects exact Source release,
baseline, full actors, Origin list, Host, TX, original Owner plan and canonical
runtime receipt. No program manufactures that independent approval.

Binding `TU1NZ_PUBLIC_PROSPECTIVE_BINDING_V1` exact keys:
`schema,machine_sha256,boot_id,transaction,capture,host_files,unit_files,
policy_roots,actors,metadata,execution_origins,names`.
`capture` exact keys: `read_scope_sha256,reader_source_sha256,
read_receipt_sha256,started_at,finished_at`. File rows:
`sha256,uid,gid,mode,attrs,flags`; actor items:`profile,justification`.
Metadata rows:`uid,gid,mode,attrs,flags`.
Directory names:`kind=directory,uid,gid,mode,attrs,flags`;
link names:`kind=link,uid,gid,mode,attrs,target`.

Acceptance `TU1NZ_PUBLIC_PROSPECTIVE_ACCEPTANCE_V1` exact keys:
`schema,binding_sha256,machine_sha256,boot_id,transaction,release_sha256,
owner_plan_sha256,review_sha256,human_decision_sha256,accepted_at,expires_at,risk`.
Capture scope, exact reader Source, read receipt, independent review and human
decision are five distinct, material, hash-bound evidence files, each≤256KiB;
not names or empty placeholders. Read scope/review/decision must in substance
bind exact objects, effects, privileges, hashes and this explicit risk. The
validator verifies material identity, NOT the identity/authority of an author;
the external independently approved Scope SHA supplies that selection.

UTC timestamps must be exact second-resolution Z form. Capture wall interval
≤300s; capture end≤acceptance≤current time≤expiry≤capture end+24h, same exact
boot. This is an annex validity bound, not a changed20/120/600s execution limit,
and does not create an unattended maintenance window. Selected transmitted
evidence total≤1MiB, original packet ceiling4MiB remains.

Byte receipts `TU1NZ_PUBLIC_BYTE_ORIGIN_V1` are explicitly separate:
`schema,basis,source_evidence_sha256,objects` (path→byteSHA256,1..512 entries).
Basis for executable/Stdlib/DSO inputs is PUBLISHER or GIT only; all actual
actor binaries and exact probe/operator closure must be covered. Four Unit
bytes use GIT. Existing other non-executable static /etc files may use PUBLISHER/GIT/PRIOR_RECORD;
other baseline paths still require PUBLISHER/GIT (never a prior-record byte waiver).
The existing cache uses CACHE_DERIVATION, retaining its closed independent
input-coverage/MATCH evidence; no historical cache-creation requirement.
Each typed receipt references1..8 actual original provenance files. No nested
typed-receipt cycle, prospective binding/review/decision as Publisher origin,
or self-hash assertion. A type label is not authentication: the independent
material review must verify the actual Publisher/Git/derived evidence and
complete consumption/alias coverage. U1/full TCB is not waived by R5P.

Binding/acceptance are validated locally **before** successful no-execute output
and repeated remotely **before** adapter/claim; exact graph/profile observations
then occur before the client custody claim. Acceptance validity is rechecked
after preparation and at client custody/
claim handling, so read-only preparation cannot consume an expired approval.
Selected evidence is carried once
as private framed base64; full Runtime receipt is not needlessly duplicated.
Old scopes cannot carry new prospective receipts; removing the R5P schema cannot
authorize these new prospective origins. No actual annex is shipped here.

## Prepared later privileged read — NOT authorized by this Source change

1. Select exact finalized Source/reader bytes and the complete finite input
   matrix from already authenticated material; independently check coverage.
   Do not start with an unbounded inventory or a new library search. Missing
   executable/Stdlib/ELF material remains a separate concrete blocker.
2. Before any privilege: human authorizes the exact read-scope hash, exact
   reader Source hash, fixed machine/boot/TX,≤300s wall ceiling and private
   custody paths. The preparation instruction does NOT authorize this read.
3. Sole existing authenticated chatops/SSH path; supervised local TTY sudo only
   when separately authorized. Password never in chat/argv/files/logs. Read
   machine/boot/architecture, exact B-H bodies+metadata, effective include/root
   names, four Unitbytes+loaded typed configuration, complete exact B-R
   profiles, selected B-M no-follow graph and actual finite TCB coverage.
   Secret config fields and argv/environment remain private hashes/redacted
   review material, never public output. No production data query.
4. Read errors/EACCES/unknown role/include/namespace/policy/extra file or missing
   TCB member mean incomplete/DENY. No installation, fallback, rights change,
   file staging, service action, authorization trial, claim/slot/window/reset.
   The separate existing execution negative-authorization checks remain later.
5. Secure two existing local custody areas0700/files0600, preserve originals,
   hash/read back each exact byte and manifest; same-Mac copies are not physical
   redundancy. Material and semantic review must be independent of the reader.
6. Independent review checks complete sets, each policy effect/admin task,
   necessity/minimum privileges, Publisher/Git comparisons, aliases/ancestors,
   no unknown authority and all unchanged safety conditions. Hash-copying or
   UID/cgroup matching alone is insufficient.
7. Present actual Binding/Review/Decision/Acceptance hashes, scope and residual
   risk to the human. Only explicit acceptance of those concrete annexes may
   supply `human_decision_sha256`; this preparation's approval cannot do so.
   Independently approve exact final whole Scope SHA separately. Then validate
   the original full production CLI **without --execute** and preserve result.

If this reveals unsafe state or requires wider roles/paths/values, HOLD before
claim and present that exact decision; no automatic repair chain. After complete
admission only actual supervised TTY maintenance readiness and exact timing are
asked, not a repeat general R5/Owner approval. Existing create-only Runtime93555,
three exact R5 drop-ins, same artifact receipt and forward-only HOLD approval
remain valid. Stop-only originals, writer closure, real backup/readback/isolated
restore/probes, S7→Landing→WMS actual function,84Owner ACKs/OWNER_COMPLETED and
cleanup remain mandatory.88objects=82files+6directories;84Owner actions=
78files+6directories;4root-owned files unchanged. No extra Owner scope.

## Source completion, not Host GO

Targeted portable regressions plus all original mandatory CI gates are required;
skipped/neutral native gates are not PASS. Independent final Same-SHA review,
exact PR head/base/testmerge binding, regular merge and automatic postmerge CI
must bind the new Source release. Old valid Source/Cache/Artifact evidence is
retained but cannot attest new code bytes. Required Environment admission for
the actual exact PR merge ref and normal configured-reviewer approval are
separate; no administrator bypass or Browser/Settings workaround. Any necessary
personal Settings action is collected with actual PR/SHA/Run IDs.

This Source change does not accept real annexes, grant privileged read, start
maintenance, consume a claim/slot or publish Lighting. After actual complete
Rights/Owner closure, pass exact completion evidence to the existing Lighting
chat; publication permission and context/claim remain there separately.

## CONTEXT_V1: finite coexistence TCB (separate, not yet Host acceptance)

This implements Approach A: retain the entire Host Userspace/Thread census,
add explicitly trusted finite subjects, **not** isolation or proof of absent
future writers. No generic Root, Docker, chatops, child, prefix or unknown
exception is added. The existing four roles, authenticated ancestry, precise
operator/stop/runtime exceptions, manager/Owner/policy/runtime/backup fences,
all-process writable-FD/shared-mapping checks and their deadlines remain.
Container or ordinary user-session subjects cannot fall back to a HOST role.

The new strict schema names are:

* `TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5P_CONTEXT_V1`;
* `TU1NZ_PUBLIC_HOST_BASELINE_CONTEXT_V1`;
* `TU1NZ_PUBLIC_PROSPECTIVE_BINDING_CONTEXT_V1`;
* `TU1NZ_PUBLIC_PROSPECTIVE_ACCEPTANCE_CONTEXT_V1`.

They retain every original field. Baseline and binding additionally require
exact `contexts`. Every actor additionally requires `context_id`: `HOST` for
the original four roles, one finite D/U ID for a new role. Acceptance risk is
exactly the ordered list of the original risk above and
`SELECTED_COEXISTENCE_TCB_CAN_INFLUENCE_R5_NOT_ISOLATED`.
Old/new schema mixtures, missing fields, extra fields and downgrades DENY.
The validator checks material identity; independent semantics and actual human
authority still come from the separately approved complete Scope SHA. Nothing
here creates a real annex, read approval, Context acceptance or execution GO.

### Fixed profiles, no replacement pool

`coexisting_container_tcb` contains D1..D6; `coexisting_user_tcb` U1..U7.
`PROGRAMS` in `tu1nz_public_operator_context.py` is the exact program/ceiling
table: D1 at most11 (s6-svscan1, s6-supervise5, s6-ipcserverd1,
s6-linux-init-shutdownd1, Jellyfin1, Bash1, sleep1); D2 Grafana1; D3/D4/D6
Python3.11 each1; D5 Node1+tini1. U1 systemd1, U2 systemd-executor1,
U3 Bash1, U4 ssh-agent1, U5 tmux1, U6 Bash1, U7 dbus-daemon1.
All13 context IDs must have at least one member; total at most24, no spare
wildcard slot. Original role counts plus new counts remain at most256.
These are synthetic public slots, not authentication of actual applications.

Context exact fields: `id,kind,full_cgroup,anchor_pid,anchor_starttime,
root_identity,namespaces,uid_map,gid_map,setgroups,profiles,instance_policy,
authority_edges,code_inputs,purpose_evidence_sha256,review_sha256`.
`instance_policy` is exactly `mode=transaction-pinned,members`; each member
is exactly `pid,starttime,profile_sha256`. Profile hashes select all15 fields,
not merely executable/UID. PID/start/image/root/namespace changes, extra or
missing members, exception overlap, unknown views and bounds yield HOLD;
never adopt a replacement, stop a service or end a session. Tasks are stable
and individually bound to the same held domain root, in addition to all
original double credential/namespace/IDmap/KCMP_FILES checks.

Each D cgroup is one exact v2 `docker-<64hex>.scope` under system.slice;
each U one exact user-1001.slice context, UID vector exactly1001. Full raw
cgroup record equality is preserved. U roots and PID/mount/user namespaces
must equal the real Host root/PID1 view; namespace IDs alone are insufficient.

### Domain-specific authentic code and native fences

`code_inputs` exact fields: `files,names,aliases,executable_mappings,
dynamic_risk,mountinfo_sha256`. Each canonical file has
`sha256,origin_sha256,uid,gid,mode,attrs,flags`; origins remain actual Publisher
or Git material. Image tags/current hashes/Compose labels are NOT origins.
The no-follow name graph has the original directory/link metadata fields;
aliases map exactly to selected canonical files. U shared-Host bytes must
agree with original Host inputs. Files are keyed by `(context_id,path)`, not
merged with Host paths. Host busctl/loader/DSOs remain Host-bound.

Hold root/namespace/pidfds; use only `openat2(IN_ROOT|NO_MAGICLINKS|
NO_SYMLINKS)` for code and explicit finite alias traversal. No setns/chroot/
foreign execution/fallback resolver occurs in the operator. Every executable
file-backed map is bound through map_files to the exact held code inode and
mount ID; new/deleted/memfd/unreadable maps DENY. Anonymous dynamic memory is
explicitly `DYNAMIC_MEMORY_NOT_ATTESTED`, not silently proven immutable.
Selected executable, interpreter, loader, script/payload, alias, policy and
dependency inputs must be complete in the actual independently reviewed annex.

Code watches and passive exec marks precede two stable full byte reads.
Inotify protects selected file/name identities. A separately armed foreign
`/proc/PID/mounts` poll epoch permanently latches any subsequent change,
including overmount/unmount-and-return; it is never reset to accept events.
Full mountinfo hashes independently bind topology. Passive fanotify OPEN_EXEC
with REPORT_PIDFD latches a pinned actor's same-image/away-and-return exec;
it is not a JIT/interpreted-memory integrity proof or permission mediation.
All proc reads reach actual EOF with sentinel bounds and the unchanged outer
deadline before every physical read. New code inodes join the existing
all-process Writer target union; trusted subjects receive no Writer exemption.

Limits: selected files512 total, names including HOST1024, each regular code
file32MiB, proc maps8MiB, mountinfo1MiB, fdinfo32KiB, FDs4096 per member,
tasks8192, event drains64x65536 bytes; original material/frame bounds1MiB,
Origin list256 and technical20/120/600s constraints are not enlarged.
Missing kernel facilities/privilege, lost events, unsupported ABI, short or
unknown views, overflow and deadline expiry fail closed. Cleanup closes only
owned handles and records errors; it does not terminate subjects.

### Positive Authority graph, not generic potential hashes

Every member has exactly five typed edges: `identity,administration,
descriptors,same_uid,mount_idmap`. Exact keys: `kind,member,objects,
measurement_sha256,evidence_sha256,effect,source_profile_sha256,
target_profiles,reserved_targets,actions,channels`. Source/target hashes name
exact profiles. Objects are all baseline protected files, the single existing
create-only Runtime93555 root and the three exact `zzz-public-runtime-r5.conf`
destinations. The outer Scope still binds the unchanged complete Owner plan.
Effect is explicitly `POTENTIAL_SUBJECT_AUTHORITY_ACCEPTED_TCB`, not denied
privilege. Each evidence object has exact schema
`TU1NZ_CONTEXT_AUTHORITY_EVIDENCE_V1`, actual measurement, and independent
semantic explanation32..2048 chars, and must hash to the expected measurement.
Missing action/target/effect or unknown Authority cannot become `trusted=true`.

Administration binds all21 fixed systemd Polkit action/unit/verb tuples
(manage-units x six verbs x three Units, plus manage-unit-files,
reload-daemon, set-environment). Actual protected noninteractive
CheckAuthorization queries use the already-running unique owner with no
activation and no challenge flag; allow AND deny are compared exactly,
challenge/unknown DENY. The exact Host-NSS sudo listing hash is an independent
policy-semantics input, not return-code-as-denial or a container-sudo proof.
All effective policy includes, direct Root/capability implications and finite
allowed R5 effects must be explained by the real independent annex review.
No Root negative-authorization fiction replaces positive TCB acceptance.

Same-UID potential includes all four UID intersections, conservatively all
targets for privileged vectors/capsets, not only EUID. Mount/IDmap potential
similarly binds exact profile targets; it does not claim absent namespace
escape. Both explicitly include all seven reserved R5 targets: this one
authenticated Source/Scope/Host/Boot/TX operator, the three old stop targets,
and three own new Unit/RuntimeReceipt invocations. Static prospective target
templates and live witnesses are separate: no future PID is guessed. Original
strict checks establish each live PID/start/Invocation once; replacements are
never adopted. These primary R5 targets are not silently dropped from edges.

Each actual socket FD additionally needs one exact `channels` entry:
`fd,direction,providers,objects,source_profile_sha256,
target_profile_sha256,socket_sha256`. Direction is bound-listener/bound-peer;
`providers` has one or two exact `side,profile_sha256,authority,actions` rows;
side is explicitly source/peer (a listener requires source). Named providers
at EITHER end cannot be relabelled application input or omitted. U1's exact
user-systemd profile is `user_service_manager`, U2 `user_executor`, U7
`userbus_policy`; their composed manager/router channel names BOTH directed
effects, not Host-systemd authority. Other finite types are application_input,
tmux_command, agent_signing and system_broker; action lists are exactly
`CHANNEL_ACTIONS`. Host providers require original HOST roles. Docker/SSH
administrative channels without a finite action model remain HOLD.
Provider profile, kernel cookie, addresses, type, direction, peer and full
measurement must agree; named tmux/agent/userbus providers are checked.
UNIX connected peers require SO_PEERPIDFD+fdinfo PID+exit poll and fresh full
census/profile/start/UID/GID bracketing, not SO_PEERCRED PIDnumber join.
This authenticates connection-time lifetime, NOT present FD ownership,
SCM_RIGHTS absence, agent keys or delivery. Such unresolved forwarding or
administrative effects must remain HOLD in actual semantic acceptance.
INET/6 connected and NETLINK channels lack that peer proof here and DENY;
an exact application listener is explicitly untrusted input, not a remote
principal. Existing global broker/TCP and inherited nginx/runtime socket
allowlists are unchanged; no Docker/SSH/agent request is a test.

### T01–T10 evidence and separate public CI decision

`tests/test_public_context.py` adds only synthetic portable schema/domain,
full-census, pinning, Authority, byte/watch, EOF/deadline, ABI/cleanup, Writer
target-union and Source-membership tests. Existing regression modules stay
required. `tests/test_public_context_native.py` prepares twelve separately
guarded tests in the existing owned network-none systemd CI guest: separate
roots/aliases, overlay, real foreign/overlay exe+same-image exec, mount/unmount
return, name/alias mutation, real pidfd_getfd/peer-lifetime, a private
nonleader fs-root and Writer FD.
Private helper requires exactly12 with ZERO skips, original7 native FSUID,
all28 adapter cases, Control64/Capsule and cleanup remain mandatory.
Native limitations or false setup assumptions are feasibility HOLD, not a
reason to widen permissions or extend safety deadlines. Portable success
does not certify any native/Host gate, shared mapping/Task or actual annex.

No public push/PR/run/merge is authorized by this local implementation. The
next proposal must bind exact final commit/tree/full diff, synthetic-only
fixtures, unchanged workflow triggers and actual native requirements. A
separately approved regular PR and automatic postmerge run must both be
fully green before a new create-only Source release/receipt can cover these
bytes. Closed PR239/Cache/Runtime evidence remains valid only for its bytes.
Actual identification/read scope, complete authentic Context/TCB/Authority
annexes, independent review, human risk acceptance, real Scope SHA/full CLI
validation, original Host admission and supervised maintenance remain later
requirements. No I2/R1/Host read or execution is granted by this extension.

Kernel API references: [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html),
[proc root](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html),
[foreign mount polling](https://man7.org/linux/man-pages/man5/proc_pid_mounts.5.html),
[fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html),
[SO_PEERPIDFD implementation](https://linux.googlesource.com/linux/kernel/git/torvalds/linux/+/6c790212c588fddeb0d852f2790840753bb604b1/net/core/sock.c).
