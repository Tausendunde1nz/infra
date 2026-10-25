# R5P: finite prospective Hostpolicy/role addendum

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

UID/GID are exact four-integer vectors; groups sorted unique integers;
all five capability sets exact unsigned64-bit integers; nnp integer0/1;
argv/environment/LSM represented by exact SHA256, not published raw values;
pid/mnt/user/net namespace identities are exact. Executable canonical paths
are finite under /usr/bin,/usr/sbin,/usr/lib,/bin,/sbin with separately
authenticated byte origins. No name glob, extra role, omitted actor or wildcard.

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

`metadata` is exactly B-H + four Unitfiles + operator_dependency alias rows;
it repeats the corresponding exact baseline metadata, not a second looser set.
Operator executables/DSOs may have execute bits but never group/other write;
uid/gid0:0,attrs empty,flags0/0x80000. Their **bytes** retain Publisher/Git origin.
Other existing byte-origin/metadata rows are not converted to prospective rows.

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
bytes use GIT. Existing other static /etc files may use PUBLISHER/GIT/PRIOR_RECORD;
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
then occur before the client custody claim. Selected evidence is carried once
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
