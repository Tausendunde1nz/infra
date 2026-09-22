# Commercial S11.2 Canary Bootstrap

S11.2 replaces the impossible all-users-before-release dependency with one
bounded, fail-closed release state machine. It changes no Adult, identity,
payment, publishing, beta or production boundary.

## State contract

The only states are `S11_DISABLED`, `S11_CANARY` and `S11_FULL`. The Canary
admits at most the first ten sessions. Its release binding, evidence start,
live start, 24-hour horizon and cap become immutable when `START_CANARY`
commits. Every transition shares the database evidence barrier with every
Canary latency writer.

Historical ambiguous samples remain intact and are excluded only because they
predate the immutable epoch. Any ambiguous sample written inside the new epoch
fails the Canary closed. Evidence is additionally bound to the frozen runtime
release ID.

## Promotion and terminal outcomes

Promotion requires five technical and five real direct-response samples. Both
profiles require p50 below 1000ms, p95 below 2000ms and p99 below 5000ms.
Operational health, timer liveness, the single Poller lease, publication
rotation, public health, product boundaries and the unchanged acquisition
baseline are rechecked before and after the serialized promotion.

The historically retired S8 recurring health timer is a protected runtime
invariant: its reviewed unit remains loaded but the timer stays disabled and
inactive after S9/S10 assumed recurring health responsibility. S11.2 requires
the active S9/S10 timers to have future runs and executes the retained S8
health service only as an explicit one-shot deployment gate. It never
reactivates duplicate S8 recurring monitoring.

The final evidence read occurs only after the controller has acquired the
exclusive database barrier used by every Canary evidence writer. While that
barrier remains held, a fixed read-only controller subcommand repeats every
hard gate. The gate then applies `CANARY_READY_FOR_PROMOTION` and
`FULL_RELEASE` in that same database transaction. A failed immediate or
in-barrier hard-gate recheck rolls the transaction back and moves the active
Canary directly to `CANARY_RED`; it can never leave a committed, active READY
intermediate state.

The controller does not reinterpret insufficient real volume as success. When
the 24-hour horizon or ten-session cap arrives below the five-real-sample
floor, the state becomes `CANARY_INSUFFICIENT_REAL_VOLUME` and S11 is disabled.
Any red hard gate, red latency profile or new ambiguous provenance becomes
`CANARY_RED`. `S11_FULL` is possible only through the guarded, atomic
`CANARY_READY_FOR_PROMOTION` transition pair. At a terminal outcome the systemd
controller retains only its periodic read-only health observation; no further
state transition is available.

The observer is ordered after the Telegram service but does not require that
service to start successfully. This lets an inactive or failed monitored
service drive the active Canary to `CANARY_RED` instead of preventing the
fail-closed observer itself from running. Repository or freeze drift follows
the same terminal path.

## Backup, activation and recovery

The deployment controller verifies the installed source state and the signed
freeze binding before mutation. It then creates and verifies Git bundles, a
custom PostgreSQL dump and restore list, installed-unit/config copies,
aggregate evidence, permissions and checksums. Only after that backup does it
switch to the frozen releases and apply additive migration 0033 with S11 off.

Health and all eight synthetic journeys run before `START_CANARY`. Five timed
internal journeys establish the separate technical profile; they cannot count
as real-user evidence. The controller then starts the bounded Canary and its
single mutating systemd timer. A deployment failure restores the source Git,
code, units and configuration after first disabling an active Canary. The
additive schema and evidence are intentionally retained. A rollback from an
already promoted Full release is rejected and requires a separate reviewed
recovery contract.

Human Telegram acceptance is deferred and is never claimed by this contract.
Real acquisition remains active with its existing baseline; it is not reset.

## P0 rollback compatibility recovery

The first runtime attempt exposed a source/configuration binding gap. The
preflight proved repository commits but did not prove that the installed WMS
copy could be parsed by the exact Application commit selected for rollback.
The target runtime started successfully; rollback then restored the source
commit and its independently backed-up copy, and that pair failed closed with
`S10_PUBLIC_COPY_KEYS_INVALID_EN`. Git returned cleanly while public WMS became
unavailable.

Freeze r3 added a read-only WMS construction probe to both deployment preflight
and the rollback path before any service restart. The backup now also binds the
base WMS, bot, community, aggregate and traffic-quality inputs needed to prove
the runtime tuple.

The separate P0 recovery entrypoint accepts only the observed failed state. It
requires the exact clean pre-deployment repositories, exact failed-copy hash,
verified original backup, absent S11 controller, disabled S11 state, unchanged
acquisition baseline and closed product boundaries. It creates another full
verified backup before installing the canonical copy from the exact rollback
Application commit. It changes no repository, database state, latency evidence
or S11 flag. Public WMS becomes the recovery commit point; later health failure
cannot deliberately reintroduce the known 502 state.

This recovery restores S10.2F availability only. It does not retry the Canary,
promote S11 or authorize a second S11.2 deployment.

The first P0 recovery execution completed its second backup and checksum
verification but stopped before mutation because the setgid backup parent made
the root-owned directory inherit mode 2700. Although group and other had no
access, the exact contract requires root:root 0700. Freeze r4 explicitly
removes inherited setgid, verifies exact 0700 before the first backup write and
rechecks it after permission hardening. The completed r3 backup remains
immutable, and r4 retains the same public-WMS-only boundary.

R4 then proved the normalized backup GREEN but exposed a separate readiness
race: systemd marked the simple WMS process active before its HTTP listener was
ready, and the public gate ran 194 ms later. Freeze r5 replaces that
process-active-only wait with bounded polling of the existing local health
endpoint. It requires parsed `ok=true` with all forbidden capabilities false
before the unchanged public gate runs. The 30-second limit remains fail-closed;
there is no fixed sleep, public-gate bypass or broader recovery scope.

## S11.2-R2 recovery-compatible bootstrap

P0 Recovery R5 restored public WMS and later closed with both S9 and S10
health GREEN after the historical ambiguous samples naturally left the rolling
window. R2 keeps that recovery closed and starts from a fresh immutable Canary
epoch; it neither retries recovery nor rewrites historical evidence.

Freeze r6 carries the R5 startup contract into the Canary deployment and its
rollback path. After each WMS restart, the controller polls the existing local
health endpoint for at most 30 seconds and requires parsed `ok=true` with all
forbidden capabilities false. Only then may it evaluate the unchanged public
HTTP gate. A process-active state alone is not readiness and there is no fixed
sleep.

Before switching repositories, the controller also proves that the source and
target WMS parser surface is unchanged and constructs the exact target WMS
copy with the current proven parser and live non-secret runtime inputs. This
keeps forward deployment, feature-off fallback and rollback bound to the same
compatible Application/copy contract. The S11-disabled public-health result is
captured as explicit feature-off fallback evidence before `START_CANARY`.

## R7 gate-field correction and S8/Poller recovery

The R6 deployment reached `START_CANARY`, then failed while extracting the
already valid gate decision. The compact Python helper printed the requested
JSON field but used a conditional `raise` expression whose successful branch
evaluated to `None`; Python then raised `TypeError` and returned non-zero. The
existing deployment trap correctly moved the Canary to `CANARY_RED` and
restored the exact Source repositories, units and public WMS configuration.
The repeated rollback restart left only the S8 Telegram service in the
observed `start-limit-hit` state; the Poller lease then expired and S9 health
failed closed. Public WMS and all product boundaries remained safe.

Freeze r7 replaces that expression with an explicit conditional `sys.exit(2)`
for a missing field and a normal successful `print` for a present value. An
executable regression test proves exit 0 plus the exact value for a valid gate
payload and exit 2 for an absent field.

The separate r7 S8/Poller recovery entrypoint accepts only this exact incident:
clean Source Application and Control commits, the verified R6 deployment
backup, `S11_DISABLED|CANARY_RED`, absent S11 controller artifacts, unchanged
acquisition baseline, closed product boundaries, S8 `start-limit-hit`, expired
Poller state, the matching S9 health failure, green unrelated services and
green public WMS. It creates and verifies a fresh root-only Git/database/runtime
backup before resetting and starting S8 once. It then requires a live lease,
recent successful Polling, Event Path, all S8/S9/S10 one-shot health gates,
future recurring timer runs, Publication Rotation, public endpoints and clean
Source repositories. Any post-mutation failure stops S8 fail-closed.

This recovery does not install the r7 controller, switch either repository,
mutate S11, write/reclassify latency evidence, start a Canary, alter
acquisition, or authorize a second deployment attempt. S11 remains OFF after
recovery.

## R8 Community child-code contract

The single R7 recovery start proved S8, its Poller and its lease ready, then
stopped fail-closed at S9 health. The Application child had emitted a
privacy-safe Community reason, but `tu1nz_adult_public_s10_1_health.py`
normalized every unrecognised Community failure to
`S10_2D_COMMUNITY_STATE_RED`/44. The health-gate and recovery layers therefore
received the outer class but not the actionable child.

Freeze r8 keeps all legacy outer codes and exit statuses stable while adding a
strict JSON child contract. The envelope contains only `outer_code`, an exact
allowlisted `child_code`, an allowlisted `component`, a bounded decision class
and a bounded next action. It never contains usernames, Telegram identifiers,
messages, media, credentials, DSNs or free-form provider output. A missing
child becomes `COMMUNITY_CHILD_CODE_MISSING_RED`; an unallowlisted value
becomes `COMMUNITY_CHILD_CODE_UNKNOWN_RED`. Both are hard RED.

The five decision classes are retryable runtime readiness, state integrity,
release binding, provider/external and unknown/hard RED. Classification is
diagnostic only: every R8 RED decision is `STOP_NO_RETRY`. The exact systemd
invocation is used to locate the bounded JSON envelope, and raw journal text is
never copied into the recovery report. The fixture and simulator matrix A-I
covers GREEN, a valid child, missing and unknown children, release binding,
lease/Poller readiness, Event Path, retained state and provider state.

No R8 source-validation action starts S8, installs a controller, changes a
database, mutates Telegram, starts the Canary or alters acquisition. The next
runtime recovery remains a separate backup-first authorization.

## R10 latency evidence and runtime-health integrity

The R9 recovery attempt proved the Poller, lease and successful-poll path, then
stopped at an S9 child reported as `S11_COMMUNITY_LATENCY_SLO_RED`. Its five
retained rows were not written by R9: they came from the earlier failed S11.2
Canary bootstrap. Each row is release- and run-bound `INTERNAL_TEST`, uses
`S11_CANARY_RESPONSE` plus `INTERNAL_ACCEPTANCE`, and is therefore technical
Canary evidence rather than real-user evidence.

The rollback intentionally retained the additive schema and evidence while it
restored an older Application reader. That reader did not recognise the newer
sample type and mapped it to `UNKNOWN`; the generic S9 wrapper then coupled the
product-level real-user profile to S8 runtime health. R10 classifies the proven
root cause as `MULTIPLE_CAUSES`: `WRITER_READER_SCHEMA_MISMATCH` together with
`PRE_CANARY_HEALTH_WRONGLY_REQUIRES_S11_SLO`.

R10 keeps the evidence immutable and exposes four independent profiles in the
Application health payload: technical runtime, Canary technical, Canary real
user, and full real user. The S8/S9 runtime contract blocks only a RED
`TECHNICAL_RUNTIME_LATENCY`; GREEN or `INSUFFICIENT_EVIDENCE` product profiles
remain observable without becoming a false runtime RED. Missing or malformed
profile contracts fail closed as `COMMUNITY_LATENCY_PROFILE_CONTRACT_RED`, and
a genuinely RED technical runtime fails as `COMMUNITY_RUNTIME_LATENCY_RED`.
Unknown provenance remains fail-closed.

The strict product contract is unchanged: at least five valid REAL samples,
p50 below 1000 ms, p95 below 2000 ms and p99 below 5000 ms. Technical samples
never satisfy that floor. The A-J simulator covers S11 disabled, collecting,
eligible, product RED, technical-only, unknown, state corruption, release
mismatch and technical RED scenarios without a retry.

The next recovery contract is still backup-first and permits exactly one S8
start. Before that start it binds the canonical R10 Application reader and
Control health contracts; any failure stops S8 and restores the backed-up
source commits and installed health scripts. It never starts a Canary, changes
an S11 flag, reclassifies evidence, or authorises a second attempt. R10 itself
is source-only and performs no server runtime mutation.

## R10.1 recovery preflight state

The final read-only R10 preflight found that R9's fail-closed stop had already
normalised S8 from `failed/start-limit-hit` to `inactive/dead` with a successful
stop result. The recovery contract now accepts exactly those two safe service
signatures. Both still require `MainPID=0`, `NRestarts=0`, the release-bound
`BOT_POLLER_NOT_RUNNING` database signature, S9 exit 44, healthy unrelated
services and GREEN publication rotation. Every other service tuple fails closed
as `S11_2_R10_1_S8_RECOVERY_STATE_DRIFT`.
