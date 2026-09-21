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
