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

The controller does not reinterpret insufficient real volume as success. When
the 24-hour horizon or ten-session cap arrives below the five-real-sample
floor, the state becomes `CANARY_INSUFFICIENT_REAL_VOLUME` and S11 is disabled.
Any red hard gate, red latency profile or new ambiguous provenance becomes
`CANARY_RED`. `S11_FULL` is possible only through the guarded
`CANARY_READY_FOR_PROMOTION` transition. At a terminal outcome the systemd
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
