# Commercial S11.2-R14.1 technical runtime latency recovery

R14.1 recovers the technical runtime evidence run after the first R14 probe
completed successfully but the controller lost the finished oneshot's
`InvocationID`. It closes only the technical runtime evidence gap left by R13.
It does not
start, stop, or restart S8, does not contact Telegram, and does not create an
S11 session, community member, acquisition event, or human acceptance claim.

The canonical `TECHNICAL_RUNTIME_LATENCY` profile accepts only
`INTERNAL_TEST` / `DIRECT` / `DIRECT_BOT_RESPONSE` evidence and evaluates
`handler_duration_ms` over the rolling 24-hour window. Five samples are
required. The strict p50, p95, and p99 limits are 1000, 2000, and 5000 ms.

Each manual invocation of the static R14 oneshot runs one real application
handler against an in-memory S8 store, measures that handler with the monotonic
clock, and writes exactly one append-only latency row through
`PostgresCommunityStore.record_latency`. The row is verified by its generated
sample identifier before the command reports success. The identifier and all
user-shaped synthetic fixture values stay internal and are never emitted.

The recovery requires exactly one canonical technical sample at preflight and
exactly one matching GREEN record in the existing probe-unit journal. It
preserves that sample unchanged and appends exactly four further samples. Each
new probe captures a systemd journal cursor before start and accepts exactly
one GREEN probe record after that cursor. It does not depend on post-exit
`InvocationID` retention.

The unit carries only the database credential. It has no Telegram credential,
no timer, and no `[Install]` target. Operations must invoke it serially and
inspect provenance and public/runtime health after every sample. A RED latency
result is terminal for the run; samples are never deleted, redated, duplicated,
or reclassified.

`P0_RECOVERY=CLOSED` and `NEXT_S11_CANARY_RUNTIME_READY=true` are evidence
conclusions only after technical latency, S8, S9, S10, publication rotation,
and public WMS are all GREEN with no new UNKNOWN provenance. S11 remains
disabled and no canary controller or timer is installed.
