# Commercial S10.2D-R8.3 technical readiness

R8.3 separates technical readiness from human acceptance without weakening the
existing full-human acceptance contract. It changes Control only. The frozen
Application remains at commit `312db84d5db6d76c9d6bb448459c9404b1dfcbe4`,
tree `ac4f8bca1fd796626742a8ef6c6afcdda482fc68`.

## Reproduced predecessor state

The unchanged R8.2 controller was executed against the live, acquisition-closed
target before source changes. It returned
`LATENCY_SAMPLE_FLOOR_MISSING`: the release has zero human bot-response samples.
No readiness or acquisition state changed.

The source backup is
`/opt/tu1nz_repos/backups/commercial-s10-2d-r8-3-source-20260917T184809Z`.
It contains Application and Control Git bundles. Both SHA-256 checks and both
`git bundle verify` checks are green.

## Acceptance profiles

`FULL_HUMAN_E2E` remains strict. Direct-bot, community, and moderation human
acceptance must all be `GREEN`; both human latency states must be `MEASURED`;
at least five bot-response samples must satisfy the existing p50, p95, and p99
limits.

`TECHNICAL_RUNTIME_WITH_HUMAN_DEFERRED` is the manifest-selected R8.3 profile.
It requires every technical hard gate to be green and requires the three human
states to remain explicitly `DEFERRED`. Bot-response and join/welcome latency
remain `NOT_MEASURED`. No human samples are fabricated, reclassified, or added.

An unknown or implicit profile fails closed. A human `RED` result cannot become
`DEFERRED`. A technical red gate, stale release evidence, missing observation,
unknown retained state, active acquisition, non-null acquisition baseline, or
open product boundary fails closed.

## Technical evidence

Before the readiness transition, the controller revalidates the exact Control
and Application bindings, public and local health, the target listener, the
single release-bound S8 poller and live lease, successful polling/event path,
the last health and publication-rotation results, migrations, aggregate
readability, timers, moderation queues, and all closed product boundaries.

The R8.2 observation remains immutable evidence: 29 green snapshots over 1,818
seconds. R8.3 interprets that evidence under the versioned profile; it does not
rewrite it or force an unrelated second cutover.

## State transition and stop boundary

`mark-ready` now requires an explicit fourth argument naming the manifest-bound
acceptance profile. A green evaluation changes only
`pre_acquisition_readiness` from `PENDING` to `GREEN`.

It does not set `wms_real_acquisition_ready`, does not set
`real_acquisition_baseline_start`, and does not seed or activate acquisition.
After a green R8.3 mark-ready result, S10.2E remains a separate operator gate.

Adult media, community adult media, adult submission, AVS, payment, publishing,
controlled beta, and production remain closed.

Source validation is green: 473/473 Control tests, static validation, the
release simulator, and the privacy-safe secret/PII scan passed. The temporary
same-tree local test-runtime binding was removed after validation; Application
source remained unchanged and clean.
