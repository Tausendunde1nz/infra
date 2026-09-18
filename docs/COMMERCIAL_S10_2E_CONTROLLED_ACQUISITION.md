# Commercial S10.2E controlled SFW real acquisition

S10.2E is a business-state transition on the already frozen R8.3 runtime. It
does not deploy a new Application build, change Telegram identities, alter the
Community cutover or open an Adult product boundary.

## Canonical prerequisite

- Application commit `312db84d5db6d76c9d6bb448459c9404b1dfcbe4`, tree
  `ac4f8bca1fd796626742a8ef6c6afcdda482fc68`.
- R8.3 freeze `s10-2d-r8-3-technical-readiness-freeze-r1`, resolving to
  `d41b7695061136f7449d27e38e6adf1be0df219c`.
- `pre_acquisition_readiness=GREEN`, `wms_real_acquisition_ready=false` and
  `real_acquisition_baseline_start=NULL` before activation.

The legacy database field `wms_real_acquisition_ready` is the persisted form
of `REAL_ACQUISITION_ACTIVE`. Technical readiness remains represented by
`pre_acquisition_readiness=GREEN`.

## Backup-first contract

`tu1nz_adult_public_s10_2e_backup.sh create` extends the existing verified
S10.2D backup with an aggregated acquisition baseline, the exact aggregate
bytes and digest, the public-health boundary result and restore guidance. The
base backup already contains Git bundles, provenance, a PostgreSQL custom
dump, schema and migration evidence, configuration, units and service state.

No Telegram identifiers, message bodies, tokens, media or identity data are
emitted in S10.2E evidence. Database backups retain their existing protected
root-only mode and are not copied to the repository.

## Activation

`tu1nz_adult_public_s10_2e_acquisition.sh preflight` binds the command to the
exact Control SHA/tree supplied by the operator, the canonical Application and
the immutable R8.3 freeze. It reuses the R8.3 runtime verification, requires a
verified S10.2E backup, confirms the inactive/null acquisition state, checks
owned/organic Growth and confirms the closed product boundaries.

`activate` performs one conditional database update. PostgreSQL
`CURRENT_TIMESTAMP` becomes both the authoritative baseline and activation
time, and the active flag changes to true in the same statement. A second
activation cannot move the timestamp because the conditional update requires
the baseline to be null.

Existing SFW Growth already supplies owned/organic distribution. S10.2E does
not enable paid campaigns, X, Reddit, mass direct messages, affiliate traffic
or Adult networks.

## Pause and failure semantics

`pause` changes only `wms_real_acquisition_ready` from true to false and keeps
the original `real_acquisition_baseline_start`. It is idempotent for an already
paused state and requires an uppercase safe-code reason. A product/acquisition
problem therefore pauses acquisition without rolling back a healthy runtime.
Critical runtime or release failure continues to use the existing versioned
S10.2D runtime rollback contract.

The hard pause conditions include public or WMS health failure, poller or
lease loss, duplicate polling, database-integrity failure, unknown retained
state, critical moderation failure, or any unexpected opening of media, AVS,
payment or publishing.

## Reporting

`report` compares the protected pre-activation database and aggregate
snapshots with current aggregated state. It reports landing, Telegram and
Community CTA deltas, bot and waitlist events, referral events, Community and
moderation counters and the active/baseline state. A zero-user window is valid
when health and boundaries remain green.

Human acceptance and latency remain explicitly deferred/not measured. Real
usage does not silently upgrade those gates. Adult media, AVS, payment,
publishing, Controlled Beta and Production remain closed.
