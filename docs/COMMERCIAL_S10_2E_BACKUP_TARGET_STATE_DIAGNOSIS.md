# S10.2E target-state backup diagnosis

## Failure

The first S10.2E backup attempts stopped before acquisition activation with
`CUTOVER_PREFLIGHT_AGGREGATE_NOT_SOURCE_RED`. No product or acquisition state
was changed.

## Root cause

The S10.2E wrapper extended the S10.2D pre-cutover backup entrypoint. That
older entrypoint deliberately accepts only the historical source aggregate
events `LANDING_VIEW` and `TELEGRAM_CTA`. The canonical R8.3 runtime is already
post-cutover and correctly contains the known target event `COMMUNITY_CTA`, so
the old pre-cutover assertion cannot be reused for an acquisition baseline.

## Corrected contract

S10.2E now extends the verified S10.1 runtime backup directly and creates an
exact, mode-0600 aggregate snapshot under the S10.2E evidence contract. The
snapshot accepts only the three versioned SFW events `LANDING_VIEW`,
`TELEGRAM_CTA`, and `COMMUNITY_CTA`; unknown events, malformed counters,
symlinks, multiple hard links, unsafe modes, overwrites, and count regressions
remain fail-closed.

## Risk and rollback

This correction changes backup validation only. It does not change the
Application, runtime services, database state, acquisition flag, baseline, or
public endpoints. A failed backup remains non-activating. Recovery uses the
verified base runtime snapshot plus the exact aggregate bytes and SHA-256
captured by S10.2E. The two rejected backup directories remain preserved as
diagnostic evidence and must not be used for restore or activation.
