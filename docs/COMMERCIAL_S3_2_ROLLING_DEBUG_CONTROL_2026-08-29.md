# Commercial S3.2 — rolling server-staging debug Control SSOT

Decision: **GO for repeated diagnostic start/stop cycles before READY inside the
authorized S3.2 window.** The first product acceptance remains limited to one
harmless submission after `READY + HEALTH GREEN`.

The application target is commit
`9f82e3c682a0f59a4675cca568058a3779a4a4ed`, tree
`759cc536298901ae1ee57fa9de3e7ec177d357c3`, on the single rolling branch
`fix/commercial-s3-staging-recovery`. Every installed server delta must bind the
exact Control commit and tree as external execution inputs.

## Recovery and rollback

The verified baseline recovery point is
`/opt/tu1nz_repos/backups/commercial-s3-1-fix/20260829T13-56-54Z`. Its two hash
indices must validate before any probe or diagnostic start. Code-only deltas use
the previous/new Git SHA and tree as rollback coordinates. A new full recovery
point becomes mandatory if database schema, permanent data, system paths, or
rollback completeness changes.

## Startup evidence

The runtime records strict phases `01_CONTRACT_LOAD` through `18_READY`. Each
phase emits ENTER and OK or FAILED. Failure evidence contains only the phase,
safe exception type/module/reason, optional errno/SQLSTATE, and UTC timestamp.
It never includes tokens, DSNs, response bodies, identities, or media.

The versioned probe controller executes the same runtime entrypoint with
`--startup-probe` in a transient systemd unit reproducing the installed unit's
user, LoadCredential boundary, filesystem protection, network-family boundary,
and state paths. It exits after phase 17 and never begins Telegram polling,
submission handling, workers, publishing, or READY. It installs no persistent
unit and performs no daemon reload.

The same controller opens a bounded 30-minute active contract from the
versioned disabled template, after preserving the exact prior contract in the
private attempt evidence. `close-window` is permitted only while the service is
inactive and restores the hash-bound disabled contract. Neither action changes
the unit or enables a service.

## Hard product boundary

- one internal allowlisted test account only
- AVS and payment remain MOCK
- Telegram, X, and Reddit publishers remain SYNTHETIC
- harmless registered JPEG only; no adult media
- no Stars, external publishing, public Telegram post, beta, or production
- `Restart=no`, no restart, no enable

Diagnostic service cycles must always be `inactive → start → failure/stop →
inactive`. After the first stable READY, code changes stop until exactly one
product acceptance, takedown, ten-minute idle observation, controlled stop, and
post-state verification are complete. Only then may the rolling branches be
reviewed and merged.
