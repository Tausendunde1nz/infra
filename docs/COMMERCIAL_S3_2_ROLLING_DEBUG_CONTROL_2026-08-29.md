# Commercial S3.2 — rolling server-staging debug Control SSOT

Decision: **GO for repeated diagnostic start/stop cycles before READY inside the
authorized S3.2 window.** The first product acceptance remains limited to one
harmless submission after `READY + HEALTH GREEN`.

The application target is commit
`d7e78201f06ec493e7ecabcb4b624e5f92c9abf9`, tree
`81f28d53b2595b88ad1a48cba68378e680b8abbd`, on the single rolling branch
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

The private evidence directory must be owned by `root:root` and may have mode
`0700` or inherited-setgid mode `2700`; both modes deny all group and other
access. No broader mode is accepted.

After a green startup probe, `fresh-prestart` runs the shared prestart
dependency graph in a second transient systemd sandbox. Its address-family
boundary is AF_UNIX only, so it cannot contact Telegram or any provider. It
must return `S3_PRESTART_READY` and explicitly prove that no service was
started before a diagnostic start is allowed.

The window installs a separately versioned runtime-release authorization with
`single_bootstrap_authorized=false` and
`decision=GO_FOR_RUNTIME_RELEASE_VERIFY_ONLY`. It binds the instrumented
Application SHA/tree for migration/reference/database verification but is
rejected by the bootstrap mutator before any database connection. Closing the
window restores the prior consumed S3.1 bootstrap authorization exactly.

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
