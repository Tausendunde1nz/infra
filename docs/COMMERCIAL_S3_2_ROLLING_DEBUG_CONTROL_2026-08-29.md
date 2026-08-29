# Commercial S3.2 — rolling server-staging debug Control SSOT

Decision: **GO for repeated diagnostic start/stop cycles before READY inside the
authorized S3.2 window.** The first product acceptance remains limited to one
harmless submission after `READY + HEALTH GREEN`.

The application target is commit
`3761ab738bd48be411ac8c6db394cf43748e6dab`, tree
`b1a977f35b0c8fec81dccc4c8930943c7d8adf21`, on the single rolling branch
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
dependency graph in a second transient systemd sandbox. It has no Telegram
credential. Its IP policy denies every destination except localhost, which is
required by the bound PostgreSQL loopback DSN; Telegram and all providers stay
unreachable. It must return `S3_PRESTART_READY` and explicitly prove that no
service was started before a diagnostic start is allowed.

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

## First READY runtime recovery

The first READY process later stopped at `2026-08-29T16:08:36Z` because the S3
adapter classified an ordinary Telegram long-poll timeout/network interruption
as a non-retryable generic failure. At that instant the same acceptance journey
had completed only terms and synthetic creator verification: zero submissions,
zero payments and zero publications existed. Restart remained disabled and
`NRestarts=0`.

The bounded correction maps only Telegram timeout, network and rate-limit safe
codes to the existing retryable `TELEGRAM_API_UNAVAILABLE` result and logs the
safe retry attempt. Unknown errors remain fail-closed. The already queued exact
JPEG document may therefore be consumed after a fresh bound release start,
continuing the same single journey; no second submission or second account is
authorized.

The next bound run proved the polling recovery but exposed a second pre-product
gate: S3 required a fresh upload's Telegram reference to equal an older
reconciled value before downloading it. S3 now follows the proven S2.2 order:
bounded reference and metadata validation first, followed by an exact-size
download, JPEG-boundary check and SHA-256 match. A new Telegram reference alone
cannot authorize different content, and the internal media identity remains
manifest-bound. At correction time the journey still contained zero
submissions, zero payments and zero publications.

The first exact-document retry then reached the S3 metadata envelope and was
rejected before download because Telegram supplied the backward-compatible
`thumb` spelling in addition to the current `thumbnail` field. The bound repair
accepts only those two ignored thumbnail spellings; arbitrary document fields
remain blocked. Exact size, MIME, JPEG boundary and SHA-256 verification still
gate the normalized product input. The rejection again created zero
submissions, zero payments and zero publications.

The single accepted document then created exactly one submission and reached
human moderation. The PostgreSQL projection rejected the approval because the
creator-facing S1 mock-credit and legacy X binding did not match the M4.15
durable composition contract. The JSON state therefore remained
`READY_FOR_REVIEW`; no charge or publication was recorded. The bound repair
emits the canonical X binding for new journeys, strictly normalizes the exact
legacy in-flight binding, maps the one-credit mock payment to the catalog-bound
synthetic core evidence, and preserves `AWAITING_PAYMENT` as a presentation
state over the core target-authorization gate. Arbitrary bindings, X in a paid
bundle, real payment and external publishers remain rejected.

The first restart probe against that in-flight aggregate then exposed the
original bootstrap-only `business_rows_zero` condition in the shared runtime
dependency graph. Runtime and prestart now use a separate bounded reconstruction
check: exactly one submission owned by the fixed synthetic creator is allowed,
and every business table exposing a submission or creator key must remain tied
to that aggregate. Bootstrap and the default verifier still require an empty
business state. Multiple submissions, a different creator, unsafe content,
country, target or display shapes, and external destinations remain RED.

The bounded reconstruction then reached the original partial core projection
from the first moderation attempt. PostgreSQL contained only the successful
prefix through publication-entitlement creation; no payment evidence, dispatch
or publication existed. Retrying with a newly generated envelope correctly
failed the exact receipt hash check. The release now resolves only a successful
receipt's original whole-second timestamp by reproducing its stored SHA-256
from an eight-second bounded search. It then replays the otherwise immutable
command envelope. Rejected receipts, payload changes, actor/revision/key drift,
and any non-exact hash stay RED. The recovery is read-only and never rewrites or
deletes durable rows.
