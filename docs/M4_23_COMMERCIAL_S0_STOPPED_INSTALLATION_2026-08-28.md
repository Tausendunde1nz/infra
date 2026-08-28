# M4.23 — Commercial S0 stopped installation

Date: 2026-08-28

Application: `52494d6121660ead53774deb8616701f14bb7a8f`

Recovery profile: RPO 86400 seconds, RTO 14400 seconds, encrypted retention
7 days.

Decision: **GO for the reviewed stopped preparation after merge; NO-GO for
first start, providers, tokens, real media, real payment or publication**

## Goal and product boundary

M4.23 installs only the persistent, network-free commercial S0 candidate that
directly supports the TU1NZ path toward Telegram intake, adult/consent checks,
human moderation, paid Telegram/Reddit distribution and separately authorized
uncompensated X automation. All source data and publishers remain synthetic.
The candidate has no Telegram intake and no external provider access.

The fresh absent-state encrypted archive created immediately before this
transaction is
`tu1nz_system_backup_20260828T14-39-46Z.tar.gz`, 45,417,608 bytes, SHA-256
`011856113239a94c83104e9156336dfc0cfbae8208f6cfdc0cee8f68d4316887`.
The local and streamed encrypted-remote hashes match, and the non-disruptive
restore smoke completed at 2026-08-28T15:26:01Z. Google Drive quota throttling
made the upload require a whole-attempt retry; the final service result was
successful and is recorded in the M4.23 diagnosis.

## Versioned installation transaction

`scripts/tu1nz_adult_commercial_s0_install.sh` has four normal installation
modes:

1. `preflight` proves the final repositories, authorization, backup hash,
   absent commercial targets, active PostgreSQL/S1, idle backup process,
   capacity and exact PostgreSQL configuration baselines.
2. `prepare` installs the reviewed commercial-aware backup script, creates the
   locked OS identity and minimal parent traversal ACL, installs the exact peer
   mapping, creates isolated database roles/database, stages clean immutable
   releases, builds the hash-locked venv, applies migrations 0001–0014 and the
   synthetic bootstrap, and creates exact private config/empty state.
   Application transport is the same root-private, SHA-256-bound Git bundle
   used by partial recovery; no server-side application credential is needed.
3. `verify-prepared` validates that prepared state read-only and requires the
   release manifest and installed unit to remain absent.
4. `install-unit` is intentionally blocked until a qualifying commercial
   archive and post-backup approved manifest exist. It can only install and
   verify the unit stopped; it contains no candidate start or enable action.

The fail-closed partial-state repair adds dedicated modes without broadening the
product scope: `partial-preflight` recognizes only the exact stopped boundary
recorded in the M4.23 diagnosis, `recover-partial` restores only the daily
encrypted-backup timer, and `resume-prepare` consumes one root-private,
SHA-256-bound Git bundle for the final application commit. The bundle must
verify as Git data and still produce the exact final commit/tree and clean
object graph. This avoids creating or broadening a GitHub credential. Control
uses the existing `github.com-infra` server route.

The later `resume-after-venv-build` mode recognizes only the exact second
recorded boundary: final application and prior Control releases are present,
the exact virtual environment imports successfully, the database is still
empty, and only `build/` plus the package `egg-info` directory exist as ignored
application output. It preserves those two directories below the root-private
M4.23 evidence root, removes inherited setgid bits from immutable targets,
stages the newly reviewed Control commit and completes the still-stopped
database/configuration preparation. It contains no broad clean or recursive
delete operation. Future fresh preparation creates a root-private source
archive with `git archive` and installs the application from that archive, so
the immutable checkout remains clean throughout the virtual-environment build.

The next fail-closed boundary occurred after the new Control release had been
staged but before PostgreSQL parsed migration 0001: the `postgres` operating-
system identity correctly cannot traverse the private runtime-group release.
`resume-after-control-stage` accepts only that exact empty-database state.
Migration and bootstrap files remain private; the root transaction opens each
reviewed file and provides it over standard input to `psql` running as
`postgres` with the non-login migrator role. No traversal permission is added
to PostgreSQL, and future fresh/recovery paths use the same input method.

After migrations and synthetic bootstrap completed, the first acceptance run
also stopped safely because `psql` inherited the hyphenated operating-system
username instead of selecting the underscore PostgreSQL runtime role. A
read-only probe proved the schema succeeds with the explicit reviewed role.
`finalize-schema-acceptance` binds to the exact 39-table/21-function schema,
synthetic seed counts, private config, empty state and immutable links. It
stages the newly reviewed Control commit, atomically advances only the Control
link and completes stopped verification. Every acceptance path now specifies
`tu1nz_adult_commercial_s0_runtime`; no peer rule or filesystem permission is
widened.

If a formally valid but non-clonable shallow bundle is encountered,
`reject-incomplete-bundle` recognizes only its recorded SHA-256 and moves it
into the root-private M4.23 evidence directory. It does not delete that
artifact or alter the partial database/identity/ACL boundary.

The PostgreSQL HBA/ident changes and database storage are the narrow,
operator-approved exceptions needed to implement the M4.21 peer-auth design.
Before writing them, the transaction verifies the exact M4.20 hashes and saves
root-private copies under the M4.23 backup evidence directory. It validates the
versioned fragments, reloads PostgreSQL without stopping it and requires both
native parser views to be error-free. Existing S1 remains active throughout.
The daily encrypted-backup timer must be active before the window, is paused
only while commercial roots transition from absent to complete, and is resumed
by an exit trap on success or failure. The backup service itself must be idle.

## Failure and rollback boundary

Every phase aborts on the first mismatch. It does not automatically remove a
partially prepared database, identity, ACL, release or configuration; evidence
must be preserved and a `.diagnose` review must precede rollback. The approved
rollback basis is the exact absent-state archive above plus the root-private
copies of the prior backup script and PostgreSQL files. Rollback may remove
only M4.23 resources, use the versioned ACL `rollback` mode, restore the exact
PostgreSQL copies, reload/validate PostgreSQL and prove S1 stayed unchanged.

## Deliberate post-backup gate

After `prepare` passes, the installed backup process must create the first
archive containing the immutable application/Control/venv roots, config,
state and custom-format PostgreSQL dump. The release-manifest contract requires
`approved_utc` to be at or after that backup's completion. The 14:35:32Z root
window approval predates that future archive and is therefore not reused as a
release approval. No timestamp is invented.

Consequently the uninterrupted authorized work may proceed through stopped
preparation and the exact commercial backup. Manifest generation, isolated
restore rehearsal and stopped unit installation then require one concise
operator confirmation of that named archive. First start remains a later,
separate decision even after the unit is installed.

The first post-preparation backup attempt stopped before archive creation:
local `postgres` could not traverse the protected backup parent to open its
custom dump output. The correction keeps that identity and all parent
permissions unchanged. Root opens a `0600` file inside a root-private temporary
directory and receives `pg_dump --format=custom --file=-` output. Cleanup,
archive membership, encrypted upload, seven-day retention and the later restore
contract are unchanged.

Because that backup correction creates a newer canonical Control commit after
the stopped candidate was already prepared, `advance-prepared-control` binds to
the exact verified `7ce7583a394d28e916bd7d3e8e37e2292e0bf5f8` release and prior backup-script
digest. It preserves that installed script as root-private evidence, installs
only the newly versioned backup script, stages the current reviewed Control
release and atomically advances the Control link. It then reruns the complete
stopped verification with manifest and unit still absent. This avoids a split
between canonical SSOT, active immutable Control and the installed backup code.

The first retry exposed one command-line detail before archive creation:
`pg_dump --file=-` treats the dash as a literal filename on this host. The
native standard-output mode omits `--file` entirely. The corrected script keeps
the root-opened `0600` redirection unchanged. The same prepared-Control advance
is re-bound to the exact `7176e7b8f22ce7436c29cde07de8e58965896f04` state and
installed script digest, preserves that failed-retry script separately and
advances to the newly reviewed Control commit before the next backup attempt.
