# M4.24 — Network-free first-start acceptance

Date: 2026-08-28

Decision: **GO for versioned design and automated tests; NO-GO for the actual
first start**

## Goal and product alignment

M4.24 provides the smallest controlled runtime proof needed after the M4.23
stopped installation. It remains directly on the product path toward Telegram
creator intake, adult/consent verification, moderation, paid Telegram/Reddit
distribution and separately authorized uncompensated X automation. It does not
add any provider, token, real media, payment, Telegram intake or publication.

The acceptance window runs only the existing synthetic, network-free
commercial S0 candidate. A successful window must end with the unit stopped.
The unit has no enablement section and M4.24 never enables or restarts it.

## Exact stopped boundary

- application commit: `52494d6121660ead53774deb8616701f14bb7a8f`;
- application tree: `b2820945c52ffdf77c2f5fbdd227c03ee6b245ab`;
- installed Control release: `8c4e8992a60c215295cf9d0c400afcd9a931f883`;
- release manifest SHA-256:
  `2a3dc857205f9cff262edd686bc6db13d799c1e5de8aea954a8f50b9420cdc54`;
- unit SHA-256:
  `ecec13e294ded68dfeeaba1300eb2f5247aacf5e9085c9838eca3b50f6a56bf3`;
- archive: `tu1nz_system_backup_20260828T16-50-53Z.tar.gz`;
- archive SHA-256:
  `b96f9efb304b2898758539516d842d27574307de82cbfb49229692ab8c9bcbd7`;
- archive inventory SHA-256:
  `24144ec79a867c7f002da15c80fc7c9a5f429d28c52d16715a5602dded1c80c2`;
- isolated restore root:
  `/opt/tu1nz_repos/backups/m4-23-commercial-s0-restore/20260828T16-50-53Z`.

The observed unit is installed, `inactive`, `dead`, `static` and never started.
The native unit verification passes and the offline security rating is
`0.6 SAFE`. S1 and the encrypted-backup timer are active; the backup service is
idle. There is no commercial process, timer, cron reference, container mount,
open release file, runtime status or lock. The dedicated database has 39
tables, 21 TU1NZ functions, exact synthetic seed counts and zero rows across
all 33 non-seed business tables.

The final code review identified that this exact installed unit still has
`Restart=on-failure` and no finite `RuntimeMaxSec`. It therefore does not yet
meet the one-start/guaranteed-stop boundary. The contract records this as
`UNIT_SINGLE_START_GUARD_NOT_INSTALLED`; the controller now rejects the unit
unless its effective properties are exactly `Restart=no` and
`RuntimeMaxUSec=180000000`. No start is possible with the observed unit.

## Fail-closed authorization

`manifests/adult-publishing-commercial-first-start.m4-24.json` is the only
versioned authorization source accepted by the controller. In this commit it
is deliberately inactive:

- `active=false`;
- `decision=NO_GO`;
- `first_start_approved=false`;
- `approved_at=null`;
- no-swap risk not accepted for the first-start window; and
- the single-start unit guard is not installed; and
- all three explicit blockers remain.

The authorization gate validates this as a sound design state but exits
nonzero when `--require-approved` is requested. A later approval must be a new
reviewed Control change with an operator timestamp after the recorded
preflight, acceptance of the known no-swap risk, no blockers, the exact GO
decision and a verified single-start unit guard. Approval expires after 3600
seconds and future timestamps are rejected. An unversioned copy, hard link,
alternate path, dirty/ignored canonical file or parallel controller is rejected.

## Automated technical preflight

The `preflight` mode is read-only and requires all of the following before any
later start can be considered:

1. canonical Control is clean, on `control-main` and equal to
   `origin/control-main`;
2. the contract is the canonical versioned M4.24 file;
3. archive, manifest, unit, application commit/tree and Control commit/tree
   have the exact recorded digests;
4. the isolated restore evidence exists;
5. the existing M4.19 release gate, native unit verification and `0.6 SAFE`
   security gate pass;
6. the unit is loaded, inactive, dead and static with no prior start/restart
   evidence, `Restart=no` and a 180-second systemd maximum runtime;
7. S1 and backup timer are active, backup service is idle and only the already
   accepted unrelated `tu1nz-doc.service` may be failed;
8. runtime state is exactly empty and no runtime status or lock exists;
9. database schema, functions, exact per-table counts and complete deterministic
   row-content hashes match in one repeatable-read, read-only transaction, with
   no other database session;
10. no process, commercial timer, cron entry, Docker mount or open release file
    collides;
11. Tailscale identity is `100.121.130.51`; and
12. no process owned by the dedicated runtime user remains, sensitive manager
    or unit environment names are absent, and helper commands receive a fixed,
    credential-free environment; and
13. minimum root storage and available-memory boundaries pass.

The zero-swap result remains a risk, not a hidden technical fact. It must be
accepted in the later authorization contract before execution.

## Controlled execution and post-check

The `execute` mode is implemented but not authorized or invoked by this
sprint. Its order is fixed:

1. complete the entire read-only technical preflight;
2. rerun the authorization gate with `--require-approved` and hold an exclusive
   lock on the exact contract inode;
3. create a new root-owned `0700` evidence directory below
   `/opt/tu1nz_repos/backups/m4-24-commercial-s0-first-start`;
4. preserve the authorization and preflight snapshot;
5. rerun the complete technical preflight, compare every stable release, unit,
   contract, state, database and service boundary, then rerun authorization;
6. issue exactly one `systemctl start` for the static candidate;
7. require a fresh, privacy-safe `READY` status created after this window, with
   zero projected submissions, and
   run the versioned local health command;
8. issue `systemctl stop` within the bounded window;
9. require `STOPPED`, inactive/dead/static state and zero restarts;
10. compare the exact state-file hash and complete database snapshot with the
   pre-start snapshot;
11. rerun the release, manifest, unit, contract, provider-environment and
    canonical-Control guards; prove S1 and the backup timer active, the backup
    service idle and
    no commercial process remains; and
12. preserve the journal, status and final result as root-private evidence.

Success is impossible unless the service ends stopped. There is no mode that
leaves the first-start candidate running.

## Automated abort plan

The controller installs controlled `SIGHUP`, `SIGINT` and `SIGTERM` handling,
then marks the window as start-attempted before invoking systemd. Any subsequent
exception, command, readiness, health, timeout, state, database, evidence or
release failure invokes the abort routine. The routine:

1. captures the pre-abort service state;
2. stops the candidate if it is not already inactive;
3. waits for and verifies inactive/dead state; stop timeout or state-query
   failure remains a critical error and is never reported as success;
4. preserves the runtime status and the last 200 unit journal lines;
5. compares the complete database and state-file snapshot with the preflight
   evidence rather than claiming preservation without proof;
6. records a timestamped abort result; and
7. preserves the database, runtime state, manifest, lock, releases and all
   evidence for diagnosis.

The `finally` guard performs another mandatory, verified stop if an exception
interrupts the abort path. The 180-second systemd runtime maximum is required so
even an uncatchable controller termination cannot create an unbounded service.
The manual `abort` mode accepts only an existing root-owned
`0700` directory below the fixed evidence parent. It cannot target an arbitrary
path. Neither automatic nor manual abort deletes evidence or rolls back the
database.

## Tests and CI boundary

The M4.24 module covers:

- valid inactive contract and mandatory execution rejection;
- a complete synthetic approved-contract fixture;
- stale/future timestamp, no-swap, hash, prior-start, single-start guard,
  business-row, network and recovery
  negative cases;
- authorization-before-start ordering;
- exclusive-controller locking, full pre-start revalidation and one-start/
  one-stop success flow ending stopped;
- authorization failure proving no start command is issued;
- health and evidence failures proving abort and final stop;
- signal conversion and fatal stop-timeout behavior;
- exact per-table database counts, schema/content hashes and sum-cancellation
  detection; and
- AST and static rejection of dynamic systemctl verbs, enable, restart, broad
  deletion, provider credentials and external API URLs. Static-guard
  infrastructure errors are distinct from the expected no-match result.

CI also requires the committed contract to remain NO-GO and confirms that
`--require-approved` rejects it. The actual first start therefore cannot become
authorized accidentally through this sprint.

## Rollback

Before merge, repository rollback is branch abandonment. After merge, it is a
normal Git revert. No server rollback exists for M4.24 design because this
sprint does not deploy the controller, change the installed release, change
the unit or start a service. The M4.23 archive remains the recovery basis.

## Exact next boundary

Do not merge, deploy or start in this review. A separate stopped-unit sprint
must first version, back up, install and verify `Restart=no` plus
`RuntimeMaxSec=180`, then refresh every bound unit/manifest/archive digest and
the preflight observation. Only after a fresh reviewed approval may canonical
Control be synchronized and the read-only `preflight` mode run. `execute`
remains a further explicit action and is not part of this sprint.
