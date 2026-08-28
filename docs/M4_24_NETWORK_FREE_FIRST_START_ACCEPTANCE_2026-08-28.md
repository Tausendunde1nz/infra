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

## Fail-closed authorization

`manifests/adult-publishing-commercial-first-start.m4-24.json` is the only
versioned authorization source accepted by the controller. In this commit it
is deliberately inactive:

- `active=false`;
- `decision=NO_GO`;
- `first_start_approved=false`;
- `approved_at=null`;
- no-swap risk not accepted for the first-start window; and
- explicit blockers remain.

The authorization gate validates this as a sound design state but exits
nonzero when `--require-approved` is requested. A later approval must be a new
reviewed Control change with an operator timestamp after the recorded
preflight, acceptance of the known no-swap risk, no blockers and the exact GO
decision. An unversioned copy or alternate path is rejected.

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
6. the unit is loaded, inactive, dead and static with no prior start evidence;
7. S1 and backup timer are active, backup service is idle and only the already
   accepted unrelated `tu1nz-doc.service` may be failed;
8. runtime state is exactly empty and no runtime status or lock exists;
9. database schema, functions, seed counts and all business-row zeros match;
10. no process, commercial timer, cron entry, Docker mount or open release file
    collides;
11. Tailscale identity is `100.121.130.51`; and
12. minimum root storage and available-memory boundaries pass.

The zero-swap result remains a risk, not a hidden technical fact. It must be
accepted in the later authorization contract before execution.

## Controlled execution and post-check

The `execute` mode is implemented but not authorized or invoked by this
sprint. Its order is fixed:

1. complete the entire read-only technical preflight;
2. rerun the authorization gate with `--require-approved`;
3. create a new root-owned `0700` evidence directory below
   `/opt/tu1nz_repos/backups/m4-24-commercial-s0-first-start`;
4. preserve the authorization and preflight snapshot;
5. issue exactly one `systemctl start` for the static candidate;
6. require a privacy-safe `READY` status with zero projected submissions and
   run the versioned local health command;
7. issue `systemctl stop` within the bounded window;
8. require `STOPPED`, inactive/dead/static state and zero restarts;
9. compare the exact state-file hash and complete database snapshot with the
   pre-start snapshot;
10. prove releases clean, S1 and backup timer active, backup service idle and
    no commercial process remains; and
11. preserve the journal, status and final result as root-private evidence.

Success is impossible unless the service ends stopped. There is no mode that
leaves the first-start candidate running.

## Automated abort plan

The controller marks the window as start-attempted before invoking systemd. Any
subsequent command, readiness, health, timeout, state, database or release
failure invokes the abort routine. The routine:

1. captures the pre-abort service state;
2. stops the candidate if it is not already inactive;
3. waits for inactivity without deleting or rewriting state;
4. preserves the runtime status and the last 200 unit journal lines;
5. records a timestamped abort result; and
6. preserves the database, runtime state, manifest, lock, releases and all
   evidence for diagnosis.

The `finally` guard makes a second best-effort stop if an exception interrupted
the abort path. The manual `abort` mode accepts only an existing root-owned
`0700` directory below the fixed evidence parent. It cannot target an arbitrary
path. Neither automatic nor manual abort deletes evidence or rolls back the
database.

## Tests and CI boundary

The M4.24 module covers:

- valid inactive contract and mandatory execution rejection;
- a complete synthetic approved-contract fixture;
- timestamp, no-swap, hash, prior-start, business-row, network and recovery
  negative cases;
- authorization-before-start ordering;
- one-start/one-stop success flow ending stopped;
- authorization failure proving no start command is issued;
- health failure proving abort and final stop;
- exact synthetic database snapshot; and
- static rejection of enable, restart, broad deletion, provider credentials
  and external API URLs.

CI also requires the committed contract to remain NO-GO and confirms that
`--require-approved` rejects it. The actual first start therefore cannot become
authorized accidentally through this sprint.

## Rollback

Before merge, repository rollback is branch abandonment. After merge, it is a
normal Git revert. No server rollback exists for M4.24 design because this
sprint does not deploy the controller, change the installed release, change
the unit or start a service. The M4.23 archive remains the recovery basis.

## Exact next boundary

Stop after merge and CI. A later, separately approved window must first update
the versioned M4.24 contract from NO-GO to the exact one-window GO state and
resynchronize canonical Control. Only then may the controller's `preflight`
mode be run on the server. The `execute` mode remains a further explicit action;
it is not part of this sprint.
