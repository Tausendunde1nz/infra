# M3.9 — Persistent Telegram STAGING-S1

Status date: 2026-08-27

Control decision: **GO for a controlled, synthetic-only S1 release after every
gate in this document passes; NO-GO for production and all real publishers**

## Goal and boundary

M3.9 installs one persistent worker for the dedicated
`TU1NZ_Adult_Sandbox_Bot`. The bot accepts only the previously registered
non-person synthetic fixture and allowlisted test identities. PostgreSQL is
local. Adult verification, moderation and payment are synthetic/mock. Telegram,
X and Reddit publication and takedown remain deterministic network-free
adapters.

No public listener, proxy, DNS, TLS, webhook, cron job, AVS provider, payment
provider, X API, Reddit API or Telegram publication destination is added. The
only external network boundary is Telegram Bot API long polling and replies for
the dedicated sandbox bot.

## Exact host contract

| Resource | Authoritative value |
| --- | --- |
| Service | `tu1nz-adult-publishing-s1.service` |
| Runtime identity | `tu1nz-adult-s1:tu1nz-adult-s1`, system/non-login |
| Application releases | `/opt/tu1nz_repos/releases/adult-publishing/staging-s1/application/<SHA>` |
| Control releases | `/opt/tu1nz_repos/releases/adult-publishing/staging-s1/control/<SHA>` |
| Virtual environments | `/opt/tu1nz_repos/releases/adult-publishing/staging-s1/venv/<application-SHA>` |
| Active pointers | sibling `application-current`, `control-current`, `venv-current` symlinks |
| Configuration | `/etc/tu1nz/adult-publishing/staging-s1`, root/runtime, `0750` |
| Config files | root/runtime, `0640`, regular and single-link |
| State | `/var/lib/tausendunde1nz/adult-publishing/staging-s1`, runtime, `0750` |
| Media | state child `media`, runtime, `0700` |
| State/cursor/status/lock | runtime, `0600` |
| PostgreSQL | local Unix socket, database `tu1nz_adult_s1`, role `tu1nz-adult-s1` |
| Migrations | one-shot administrator action; never the application identity |

After all application migrations, the administrator applies the byte-exact
`config/adult-publishing/staging-s1/bootstrap.sql`. It creates only one
pseudonymous synthetic creator, synthetic policy and three network-free TEST
destinations, then grants the runtime role only schema usage and application
DML/function access. It stores no raw Telegram identity and no credential.

Ubuntu 24.04 does not provide PostgreSQL 17 from its distribution snapshot.
The host may therefore install `postgresql-17` and `postgresql-client-17` only
from the PostgreSQL Global Development Group repository for `noble-pgdg`. The
repository key is stored at
`/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc`; the deb822 source is
`/etc/apt/sources.list.d/pgdg.sources`, is byte-identical to
`config/postgresql/pgdg.sources`, uses HTTPS and `Signed-By`, and names no
testing or development component. The downloaded official key must have
SHA-256 `0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76`.
The installed package version is captured in the deployment evidence. No
database port is opened by this decision.

The release directories and virtual environment are immutable, root-owned and
group-readable by the runtime. The application can write only its state root.

## Credentials and configuration

The token never enters Git, a command line, a process listing, logs, status or
the release manifest. It is installed out of band in `runtime.env`. The only
accepted environment keys are:

```text
TU1NZ_TELEGRAM_STAGING_S1_TOKEN
TU1NZ_STAGING_S1_POSTGRES_DSN
```

The DSN must exactly select the local Unix socket, dedicated database and
dedicated role. Identity policy, subject key, media registry and core identity
bindings are separate mode-`0640` files. Core bindings must identify
`STAGING-S1`; S0 identities are rejected.

## Release and activation gate

The release manifest binds:

- exact application and Control commits;
- every migration and the reviewed dependency lock;
- the encrypted backup archive digest and completion time;
- the dedicated bot and `STAGING-S1` environment;
- synthetic-only, mock-payment and no-live-publisher flags;
- `TELEGRAM`, `X` and `REDDIT` as the required product targets;
- RPO, RTO and retention targets.

For this synthetic-only staging service the selected operational targets are:

```text
RPO: 86400 seconds (24 hours)
RTO: 14400 seconds (4 hours)
Retention: 7 days
```

The service pre-start gate fails closed unless the exact repositories are clean,
SHA-named and immutable; configuration, state and ownership match; the initial
conversation state is empty; the cursor is valid; the pinned dependency closure
imports; and the installed systemd unit is byte-identical to Control SSOT.

## Backup and recovery

Before activation, the existing encrypted backup is run and verified. After the
S1 resources exist, the versioned backup additionally archives:

- immutable S1 application, Control and virtual-environment releases;
- S1 configuration, state and registered synthetic media;
- a custom-format PostgreSQL dump created as the S1 database role.

The archive is uploaded only to `gcrypt01:backups`. A release manifest is
created from that exact local archive after upload. Recovery acceptance must
verify the archive digest, Git SHAs, migration/dependency hashes, required
configuration/state members, `pg_restore --list`, and a restore into a fresh
throwaway database before service start.

## Controlled sequence

1. merge application M3.9 and Control M3.9 through reviewed pull requests;
2. take and verify the pre-change encrypted backup;
3. repeat privileged path/service/timer/container/open-file checks;
4. install the supported native PostgreSQL 17 packages from the exact PGDG
   source above, then create the dedicated OS and PostgreSQL identities;
5. stage clean SHA-named releases and a hash-locked virtual environment;
6. install private configuration and fresh state without printing secrets;
7. apply all migrations as an administrator and seed only synthetic fixtures;
8. install the versioned backup script and create/upload the exact S1 archive;
9. perform the isolated restore proof;
10. generate and install the release manifest;
11. install the byte-identical unit, reload systemd, run the gate manually;
12. enable/start only the S1 service and require fresh `READY` health;
13. record deployed SHAs, backup digest, restore result and service health in
    Control; never include the token or raw Telegram identities.

## Interference and accepted isolation

The preceding M3.8 inventory found no systemd unit, timer, container mount,
cron entry or open file targeting the new S1 paths. Existing unrelated host
findings (legacy failed/unhealthy workloads, public listeners, inactive UFW and
the active cron daemon) do not share an S1 path and are not modified by this
sprint. A fresh privileged check is mandatory immediately before staging; any
path collision or open writer changes the decision to NO-GO.

## Rollback

Rollback targets only the S1 service and exact S1 paths:

1. stop and disable `tu1nz-adult-publishing-s1.service`;
2. preserve failure evidence and the current state/database dump;
3. atomically point the three active links to the prior manifest-bound SHAs;
4. restore S1 config/state/database from the matching encrypted archive;
5. run the release gate and database consistency checks;
6. start the prior release and require fresh `READY` health.

If no prior S1 release exists, leave the service disabled and retain the state
for investigation. Legacy bots and unrelated databases are never rollback
targets.

## Product trace

M3.9 advances persistent execution of `P01`-`P12`, not a new product. Telegram
creator intake and safe replies are the only external provider actions. Adult
verification, consent, moderation, policy and EUR 9.99 payment evidence remain
synthetic. All three required publication targets and takedown paths remain in
the flow but are network-free.

`TELEGRAM`, `X`, `REDDIT` and payment remain mandatory North Star outcomes. The
next missing product step after stable S1 evidence is a separately authorized
provider-sandbox publisher. Real adult media, real AVS/payment, live Telegram
publication, X, Reddit and production remain **NO-GO**.
