# M4.18 — Commercial runtime Control SSOT and server readiness

Date: 2026-08-28

Control branch: `feat/m4-18-commercial-runtime-control-readiness`

Control baseline: `0467b6354f0202b95c86c17bdca6c45dfd1626d5`

Application candidate: `183c5479246a27e7844670bf53c7e34200de92ea`

Decision: **GO / COMPLETE for the versioned Control contract and read-only
server preflight; NO-GO for installation, activation and every real provider**

## Goal and product trace

M4.18 keeps TU1NZ on the direct product path: a creator submits media through
Telegram, proves age and consent, receives human moderation, selects paid
Telegram/Reddit distribution and may separately authorize uncompensated X
automation. Payment, publication and takedown must remain entitlement-bound and
recoverable.

The M4.17 candidate proves that commercial state machine with synthetic data and
network-free publishers. M4.18 does not add another product detour. It places
the reviewed M4.17 boundary in Control SSOT and checks whether an isolated host
location exists for a later server sprint.

M4.18 performs no installation, activation, migration, database write, service
or timer action, token access, provider request, media transfer, payment,
publication, deployment or merge. The existing Telegram S1 sandbox remains
untouched.

## Authoritative repositories

| Concern | Evidence |
| --- | --- |
| Control SSOT | `Tausendunde1nz/infra`, branch `control-main` |
| Fresh Control baseline | clean `0467b6354f0202b95c86c17bdca6c45dfd1626d5` locally and on the server |
| Historical bootstrap repository | `Tausendunde1nz/control`; not the technical runtime SSOT |
| Application candidate | clean `183c5479246a27e7844670bf53c7e34200de92ea` |
| Application review | Draft PR #58, mergeable and all four current CI jobs green |
| Application ancestry | stacked Draft PRs #49 through #58; candidate is not merged to `main` |
| Application `origin/main` during preflight | `ed6e56246a59b786464ea3f843f2087c20971d64` |
| Server canonical application checkout | clean but stale `5572ea165c11fa9d409d1e76ddf08243ae657ea0`; prohibited as a release source |

Because the application chain is not merged, the M4.18 manifest explicitly
records `application_merged_to_main=false` and `activation_decision=NO_GO`.
Squash or rebase can change the final deployable SHA; a later release manifest
must bind the final reviewed main-reachable commit rather than silently reuse
this preflight SHA.

## Reviewed inactive contract

`manifests/adult-publishing-commercial-readiness.m4-18.json` binds the exact
M4.17 candidate files, dependency lock and both directions of migration 0014.
The read-only gate verifies their SHA-256 values, clean application Git state,
origin, entrypoints and exact candidate configuration.

The following conditions are mandatory and mechanically checked:

- `active=false`, `installed=false` and `server_enabled=false`;
- `network_enabled=false`, `external_providers_enabled=false` and
  `telegram_intake_enabled=false`;
- `real_media_enabled=false` and `real_payment_enabled=false`;
- PostgreSQL remains `LOCAL_ONLY`;
- only synthetic publishers are reachable;
- paid targets are exactly `REDDIT` and `TELEGRAM`;
- X is required for the product journey but is separately recorded as
  uncompensated; and
- at least one activation gate must remain blocked.

No systemd unit is introduced in M4.18.

## Planned isolated host contract

| Resource | Planned value; not created |
| --- | --- |
| Application releases | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/application/<SHA>` |
| Control releases | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/control/<SHA>` |
| Virtual environments | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/venv/<SHA>` |
| Configuration | `/etc/tu1nz/adult-publishing/staging-s0-commercial` |
| State | `/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial` |
| OS identity | `tu1nz-adult-commercial-s0:tu1nz-adult-commercial-s0` |
| Database | `tu1nz_adult_commercial_s0` |
| Database identities | `tu1nz_adult_commercial_s0_migrator`, `tu1nz_adult_commercial_s0_runtime` |

All paths and identities were absent. Their existing parents are root-owned and
not writable by `chatops`, so a future installation needs a separate reviewed
root window. The names do not overlap the active `staging-s1` service.

## Fresh Tailscale-only server observation

The observation used only `100.121.130.51`. Three VPN pings resolved to
`ubuntu-8gb-nbg1-2` through `DERP(nue)`; a direct peer path was not established.
Tailscale SSH authenticated both `chatops` and a later read-only root check.
The host was Ubuntu 24.04.3 LTS with kernel 6.8.

The local Mac CLI (`1.86.2`) and its local tailscaled daemon (`1.86.4`) report
a version skew. This did not alter server identity, but it is a maintenance
risk. No update was performed.

At observation time:

- root filesystem: 75 GiB total, 20 GiB available, 73 percent used;
- inodes: 14 percent used;
- memory: 7.6 GiB total, 5.7 GiB available; no swap;
- PostgreSQL 17.11 was online;
- TCP 5432 listened only on `127.0.0.1`; the local Unix socket accepted
  connections; and
- the planned database and every planned OS/database identity were absent.

Capacity is sufficient for planning only. It must be recalculated against the
final archive, immutable application/Control releases and virtual environment
immediately before any installation.

## Interference and path ownership

The privileged inventory found no service, timer, cron entry, process, Docker
mount, open file or configuration that references `staging-s0-commercial` or
the planned identity/database names. The commercial service unit does not
exist.

The existing `tu1nz-adult-publishing-s1.service` is enabled, active and running
with zero automatic restarts. Its immutable application/control releases are
`91d0ae139604bfe8eb61812797cac1056fa2c7d2` and
`a6a7740ed854238aa575e741bf7812f601a20217`; every read/write path is beneath
the separate `staging-s1` roots.

One important Control risk is accepted only for this preflight:
`tu1nz_agentmode.service` runs `/usr/local/bin/tu1nz_sync_all.sh` every five
minutes. That script fetches and executes `git reset --hard @{u}` in the
canonical `/opt/tu1nz_repos/control` checkout. Therefore:

- no uncommitted or manually staged release may ever use that checkout;
- the M4.18 changes must be committed, pushed, reviewed and merged before the
  server observes them; and
- every future release must use a separate clean SHA-named immutable Control
  directory, never the mutable canonical worktree.

The legacy Git-sync timer touches only the SpicyMila, Telegram chatbot and
Trendwatch legacy repositories. Containers do not mount an Adult Publishing
path. The known `tu1nz-doc.service` failure and unhealthy `spicymila_bot`
container remain unrelated and were not changed.

## Backup, restore and rollback evidence

The daily encrypted backup service completed successfully at 03:32 UTC. The
fresh archive is:

```text
tu1nz_system_backup_20260828T03-31-58Z.tar.gz
bytes: 45142464
sha256: 5110d1e85d4256e22af6ad44cf23cb0333cd759c763219ce35a10dcc0f1496e5
entries: 11506
remote: exactly named object present at gcrypt01:backups
```

The daily restore smoke test successfully decrypted and checked that exact
archive at `2026-08-28T06:16:52Z`. It contains the canonical Control and
application checkouts plus existing S1 releases. It does not contain a member
named for M4.17 SHA `183c5479246a27e7844670bf53c7e34200de92ea`.

The backup log also reports a nonfatal failure to save an updated rclone config
because the config filesystem is read-only. The transfer still completed 1/1,
the service returned success, the remote object is present and the later smoke
restore passed. A future activation backup must either produce a clean log or
explicitly prove that this message cannot invalidate credential persistence.

This is valid current-host rollback evidence, not a qualifying commercial
release backup. The exact candidate release, final Control SHA, new database,
configuration and state do not exist and therefore cannot be restored. Their
activation gates remain false.

M4.18 repository rollback is branch abandonment before merge or a normal Git
revert afterward. No server rollback is required because M4.18 changed no
server state.

## GO / NO-GO matrix

| Gate | Result |
| --- | --- |
| Exact M4.17 candidate and artifact hashes | **GO** |
| Fail-closed Control contract and negative tests | **GO** |
| Fresh Tailscale/root server identity | **GO** |
| Planned paths and identities collision-free | **GO** |
| Privileged unit/timer/cron/container/process/open-file scan | **GO** |
| Current encrypted host backup present remotely | **GO** |
| Current archive restore-smoke evidence | **GO** |
| Application candidate merged to main | **NO-GO** |
| Final immutable application and Control releases staged | **NO-GO** |
| Dedicated OS/database identities and isolated database | **NO-GO** |
| Commercial systemd unit versioned and reviewed | **NO-GO** |
| Migration 0014 installed in isolated server database | **NO-GO** |
| Backup and restore bound to exact commercial release | **NO-GO** |
| Installed acceptance and rollback rehearsal | **NO-GO** |
| Telegram intake, external AVS/payment or live publishers | **NO-GO** |
| Production | **NO-GO** |

## Exact next steps

1. Review and merge M4.18 Control only after its own CI is green. It triggers
   no deployment.
2. Review and merge the application Draft chain #49 through #58 in dependency
   order, rerun all CI on the final main-reachable state and record the final
   application SHA. Do not deploy any intermediate branch head.
3. Run a separately authorized M4.19 isolated commercial S0 installation-design
   sprint: version the exact manifest generator, release gate, hardened
   network-free unit, backup coverage and rollback procedure in Control. Keep
   them uninstalled and disabled.
4. Only after that review may a separate root installation window create the
   exact paths and identities, stage SHA-named releases, create the isolated
   database, take a fresh exact-release backup, prove an isolated restore, run
   migrations/acceptance and rehearse rollback.
5. Real Telegram media, AVS, payment, Telegram/X/Reddit publishers and
   production remain separate later provider windows.

Recommended continuing branch: the current
`feat/m4-18-commercial-runtime-control-readiness` until its Draft PR is reviewed.

## Validation evidence

- all four explicit Control test modules: **69/69 passed**;
- M4.18 positive/negative contract module: **12/12 passed**;
- exact local gate against application SHA `183c5479246a27e7844670bf53c7e34200de92ea`:
  `M4_18_COMMERCIAL_READINESS_OK`;
- all Python Control scripts/tests compiled;
- all versioned shell scripts passed syntax validation;
- both M4.18 JSON artifacts parsed successfully; and
- Git whitespace validation passed.

The rejected zero-test discovery invocation and its explicit-module correction
are recorded in the matching diagnosis rather than counted as evidence.
