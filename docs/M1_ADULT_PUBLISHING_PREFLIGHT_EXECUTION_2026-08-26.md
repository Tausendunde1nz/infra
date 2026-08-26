# TU1NZ Adult Publishing – M1 preflight execution report

- Date: 2026-08-26
- Host: `ubuntu-8gb-nbg1-2`
- Tailscale address: `100.121.130.51`
- Scope: repository/bootstrap, path and writer isolation, scheduler migration,
  recurring encrypted backup and rollback verification
- M1 application implementation: not started and unchanged
- Formal result: **GO for the isolated M1 core implementation**
- Repository readiness: **PASS**
- Infrastructure/rollback readiness: **PASS**

## 1. Binding repository and path

| Item | Verified value |
|---|---|
| GitHub repository | `Tausendunde1nz/adult-publishing-core` |
| Visibility | private |
| Canonical server path | `/opt/tu1nz_repos/adult-publishing-core` |
| Owner and mode | `chatops:chatops`, `2770` |
| `chatops` write test | passed |
| Default/local branch | `main` |
| Initial/current commit | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Working tree | clean, tracking `origin/main` |
| Remote | `git@github.com:Tausendunde1nz/adult-publishing-core.git` |
| Recommended M1 branch | `feat/m1-core-state-machine` |

The future M1 branch was not created during this preflight. No application
code, migration, state machine, policy invariant or test was added.

## 2. Dedicated repository access

The server uses a repository-specific Ed25519 deploy key.

| Item | Verified value |
|---|---|
| Private-key path | `/etc/tu1nz/ssh/adult_publishing_core_ed25519` |
| Public-key path | `/etc/tu1nz/ssh/adult_publishing_core_ed25519.pub` |
| Directory | `root:chatops`, mode `0750` |
| Private key | `chatops:chatops`, mode `0600` |
| Public key | `chatops:chatops`, mode `0644` |
| Fingerprint | `SHA256:dCODoF+3mULc12wDCbNqOcpUAPpuKdQejr2NYYfMq/4` |
| GitHub title | `ubuntu-8gb-nbg1-2 adult-publishing-core` |
| GitHub scope | this repository only |
| GitHub access | read/write |

GitHub authentication and a push dry-run passed. Private-key material was not
copied to GitHub, logs or documentation.

## 3. Writer and path-isolation audit

Final read-only checks established:

- no running container mounts the canonical M1 repository;
- no open file handle exists below the repository path;
- no active `chatops` cron entry remains;
- the only exact path references below the audited system locations are:
  - `/usr/local/bin/tu1nz_encrypted_backup.sh`, which reads the repository into
    the encrypted backup; and
  - `/usr/local/bin/tu1nz_m1_infra_gate.sh`, whose preflight action is read-only;
- the legacy Git-sync service is sandboxed to the three legacy bot paths and
  has no reference or write path to the M1 repository.

No service, timer or container was found that automatically pulls, commits,
pushes or writes application content in the M1 repository.

## 4. Cron-to-systemd migration

The two previously active `chatops` cron entries were migrated only after
manual service validation. The installed `chatops` crontab is now
comment-only, and the final active-entry count is `0`.

| Timer | Final state | Function |
|---|---|---|
| `tu1nz-mommyramona-health.timer` | enabled, active | state-aware HTTP health check every two minutes |
| `tu1nz-legacy-git-sync.timer` | enabled, active | legacy bot repository sync every 30 minutes |
| `tu1nz_encrypted_backup.timer` | enabled, active | daily encrypted system backup |

Manual validation results:

- the health-check service completed successfully;
- the Git-sync service completed successfully after optional legacy paths were
  represented correctly in its systemd namespace; and
- the encrypted-backup service completed successfully.

`cron.service` remains active for system/package and broader legacy schedules.
No remaining cron location references the M1 repository. Disabling the system
cron service is not part of this scoped M1 preflight because doing so without a
separate inventory and replacement of every system task would create an
unrelated platform risk.

## 5. Encrypted backup and restore proof

### Pre-change rollback artifact

| Item | Verified value |
|---|---|
| Timestamp | `20260826T113904Z` |
| Local root | `/opt/tu1nz_repos/backups/m1-infra-unblock-20260826T113904Z` |
| Encrypted remote | `gcrypt01:backups/m1-infra-unblock/20260826T113904Z/m1-infra-unblock-20260826T113904Z.tar.gz` |
| SHA-256 | `b049407786cfacc102afc75de0c2d347e827356cca62a1f6306cc6223f71939b` |
| Downloaded SHA-256 | identical |
| Isolated extraction | passed |

### Recurring M1-aware backup proof

| Item | Verified value |
|---|---|
| Local archive | `/opt/tu1nz_repos/backups/encrypted-system/tu1nz_system_backup_20260826T12-08-48Z.tar.gz` |
| Encrypted remote | `gcrypt01:backups/tu1nz_system_backup_20260826T12-08-48Z.tar.gz` |
| SHA-256 | `b74631cf6cb73c3649f730f6205ba1447ca500535ab6e264f4ee0817aa481a8a` |
| Isolated restore root | `/opt/tu1nz_repos/backups/restore-tests/20260826T120910Z/extracted` |
| Restored Control commit | `bd1c396f617eed95306fb112e4530b677bb0cf56` |
| Restored M1 commit | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Local/remote byte comparison | passed |
| Archive integrity | passed |
| Both Git object checks | passed |
| Both restored worktrees | clean |
| Final restore marker | `RESTORE_VERIFY=PASS` |

Nothing was removed after the restore tests. The artifacts and isolated restore
trees remain available for audit and rollback.

## 6. Incidents handled during execution

The following stops were documented under `analysis/` before recovery:

1. systemd verification initially ran before the ExecStart scripts existed;
2. a Control pull was attempted in the root SSH context instead of `chatops`;
3. the first Git-sync service start failed because a missing optional legacy
   path was treated as mandatory by systemd; and
4. the first restore gate exposed pre-existing ignored analysis material after
   an overly broad `.gitignore` exception.

Each issue was contained before timer activation, documented with evidence and
rollback, corrected in Control, committed and pushed, and then revalidated.

## 7. Residual risks

### Explicitly accepted

- GitHub Free protection limitations were explicitly accepted by the user.

### Non-blocking, separately tracked

1. The repository-scoped deploy key intentionally permits writes. A server
   compromise could write to this repository until the key is revoked.
2. The legacy SpicyMila Git remote reports an existing authentication warning
   during pull. That service does not reference or write the M1 repository.
3. `cron.service` remains active for platform tasks outside the M1 path. A
   complete platform-wide cron retirement requires its own inventory, backup,
   rollback and maintenance approval.

These risks do not invalidate the verified M1 path isolation or rollback
capability and therefore do not block the scoped M1 core implementation.

## 8. Formal decision and exact next steps

**GO for the isolated M1 core implementation.**

The GO is limited to the following future work in
`/opt/tu1nz_repos/adult-publishing-core`:

- core data model;
- migrations;
- submission state machine;
- policy invariants; and
- automated tests.

Exact next steps:

1. Confirm the repository still resolves to clean `main` at
   `5572ea165c11fa9d409d1e76ddf08243ae657ea0`.
2. Create `feat/m1-core-state-machine` from that commit.
3. Implement only the approved M1 core scope and its tests.
4. Do not add Telegram, AVS, X, payment, systemd, token, deployment or live
   publishing integration in M1.
5. Keep the legacy Git authentication warning and platform-wide cron inventory
   in separate infrastructure/security work; neither belongs in the M1
   application branch.
