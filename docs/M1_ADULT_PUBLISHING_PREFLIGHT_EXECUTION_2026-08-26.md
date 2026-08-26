# TU1NZ Adult Publishing – M1 preflight execution report

- Date: 2026-08-26
- Host: `ubuntu-8gb-nbg1-2`
- Tailscale SSH endpoint: `100.121.130.51:2222`
- Scope: repository/bootstrap, path and writer isolation, backup and rollback verification
- Explicitly excluded: M1 implementation, Telegram bot, AVS, X, payment, systemd integration and deployment
- Formal result: **NO-GO for starting M1 implementation**
- Repository readiness result: **PASS**

## 1. Binding repository and path

| Item | Verified value |
|---|---|
| GitHub repository | `Tausendunde1nz/adult-publishing-core` |
| Visibility | private |
| Canonical server path | `/opt/tu1nz_repos/adult-publishing-core` |
| Owner and mode | `chatops:chatops`, `2770` |
| Default/local branch | `main` |
| Initial commit | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Working tree | clean, tracking `origin/main` |
| Remote | `git@github.com:Tausendunde1nz/adult-publishing-core.git` |
| Recommended future M1 branch | `feat/m1-core-state-machine` |

The future M1 branch was not created during this preflight. No application code,
migration, state machine, policy invariant or test was added.

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

GitHub authentication identified the key as
`Tausendunde1nz/adult-publishing-core`. A push dry-run from clean `main`
returned `Everything up-to-date`. Private-key material was never copied to
GitHub or included in this document.

## 3. Writer and path-isolation audit

### Positive findings

- No exact reference to `/opt/tu1nz_repos/adult-publishing-core` was found in
  active systemd unit files, `/usr/local/bin`, system cron directories or
  container configuration.
- No running container mounts the repository or its canonical path.
- No open file handle was found below the repository path.
- `tu1nz_agentmode.service` synchronizes only the explicitly configured `docs`
  and `control` repositories.
- `agentmodus_tu1nz.service` writes only its own agent log.
- `tu1nz-guard.service` discovers all repositories below
  `/opt/tu1nz_repos/*`, but only reads Git status and reports drift; it does not
  modify the M1 repository.
- `t1nz-golden-snapshot.service` writes to its snapshot/log destinations and
  performs Git changes only in the explicitly configured `docs` repository.
- The broad inventory script under `/usr/local/bin` lists repository scripts
  but does not execute the ownership commands it prints.

### Blocking finding: active cron entries

The active `chatops` crontab still contains two live entries:

```text
*/2 * * * * curl -fsS https://api.mychatbuddy.dev/mommyramona/health ...
*/30 * * * * /usr/local/bin/tausendunde1nz-git-sync.sh ...
```

The Git-sync script is limited to these legacy paths and does not touch M1:

- `/opt/spicymila_bot`
- `/opt/telegram_chatbot`
- `/opt/trendwatch_bot`

This proves path isolation, but the live cron entries still violate the binding
TU1NZ rule that cronjobs are prohibited and only systemd timers may schedule
work. The server cron spool contained an active `chatops` crontab and one dated
backup; no active root crontab was present.

## 4. Encrypted snapshot and restore proof

The clean initial repository was archived, uploaded through the encrypted
`gcrypt01` remote, downloaded again and restored into an isolated directory.

| Item | Verified value |
|---|---|
| Snapshot timestamp | `20260826T112914Z` |
| Local snapshot root | `/opt/tu1nz_repos/backups/m1-adult-publishing-core-20260826T112914Z` |
| Encrypted remote object | `gcrypt01:backups/m1-adult-publishing-core/20260826T112914Z/adult-publishing-core-20260826T112914Z.tar.gz` |
| Archive size | `12379` bytes |
| Source SHA-256 | `c879cf6d2820f7c4a4ae2a4b9bbed04d3f1308eaee3496a80a168ae4b276af85` |
| Downloaded SHA-256 | `c879cf6d2820f7c4a4ae2a4b9bbed04d3f1308eaee3496a80a168ae4b276af85` |
| Restored commit | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Restored branch/status | `main`, clean |
| Git object validation | `git fsck --no-dangling` passed |
| Restore test | **PASS** |

Nothing was deleted after the test. The source archive, downloaded archive and
isolated restore tree remain available for audit and rollback.

The currently scheduled encrypted backup script still archives only legacy bot
and nginx paths. Therefore the verified one-off M1 snapshot is the current
encrypted rollback artifact; recurring M1 coverage must be decided and
documented before M1 contains non-trivial work.

## 5. Risks and decision

### Accepted residual risk

The user explicitly chose GitHub Free and accepted its remaining protection
limitations. This is recorded as an accepted residual risk and is not the reason
for the NO-GO result.

### Open risks

1. Two active cron entries conflict with the binding system policy.
2. The scheduled encrypted backup does not yet include the M1 repository.
3. A deploy key with write access is intentionally stored on the server. Its
   blast radius is limited to this one repository; server compromise would still
   permit writes to that repository until the key is revoked.

### Formal decision

**NO-GO for starting M1 implementation.**

The repository, key, canonical path, Git baseline, writer isolation and tested
rollback artifact are ready. Formal GO is withheld because the active cron state
contradicts the binding TU1NZ policy and recurring encrypted coverage for the new
repository has not yet been established or explicitly waived.

## 6. Exact next steps

1. Open a separate, SSOT-first infrastructure maintenance step for the two
   active `chatops` cron entries.
2. Document equivalent state-aware systemd services/timers, rollback and backup
   before activation; do not place this infrastructure work in the M1 repository.
3. Disable the cron entries only after the replacement timers pass their health
   checks, then verify that `crontab -l` contains no active jobs.
4. Extend or explicitly waive recurring encrypted backup coverage for
   `/opt/tu1nz_repos/adult-publishing-core`; retain the proven one-off snapshot.
5. Re-run the read-only writer, cron, container, Git and backup checks.
6. Only after a clean GO, create `feat/m1-core-state-machine` from commit
   `5572ea165c11fa9d409d1e76ddf08243ae657ea0` and begin the strictly isolated M1
   core scope.
