# M1 infrastructure unblock – cron migration and recurring backup

- Date: 2026-08-26
- Host: `ubuntu-8gb-nbg1-2`
- Status: approved implementation plan, activation pending validation
- M1 application code: out of scope and unchanged

## Objective

1. Replace the two active `chatops` cron entries with systemd timers.
2. Preserve the existing explicit legacy bot repository scope; never add the M1
   repository to automatic pull, commit or push behavior.
3. Extend the daily encrypted system backup to include both `control` and
   `adult-publishing-core`.
4. Retain an exact, encrypted rollback artifact before activation.

## Pre-change backup

| Item | Value |
|---|---|
| Timestamp | `20260826T113904Z` |
| Local root | `/opt/tu1nz_repos/backups/m1-infra-unblock-20260826T113904Z` |
| Encrypted remote | `gcrypt01:backups/m1-infra-unblock/20260826T113904Z/m1-infra-unblock-20260826T113904Z.tar.gz` |
| SHA-256 | `b049407786cfacc102afc75de0c2d347e827356cca62a1f6306cc6223f71939b` |
| Downloaded SHA-256 | `b049407786cfacc102afc75de0c2d347e827356cca62a1f6306cc6223f71939b` |
| Isolated extraction | passed |

The archive contains the active user crontab, system crontab directories, the
active encrypted-backup unit/timer and the relevant scripts.

## Migration mapping

| Existing scheduler | Replacement |
|---|---|
| two-minute MommyRamona curl | `tu1nz-mommyramona-health.service/.timer` |
| thirty-minute legacy Git sync | `tu1nz-legacy-git-sync.service/.timer` |
| daily encrypted backup | hardened `tu1nz_encrypted_backup.service/.timer` |

The legacy Git service remains restricted to:

- `/opt/spicymila_bot`
- `/opt/telegram_chatbot`
- `/opt/trendwatch_bot`

It has no reference or write path to
`/opt/tu1nz_repos/adult-publishing-core`.

## Activation order

1. Validate shell syntax and unit definitions from Control.
2. Commit and push this SSOT revision before server activation.
3. Install scripts under `/usr/local/bin` and units under
   `/etc/systemd/system` with root ownership and fixed modes.
4. Run each oneshot service manually and inspect its journal.
5. Run the encrypted backup and prove that its remote archive contains the M1
   repository through an isolated restore test under
   `/opt/tu1nz_repos/backups/restore-tests`.
6. Enable and start each replacement timer only after the service and restore
   gates pass.
7. Install the comment-only `chatops` crontab only after both replacement
   services pass and their timers are active.

## Risks

- Concurrent Git syncs could race; the service uses a runtime lock.
- A missing HTTP endpoint must fail visibly in systemd without repeated chat
  notifications.
- The backup may fail if any required path is absent; all paths are validated
  before the archive is uploaded.
- System-level cron and package maintenance are not disabled by this scoped
  migration. A separate platform-wide decision is required before disabling
  `cron.service`.

## Rollback

1. Disable and stop the three new/revised timers.
2. Restore the exact unit and script files from the verified pre-change archive.
3. Restore the saved `chatops.crontab` with the `crontab` command.
4. Run `systemctl daemon-reload`, restore the previous enablement state and
   validate the original schedules.
5. Revoke no GitHub key: this change does not alter repository credentials.
