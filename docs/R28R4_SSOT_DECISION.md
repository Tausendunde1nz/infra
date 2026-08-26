# R28-R4 SSOT, backup and restore hardening

Date: 2026-08-26
Target: ubuntu-8gb-nbg1-2
Status: approved implementation record

## Repository decision

`/opt/tu1nz_repos/control` is the authoritative local Control SSOT.

Because the existing authenticated GitHub Free remote is `Tausendunde1nz/infra`, Control uses an independent orphan history on remote branch `control-main`. This avoids mixing Control files with the existing Infra working tree while providing a real remote, commit and rollback reference. Work for this change uses `chore/r28-ssot-backup-restore-hardening` and is merged by fast-forward into `control-main` after validation.

Only explicitly allowlisted files are versioned. Legacy files and any secret-like or generated artifacts remain excluded.

## Pre-change rollback evidence

Local archive:

`/backups/snapshots/r28r4-20260826T064238Z/r28r4-prechange-root.tar.gz`

Encrypted remote object:

`gcrypt01:backups/r28r4-20260826T064238Z/r28r4-prechange-root.tar.gz`

SHA-256:

`da37f86c262ef39c6569209b55fe7809b1f3ba9c0b30e1efbf7510cf8f0aa9`

The object was downloaded from the encrypted remote to an isolated restore directory. The downloaded checksum matched, the archive extracted successfully, and restored `etc/nginx/nginx.conf` plus the restored `control` directory were verified.

## Intended changes

- version the current active nginx configuration without certificates or keys;
- include `/opt/tu1nz_repos/control` in the encrypted system backup;
- run the encrypted backup only from `/usr/local/bin/tu1nz_encrypted_backup.sh` through systemd;
- make every extraction, required-path, and active Compose validation failure return a non-zero restore-test status;
- exclude archived `backup_old` Compose files from the active-service validation set;
- require restored nginx and Control paths before a restore test may succeed;
- disable the legacy Cron execution path without deleting the original forensic artifact.

## Rollback

Restore the pre-change archive into an isolated directory first. Restore only the affected paths after checksum verification. Revert systemd units and scripts from the archive, run `systemctl daemon-reload`, and validate timers and service status. Do not restore the entire archive over a live system without a separate change approval.
