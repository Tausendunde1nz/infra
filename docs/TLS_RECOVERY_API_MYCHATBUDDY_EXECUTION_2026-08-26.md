# TLS recovery execution evidence for api.mychatbuddy.dev

Date: 2026-08-26
Target: ubuntu-8gb-nbg1-2 / 91.98.112.14
Control branch: `chore/r28-ssot-backup-restore-hardening`
Prepared SSOT commit: `b06749ff069bd4e9c9d9f23c74a68e300522c98b`
Status: primary TLS recovery successful

## Scope

This maintenance activated only the committed ACME HTTP-01 route for
`api.mychatbuddy.dev`, renewed that named certificate, re-enabled the existing
Certbot timer, and recorded validation evidence. No bot, webhook, token,
application container, or unrelated virtual host was changed.

## Pre-change evidence and rollback

The loaded nginx target is the regular file
`/etc/nginx/sites-enabled/api.mychatbuddy.dev`. Its pre-change SHA-256 was
`37f07a9ffdf7c5baf76ec700940ade33f6f890384f068d8f8e19aed1ba63c75a`.

A root-owned mode-0600 rollback copy was created below
`/etc/tu1nz/rollback/tls-api-mychatbuddy-20260826T094308Z/` and its checksum
matched the loaded pre-change file.

The wider recovery archive remains
`/backups/snapshots/r28r4-20260826T064238Z/r28r4-prechange-root.tar.gz`, SHA-256
`da37f86c262ef39c6569209b55fe7809b1f3ba9c0b30e1efbf7510cf8f0aa9`.

## nginx activation

The direct diff between the loaded target and the prepared Control file
contained only the nine added ACME lines. After installation, both files have
SHA-256 `0abd82507e6cfa45aacdd5b36c13ad9e1e8b187dde6187369af4030607456499`.

Full `nginx -t` validation succeeded before activation, after activation, and
after certificate renewal. Controlled reloads completed successfully at
09:53:11 UTC and 09:56:11 UTC. nginx remained active throughout.

The existing warning about protocol options being redefined in
`/etc/nginx/sites-enabled/n8n.conf:11` was present before the change and remains
non-fatal. It was not changed in this TLS window.

## Certificate renewal

The previous certificate expired on 2025-12-30 and had SHA-256 fingerprint
`0A:4A:21:FF:E1:8E:D4:C3:67:A2:C8:E8:7A:0A:63:C8:0F:7E:4B:D6:BF:44:DA:1F:F2:51:8D:3A:F3:50:F2:CC`.

A named Certbot staging dry-run succeeded before production issuance. The
production renewal for only `api.mychatbuddy.dev` succeeded. The externally
served certificate now has:

- subject: `CN=api.mychatbuddy.dev`;
- issuer: Let's Encrypt `YE1`;
- validity: 2026-08-26 08:56:42 UTC through 2026-11-24 08:56:41 UTC;
- SHA-256 fingerprint:
  `F0:C8:CE:0F:8B:F3:4C:E8:F3:F1:EE:90:AB:3A:67:93:0D:94:06:F4:C6:A1:1A:52:57:4B:52:49:39:7E:8A:0D`.

A second named staging dry-run after renewal also succeeded.

## Automatic renewal

`certbot.timer` is enabled and active. Its immediate overdue run completed with
`Result=success` and exit status 0. At the time of validation, the next trigger
was scheduled for 2026-08-26 22:19:18 UTC.

## Strict external validation

All checks used normal certificate verification; no insecure bypass was used.

- `https://api.mychatbuddy.dev/spicy/health`: 200;
- `https://api.mychatbuddy.dev/spicymila/health`: 200;
- `https://api.mychatbuddy.dev/mommyramona/health`: 200 with body `OK`;
- `https://n8n.mychatbuddy.dev/healthz`: 200;
- `https://lighting.tu1nz.com/`: 200;
- `https://tu1nz.com/`: 200.

## Separate findings not changed in this window

- `https://api.mychatbuddy.dev/trendwatch/` returns 502 because no process is
  listening on the already-configured upstream port 3011.
- `trendwatch.tu1nz.com` uses the `api.mychatbuddy.dev` certificate, whose only
  DNS SAN is `api.mychatbuddy.dev`; strict hostname validation therefore fails.
- `/etc/nginx/sites-available/api.mychatbuddy.dev` is a stale, non-loaded copy
  using Trendwatch port 8095. The loaded `sites-enabled` file used port 3011
  before and after this maintenance.

These are separate pre-existing Trendwatch/configuration-hygiene incidents.
No Trendwatch repair was attempted and rollback of the successful API TLS
recovery is not indicated.
