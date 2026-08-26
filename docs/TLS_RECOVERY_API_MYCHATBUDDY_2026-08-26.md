# TLS recovery plan for api.mychatbuddy.dev

Date: 2026-08-26
Target: ubuntu-8gb-nbg1-2
Status: prepared in Control SSOT; not activated

## Incident evidence

The certificate presented by `api.mychatbuddy.dev` expired on 2025-12-30. Its SHA-256 fingerprint is `0A:4A:21:FF:E1:8E:D4:C3:67:A2:C8:E8:7A:0A:63:C8:0F:7E:4B:D6:BF:44:DA:1F:F2:51:8D:3A:F3:50:F2:CC`.

The Certbot renewal profile uses the `webroot` authenticator with `/var/www/certbot`, but the active nginx virtual host has no route for `/.well-known/acme-challenge/`. Read-only HTTP probing returns 404. Repeated Certbot renewals failed before `certbot.timer` was disabled on 2026-02-16.

## Prepared SSOT change

`nginx/current/api.mychatbuddy.dev` contains an exact-match-prefix ACME HTTP-01 location rooted at `/var/www/certbot`. Existing bot health, webhook, TLS, and proxy routes are otherwise unchanged.

## Activation boundary

This preparation does not authorize writes to `/etc/nginx`, `/etc/letsencrypt`, or `/var/www/certbot`. Activation requires a separate approved maintenance window and a human-controlled privileged session because those paths are outside the standing TU1NZ agent write allowlist.

## Activation sequence

1. Record the current live nginx file checksum and copy it to a dated rollback artifact under the approved backup structure.
2. Copy the committed SSOT virtual host to the active nginx path.
3. Validate the entire nginx configuration before reload.
4. Reload nginx only after a successful validation.
5. Place a non-secret probe file below the configured Certbot webroot and verify that the public HTTP ACME URL returns its exact content; remove the probe only within the approved maintenance window.
6. Renew only the named `api.mychatbuddy.dev` certificate with the existing webroot profile.
7. Validate nginx again and reload it so the renewed certificate is served.
8. Verify the external certificate subject, issuer, validity dates, fingerprint, and strict HTTPS health response without disabling TLS verification.
9. Enable and start `certbot.timer`, then confirm its next trigger and run a renewal dry-run.
10. Record validation evidence in Control, commit it on the work branch, and push before R28-R4 resumes.

## Rollback

If nginx validation fails, do not reload. Restore the recorded live configuration from the dated rollback artifact and validate again.

If certificate renewal fails, keep the ACME route only if nginx remains valid and the public probe works; otherwise restore the prior nginx file. Do not delete or replace the existing certificate lineage. Do not use `curl -k`, disable certificate verification, expose SSH publicly, or change unrelated virtual hosts.

The pre-R28 recovery archive remains available at `/backups/snapshots/r28r4-20260826T064238Z/r28r4-prechange-root.tar.gz`, with SHA-256 `da37f86c262ef39c6569209b55fe7809b1f3ba9c0b30e1efbf7510cf8f0aa9`.

## Success criteria

- nginx validation succeeds before and after reload;
- the public ACME probe returns exact expected content over HTTP;
- a newly issued, currently valid certificate is presented for `api.mychatbuddy.dev`;
- strict HTTPS `/mommyramona/health` returns a successful response;
- `certbot.timer` is enabled and active;
- Certbot renewal dry-run succeeds;
- existing API, bot webhook, n8n, lighting, TU1NZ, and Trendwatch routes remain healthy.
