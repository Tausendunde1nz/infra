# Commercial S10.2B — Public Telegram brand migration

## Decision and boundary

S10.2B is authorized as a reversible public SFW identity migration. It changes
only the public Telegram channel and bot identity to **Want Me Seen**. The
PostgreSQL waitlist, referral attribution, analytics, nurture engine, services,
timers and internal TU1NZ component names remain in place. Adult media,
identity documents, real AVS, payments, external Adult publishing, creator
activation, Controlled Beta and production remain closed.

The initial prepared state is `GO_PREPARE_WAITING_BOTFATHER`. No public cutover
may occur until the new canonical `@wantmeseenbot` identity is bound to an exact bot ID,
the token has been installed through the interactive secret installer, and the
application and control changes have passed review and CI.

## Known baseline note

The application repository on the server is
`/opt/tu1nz_repos/adult-publishing-core`; `/opt/tu1nz_repos/application` is not
the application path. The failed state of
`tu1nz-adult-public-s10-rollback-prearm-health.service` is a historical one-shot
result from 2026-09-02 18:12:19 UTC. It is not a current runtime dependency.
S7, S8 landing, S8 Telegram, S10 WMS and nginx are active with zero restarts,
and all S9/S10 recurring timers have future runs.

## Secret installation

The new token is accepted only through
`scripts/tu1nz_adult_public_s10_2b_secret_install.sh` running as root in one
interactive TTY. Input echo is disabled. The token is never accepted as a
command argument and is never printed. Before installation the script verifies
through the official Telegram Bot API that the bot username is case-insensitively
equal to the Telegram-canonical `wantmeseenbot`, is displayed as `Want Me Seen`,
and cannot join groups. The
installed secret is a regular root-owned `0600` file outside Git at
`/etc/tu1nz/adult-commercial-s10-2b-telegram.token`.

## Backup-first cutover

Before any service or public identity change, create and verify one S10/S8
backup containing Git bundles, database dump and aggregate evidence,
configuration, systemd units and service/timer state. Secret contents are not
copied into the evidence backup. The existing S8 token remains untouched until
the final cutover and is preserved as the old-bot fallback credential.

The cutover sequence is fixed:

1. Verify canonical Git heads/trees, green CI, clean server repositories,
   public health, timer liveness, zero restarts and all closed product gates.
2. Create and verify the backup.
3. Configure and verify the new bot through the official Bot API, including
   DE/EN profile text, commands and command menu.
4. Add the new bot to the existing channel with only post/edit rights required
   for the content engine. Channel ownership and history remain unchanged.
5. Reserve `@WantMeSeen` through the existing authorized Telegram session if
   available; otherwise stop for the approved handle decision.
6. Quiesce only S9/S10 growth timers and workers, S8 Telegram and S10 WMS.
7. Install the exact reviewed application/configuration and bind the active
   runtime credential to the new token without exposing either token.
8. Configure and verify channel title, description and final CTA through the
   official Bot API.
9. Start S10 WMS and S8 Telegram, resume the existing timers and run S8, S9 and
   S10 health gates.
10. Verify website, channel and referral deep links use `wantmeseenbot`, run the
    harmless SFW smoke and observe health before marking the old bot
    `FALLBACK_ONLY`.

## Test and evidence plan

Required pre-cutover coverage includes identity, commands, DE/EN language,
start, intro, boundary display, waitlist, duplicate join, status, opt-in,
opt-out, referral, invalid referral, replay, media hard block, Adult-route hard
block, analytics allowlists, health and secret-leak scanning. The live smoke
uses only harmless SFW operator test data. Evidence contains only booleans,
counts, safe codes, hashes, commits, trees and unit states—never Telegram
tokens, chat messages, media or personal identifiers.

## Rollback

Rollback keeps the existing channel, subscribers and history. It restores the
previous bot credential and bot contract, points website/channel/content CTAs
back to the old bot, restarts the same services and timers, and verifies the
same PostgreSQL waitlist without a database restore. The renamed channel may
remain `@WantMeSeen`; the old bot can continue to post there. A database
rollback is out of scope unless a separate destructive decision is made.
