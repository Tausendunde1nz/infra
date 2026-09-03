# Commercial S10.2B — Public Telegram brand migration

## Decision and boundary

S10.2B is an authorized, reversible public SFW identity migration. The existing
Telegram channel is retained under `@WantMeSeen`; its ID, subscribers and
history are not recreated. The active private bot changes to
`@wantmeseenbot` (bot ID `8861935205`). PostgreSQL remains the single waitlist
source of truth. Referral attribution, aggregate analytics, nurture automation,
services, timers and internal TU1NZ component names remain in place.

The versioned cutover state is `GO_CUTOVER_WAITING_CHANNEL_ADMIN`. Application
commit `4a6c42f389cbf6caca738c48ae32ebe1856dd674` and tree
`f66b70452ab423c232bd529936f8e07950c138ad` passed post-merge CI run
`33803097418`. The new token was installed through the interactive secret
installer, without appearing in Git, chat, logs or evidence. The only remaining
cloud prerequisite is the minimal Telegram channel-admin assignment.

Adult media, identity documents, real AVS, payments, external Adult publishing,
creator activation, Controlled Beta, production and mass direct messages remain
closed.

## Verified backup and secret handling

The pre-cutover backup is:

`/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260903T202834Z-pre-s10-2b-public-telegram`

Its index SHA-256 is
`c398bd8e084b56f93a9f16ae71c0bc46139193fd0dcdafed7b7c7ae28d7f81bc`.
It contains verified application/control Git bundles, a database dump,
aggregate evidence, public configuration, systemd units and unit state. It does
not contain token values.

The active candidate secret is a regular root-owned `0600` file at
`/etc/tu1nz/adult-commercial-s10-2b-telegram.token`. The legacy secret remains
untouched at `/etc/tu1nz/adult-commercial-s8-telegram.token` for rollback only.

## Human cloud checkpoint

Before deployment, both `@wantmeseenbot` and the legacy
`@tu1nz_adult_early_access_bot` must be administrators of the existing
`@WantMeSeen` channel with exactly the posting capability required by the
automation:

- post messages;
- edit messages;
- change channel information, so the versioned description and CTA can be
  applied or rolled back;
- no right to add administrators;
- no subscriber, story, video-chat, direct-message or delete rights;
- no ownership transfer.

Keeping the legacy bot as a restricted administrator is a rollback requirement,
not a second active runtime. The controller verifies both assignments through
the official Telegram Bot API before stopping any service.

## Version-bound cutover

`scripts/tu1nz_adult_public_s10_2b_control.sh` accepts only a clean, exact
post-merge Control commit/tree plus the verified backup path. Its fixed sequence
is:

1. Verify the server application source commit/tree, Control commit/tree,
   credential metadata, public health, zero restarts, future timer runs and
   closed product gates.
2. Verify the exact backup and canonical application target/CI binding.
3. Verify both current and fallback bots have minimal channel posting/editing
   rights before any quiesce.
4. Capture aggregate database floors, stop only the affected public services,
   health workers and recurring timers, then install the reviewed application,
   configuration and unit bindings.
5. Configure and verify the new bot's DE/EN name, descriptions, commands and
   command menu through the official Bot API.
6. Configure and verify the existing channel title, description and private-bot
   CTA through the official Bot API.
7. Start S7, S8 landing, S10 WMS and S8 Telegram, resume the existing timers,
   then execute S8/S9/S10 health gates.
8. Verify `https://wantmeseen.com/go/telegram` resolves only to
   `https://t.me/wantmeseenbot`, confirm database counts did not regress and
   emit only privacy-safe evidence.

The cutover applies no schema migration and does not create a channel, waitlist
or referral store.

## Tests and evidence

Pre-cutover coverage includes canonical identity, DE/EN profile configuration,
commands, start, intro, boundary display, waitlist, duplicate join, status,
opt-in, opt-out, referral, invalid referral, replay protection, media hard
block, Adult-route hard block, analytics allowlists, service/timer health,
rollback and secret-leak scanning. Live evidence contains only safe codes,
booleans, counts, hashes, commits, trees and unit states—never tokens, Telegram
messages, media or personal identifiers.

## Rollback

Rollback keeps the renamed channel, subscribers and history. While the reviewed
target code is still present, the legacy bot restores the channel CTA to the
legacy private bot. The controller then restores the previous application,
configuration and systemd units from the verified backup, resumes the same
services/timers and verifies the unchanged PostgreSQL waitlist without a
database restore. The legacy bot is `FALLBACK_ONLY`; it must never poll at the
same time as the new bot.
