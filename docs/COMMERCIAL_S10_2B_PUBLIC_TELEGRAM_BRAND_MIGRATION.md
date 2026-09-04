# Commercial S10.2B — Public Telegram brand migration

## Decision and boundary

S10.2B is an authorized, reversible public SFW identity migration. The existing
Telegram channel is retained under `@WantMeSeen`; its ID, subscribers and
history are not recreated. The active private bot changes to
`@wantmeseenbot` (bot ID `8861935205`). PostgreSQL remains the single waitlist
source of truth. Referral attribution, aggregate analytics, nurture automation,
services, timers and internal TU1NZ component names remain in place.

The versioned cutover state is `GO_CUTOVER_RECOVERY_PREFLIGHT`. Application
commit `f9747088a31ec6c671e82de24e293ebdec99f717` and tree
`7defedef032f6af38bbce0165eb6c2bdec327df7` passed post-merge CI run
`33809025595`. The new token was installed through the interactive secret
installer, without appearing in Git, chat, logs or evidence. Both bots are
present as restricted channel administrators. Exact rights are still verified
through the official Bot API by every cutover preflight.

Adult media, identity documents, real AVS, payments, external Adult publishing,
creator activation, Controlled Beta, production and mass direct messages remain
closed.

## Verified backup and secret handling

The current pre-cutover backup is:

`/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260904T110654Z-pre-s10-2b-public-telegram`

Its index SHA-256 is
`e096fd678a021ac9aae5d6a6c68c62187afe42743ca85bb5ee982b3190f8252f`.
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

Telegram's Bot API documents a channel-only backward-compatibility default for
`can_restrict_members`: channel administrator promotions may report this field
as `true` even though the Telegram Desktop broadcast-channel UI exposes no
independent switch. The controller therefore first proves that the target chat
type is exactly `channel`, requires this compatibility field to be a boolean,
and continues to reject every exposed subscriber-invite, deletion, story,
video-chat, direct-message and administrator-promotion right. This exception is
not accepted for a group or supergroup and does not authorize member-management
automation.

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

## Night Shift IV recovery binding

The first live preflight correctly stopped before mutation, but its source
assumptions were newer than the intentionally preserved runtime baseline.
`docs/COMMERCIAL_S10_2B_RECOVERY_2026-09-03.diagnose` records the exact
classification and evidence.

The original S7 contract with SHA-256
`f4e2b473905f6c82afe2ad6473989604e47f26eff70356db74da6fd49af50214`
is the protected fallback state. S10.2B verifies and preserves it; the cutover
does not install the newer transport-bound S7 source file.

The S8 recurring health timer is intentionally retired. S9 channel activation
disabled it when S9 assumed recurring growth health, and S10.1 added the WMS
health envelope. S10.2B requires the reviewed S8 timer unit to remain installed
but disabled/inactive, executes the S8 health service only as a one-shot gate,
and resumes only the active S9/S10 timers. This avoids duplicate monitoring.

Observation is risk-based. A Telegram transport cutover receives stricter
smoke and health observation than copy/CSS changes, but a new fixed two-hour
window is not mandatory when state continuity, rollback, service health and
transport checks remain green.

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
