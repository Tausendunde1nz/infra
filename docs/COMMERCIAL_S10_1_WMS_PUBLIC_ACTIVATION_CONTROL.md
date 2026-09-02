# Commercial S10.1 – Want Me Seen public SFW activation

`Want Me Seen` is the operator-selected public brand. TU1NZ remains the
internal infrastructure authority. The public claim is **Exposed on purpose.
Always by choice.** The only active product surface in S10.1 is an SFW landing,
Telegram Early Access, opt-in nurture, privacy-safe referrals and aggregate
growth reporting.

## Preliminary brand screen

The exact names `Want Me Seen` and `WantMeSeen` were checked at the current
DPMA, EUIPO/TMview and WIPO entry points and on the open web, including obvious
Adult, dating and social products. No obvious knockout conflict was found.
This is preliminary technical screening only, not trademark clearance.
`operator_selected_brand=true`; `LEGAL_FINAL_REVIEW_REQUIRED=true` and
`ADULT_PUBLICATION_LEGAL_CLEARANCE=false` remain mandatory.

## Public and legal identity

- Canonical host: `wantmeseen.com`
- Redirect host after green validation: `wantmeseen.de`
- Contact: `contact@wantmeseen.com`
- Public operator reference: Want Me Seen, c/o Christian Jahnke,
  Gulisastraße 93, 56072 Koblenz
- ZERODOX: CORE + 18+, operator-selected creator-name-only variant

The current SFW launch may use this operator decision. It must never be
described as final legal clearance. Adult media remains blocked until a final
German imprint, youth-protection, AVS, privacy and provider review is complete.

## Runtime plan and rollback

The controller requires the exact canonical App commit/tree and the exact
Control commit/tree supplied at execution. It verifies clean repositories,
the running S7/S8/S9 baseline, credential metadata, path ownership and the
versioned file hashes before mutation. It then requires a verified backup,
installs migration 0028, WMS configuration and hardened health units, and first
starts the WMS listener on loopback only. Local acceptance runs as the
unprivileged `chatops` service identity. This local step does not reload the
S8/S9 WMS drop-ins and cannot publish links to an unresolved domain. Public
cutover is a separate backup-bound action after DNS and TLS validation. Nginx
is reloaded and a separate unprivileged public pre-growth gate must pass before
any S9 publication or nurture timer is armed. During the
complete two-hour observation, `wantmeseen.de` still points to the existing
`tu1nz.com/adult` recovery surface. Only exact green observation evidence may
activate the final `.de` redirect; the legacy TU1NZ surface remains available
as rollback rather than being destructively redirected in S10.1.

The read-only server preflight found the clean, canonical S9 application
baseline `d3ae2764cc1623bfcc32d2c3f15264ca74fb2e79` with tree
`c9fa052bceb1e7ec3b84a5254d399acde9ff0989`, and the clean Control baseline
`352b97c04b1841f17e21c246c1747fc3668bcfc1` with tree
`a75ec6cf2fceb2cd51625bd28387bdba3355ab65`. Both are verified ancestors of
their current canonical branches; the version gap is expected undeployed
history, not local drift.

Rollback stops the WMS listener and WMS health timer, restores the captured
configuration, units and nginx site, switches the application to the recorded
S7/S8/S9 source release and leaves database evidence intact. Database rollback
is never automatic because legal re-consent or queued WMS evidence may already
exist. Before persistent S9 publication or nurture timers are rearmed, a
dedicated unprivileged pre-arm gate runs the complete S9 application, legacy
web and Telegram channel health envelope while proving that all S9 timers are
still disabled and inactive. The controller then restores and verifies the
exact enabled/disabled and active/inactive state captured for every S9 timer;
it never re-arms a timer that was intentionally disabled before S10.1.

## Telegram state

The existing bot remains bound to ID `8622690874`. Its public display copy is
Want Me Seen; the current username remains `@tu1nz_adult_early_access_bot`
until the separate BotFather rename to `@WantMeSeenBot` is completed and both
S8 and S10 contracts are changed together. The public channel remains
`@tu1nz_adult_publishing` until the one-time rename to `@WantMeSeen`. The bot
needs only the Telegram right to post messages; it must not receive rights to
add admins, manage users, stories, video chats or channel identity.

## Hard boundary

No Adult content or media, real identity documents, real AVS, payment,
external Adult publishing, creator activation, Controlled Beta or production
is authorized by S10.1. X and Reddit remain disabled. Public analytics contain
only allowlisted aggregate events, sources and campaigns; no message bodies,
sexual preference profiles or visitor identifiers are stored.
