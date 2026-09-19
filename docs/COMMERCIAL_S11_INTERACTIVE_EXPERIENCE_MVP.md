# Commercial S11 Interactive Exposure Experience MVP

## Product contract

S11 changes the public SFW Telegram path from a waitlist-first utility into a
private, curated exposure experience. The product loop is `DARE -> DECISION ->
COMPLETION OR SKIP -> NEXT DARE`. It remains automated, SFW, voluntary and
text-only. It never claims unmeasured viewers, reactions or community activity.
It performs no external action for the user and collects no proof media or
challenge-response text.

The entry path is landing CTA, Telegram start, compact 18+ self-attestation,
mode choice, first dare, three-dare session, summary and then another round or
the existing Full WMS Early Access flow. Existing waitlist data and the
acquisition baseline `2026-09-18T00:41:06.710027Z` remain untouched.

## Experience state machine

The durable states are `AGE_PENDING`, `AGE_REJECTED`, `READY`, `DARE_ACTIVE`,
`DARE_ACCEPTED`, `SESSION_COMPLETE`, `RETURNING` and `STOPPED`. Mode and
challenge position are separate fields. Waitlist state stays in the existing
S8 model and is not folded into the experience state.

An explicit under-18 response terminates the experience at `AGE_REJECTED`.
Accepting a dare does not count it as completed; only `DONE` does. `STOP FOR
NOW` persists a resumable state. A returning adult can continue or start fresh
without repeating onboarding. Every mutation is revision-monotonic and replay
safe.

## Challenge library contract

The immutable catalog version is `s11-curated-sfw-challenges-v1`; the state
machine version is `s11-experience-state-v1`. The catalog contains exactly 36
curated bilingual challenges: 12 each for PLAYFUL, BOLD and DARING. Every
challenge carries an id, mode, category, localized copy, completion prompt,
external-action flag, risk class, repeat policy, active flag, version and next
bias. Selection uses bounded recent history and never invokes a generative
model or external API.

PLAYFUL is low-friction, BOLD increases deliberate presence, and DARING is the
highest SFW level. Safer moves downward; bolder moves upward only within these
three modes. A bolder request at DARING states that it is already the boldest
SFW level. No challenge requires nudity, sex, danger, illegality, spending,
third-party exposure, platform-rule circumvention or irreversible action.

## User autonomy and safety

Each active dare offers accept, another, safer and stop; bolder is offered only
where SFW. Accepted dares offer done, changed my mind and a different dare.
There is no coercion, shame, proof upload, observation claim or automatic
posting. The 18+ gate is self-attestation only and never represents AVS.

The following runtime capabilities stay false and database-constrained:

- community user-content publishing
- adult media and community adult media
- real AVS
- payment
- external publishing
- controlled beta
- production

## Sessions, progression and return

A session contains three challenges. Completion and skip counts are explicit;
there is no fake score or ranking. The summary can lead to another session,
come back later, or the existing Early Access writer. `My Status` reports only
real session/challenge totals, last mode and Early Access state. Immediate
repeats are prevented by a bounded 24-item history. Reminder scheduling is
deferred because no new scheduler architecture is authorized.

## Analytics and KPIs

Append-only S11 events are:

`EXPERIENCE_STARTED`, `AGE_SELF_ATTESTED`, `MODE_SELECTED`, `DARE_PRESENTED`,
`DARE_ACCEPTED`, `DARE_COMPLETED`, `DARE_SKIPPED`, `SAFER_REQUESTED`,
`BOLDER_REQUESTED`, `SESSION_COMPLETED`, `NEXT_SESSION_STARTED`,
`EARLY_ACCESS_CTA`, `EARLY_ACCESS_JOINED`, and `COMMUNITY_CTA`.

Every event is classified as `REAL_ACQUISITION`, `SYNTHETIC` or
`INTERNAL_TEST`. Synthetic and internal events are excluded from real-product
KPIs. No message body, challenge answer, IP, email, media, token or DSN belongs
in product evidence. Reports can aggregate the landing-to-bot, bot-to-
experience, experience-to-first-dare, presented-to-accepted,
accepted-to-completed, experience-to-session, session-to-Early-Access,
Early-Access-to-waitlist, seven-day second-session and thirty-day second-
exposure stages. Rates must not be described as unique-user rates unless the
denominator supports that claim.

## Feature flag and migration

Migration `0031_commercial_s11_interactive_experience.sql` is additive and
installs the feature disabled with no live-start timestamp. The deploy sequence
is code OFF, migration, health, pure synthetic journeys A-H, atomic versioned
enable, health and product validation. Enabling records
`S11_EXPERIENCE_LIVE_START` while keeping the acquisition state active and its
baseline unchanged.

The down migration is test coverage for an unused disabled schema only. A live
rollback does not destroy S11 evidence; it first disables the flag and restores
the prior bot code/unit/config so the S10.2F Early Access path remains usable.

## Deployment, backup and rollback

Only Application `65707b079183151cfe7ea508f9270c31389f2334` with tree
`79d60a5b8d791f65c0de06d0ae7861fb0d032ed4` and a Control commit bound by the
annotated tag `s11-interactive-experience-mvp-freeze-r6` may deploy. The r6
freeze contains the timer, backup-mode, database-admin and in-flight poller
gate corrections and uses the established
local PostgreSQL administrator only for hash-bound migration and feature-flag
updates. Runtime reads and services retain the least-privilege runtime DSN.
Both release commits must
be on their canonical remote branches, clean, and backed by green post-merge
CI before runtime work.

The root-only predeploy backup contains verified repository bundles, exact
source commits and trees, systemd and health artifacts, aggregate database
schema/count evidence, exact landing aggregate bytes, acquisition state and
baseline, absent markers for new files, owner/mode inventory and SHA-256.
Secrets and identifiers are excluded. The controller automatically rolls back
on an unsuccessful deployment.

Runtime validation covers public website, health, privacy, terms, imprint and
the `.de` redirect; S7, S8 Landing, S8 Telegram, S10 WMS and nginx with zero
restarts; active enabled S9/S10 timers with future realtime or monotonic runs;
the single S8 poller,
valid lease, successful polls and either a completed green event path or the
strictly bounded `BOT_UPDATE_NOT_RECEIVED` state of the current in-flight
long-poll; publication rotation;
growth health; S11 catalog/state health; all product boundaries; exact
acquisition state and baseline. Human Telegram acceptance is allowed to remain
`DEFERRED`; the release-bound synthetic A-H journey is the technical product
gate.

Deployment preflight also evaluates the existing Community 24-hour latency SLO
with the same five-sample minimum and p50/p95/p99 thresholds as runtime health.
Existing red measurements are retained and block deployment before backup or
mutation; they are never deleted, reset, relabelled or hidden by S11.

## Initial product reporting

The first report records counts by event and evidence class, never raw subjects
or content. Small-volume observations are diagnostic rather than hard business
gates. The initial priority after a green rollout is genuine use of the
experience: starts, dare completions, completed sessions, Early Access joins
and second sessions. Paid ads, new external platforms, mass outreach and other
growth expansion are outside S11.

## Final report contract

The closeout reports all 56 requested items in order: source SHAs/trees,
backups, product problem/model/state/entry/age/modes/catalog/safety/controls,
progression/session/return/Early Access/status/community/landing, analytics and
reporting, retention, migration/tests/scans/CI/reviews, final SHAs/trees,
freeze, runtime backup/deployment/flag/synthetic journey, runtime services,
acquisition and live start, acceptance and closed gates, initial safe aggregate
counts, bottleneck, next priority, and the full GO/NO-GO matrix.
