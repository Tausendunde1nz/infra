# Commercial S10.2D — Community, instant bot experience and pre-acquisition control

Status: `S10_2D_R1_AUTHORIZED_PENDING_FRESH_BACKUP`

## Authorized outcome

S10.2D connects the existing public SFW product surfaces before real
acquisition: `wantmeseen.com`, `@WantMeSeen`, `@wantmeseenbot` and the new
`@WantMeSeenCommunity` supergroup. It does not open Adult media, real AVS,
payment, external publishing, creator access, Controlled Beta or production.

The application release is merge commit
`58425156e8e16d05a2cf6bfc6d3c31b72a5a0bd3`, tree
`2ac46feed56578740101b559d37219c8ba31e9b1`, with post-merge CI run
`33953570191` green on Python 3.10/3.13 and PostgreSQL 17/18. The prior public
runtime is application `f9747088a31ec6c671e82de24e293ebdec99f717`, tree
`7defedef032f6af38bbce0165eb6c2bdec327df7`.

## Risk, backup and rollback

The main risks are a wrong Telegram destination, excess Community bot rights,
an incomplete database migration, an in-flight publication lease or a runtime
that accepts updates before its health envelope is complete. Deployment is
therefore fail-closed and exact-SHA/tree-bound.

Before mutation, `tu1nz_adult_public_s10_1_backup.sh` creates a new verified
backup under the existing protected backup root with suffix
`-pre-s10-2d-community`. It contains clean application/control bundles, a full
PostgreSQL dump and schema/grant/aggregate evidence, public and S10
configuration, affected systemd units, both installed health executables and
unit/timer state. It contains no token value.

Automatic rollback stops S8/S10 and growth/health workers, restores the exact
prior application, configurations, units and health executables, then verifies
the prior public services and timers. Migration 0029 is reversed only when the
new Community tables contain no user, event, moderation or latency data and the
readiness gate is still pending. Otherwise its additive tables remain dormant
and preserved; no automatic database restore or user-data deletion occurs.
The reviewed queue rotation is transactional and refuses any `PUBLISHING`
lease. Published and failed evidence is never rewritten.

The Telegram bot profile is part of the reversible release surface. Deployment
configures and verifies the target default and localized command menus before
the target runtime starts. Rollback restores the source profile before the
source runtime starts. BotFather's group-join capability has no official Bot API
write method: if a rollback occurs after the operator enabled it, recovery stops
the S8 poller fail-closed with `SOURCE_BOTFATHER_GROUPS_OPERATOR_REQUIRED`. The
operator must disable group joining and rerun the same version-bound rollback;
the controller never claims a green source runtime while that external setting
still contradicts the source contract.

## 2026-09-05 fail-closed deployment diagnosis

The first S10.2D deployment attempt stopped before readiness and used the
versioned rollback. The target S8 health gate reported
`S8_TELEGRAM_COMMANDS_MISMATCH` because the target adds `/community`, while the
controller had not transitioned the Bot API command profile before starting the
new runtime. After rollback, the source diagnostic correctly reported
`S8_TELEGRAM_GROUPS_ENABLED`, because the operator checkpoint had already
enabled group joining for S10.2D. No migration 0029 state or target runtime was
left active. The corrected controller adds a read-only target capability gate,
a target profile transition before migration/start, and a symmetric source
profile restore with explicit operator parking for the non-API BotFather flag.

## Single bundled operator checkpoint

One checkpoint may contain all unavoidable human/cloud actions:

1. Re-authenticate the existing Tailscale session if the server requests it.
2. In BotFather, set `@wantmeseenbot` group membership to enabled and keep bot
   privacy mode enabled.
3. Create the supergroup `Want Me Seen Community` with public username
   `@WantMeSeenCommunity`.
4. Set the reviewed description and text-only default permissions, post and pin
   the reviewed rules, then add `@wantmeseenbot` as administrator.
5. Grant exactly delete-messages and restrict/ban-members. Change-info, pin,
   promote-admin, anonymous, video-chat and topic-management rights remain off.
6. Enter the server password only in the one visible masked terminal if sudo is
   required. No credential is sent through chat, Git, logs or evidence.

The Bot API preflight then verifies the exact supergroup type, title, username,
description, pinned rule text, default permissions, bot identity and
least-privilege rights. Deployment cannot begin if any field differs.

## Version-bound deployment sequence

`scripts/tu1nz_adult_public_s10_2d_control.sh` accepts only the exact clean
Control commit/tree supplied after merge and the newly verified backup path.
Its sequence is:

1. Verify the unchanged source application/configuration/control surface,
   active services with zero restarts, future S9/S10 timer runs, public WMS and
   German redirect, closed Adult runtimes, token metadata, enabled target bot
   group capability and canonical target.
2. Verify the Community through the official Telegram Bot API and verify the
   backup provenance.
3. Stop only S8/S10 plus affected S9/S10 workers and timers.
4. Switch to the reviewed application target and install exact-hash S8/S10,
   Community, copy and business-loop contracts.
5. Install the reviewed service/health bindings; configure and verify the exact
   target default/localized bot profile; apply hash-bound migration 0029 and
   confirm its pending pre-acquisition gate.
6. Start S8/S10, resume the existing timers and execute S8/S9/S10 health gates.
7. Rotate only unpublished SFW queue entries once through the reviewed
   transaction, then repeat all provider/system/public health gates.
8. Verify the original user/update/analytics count floors did not regress.

## Observation and readiness

Deployment returns `PENDING_OBSERVATION`. The read-only `observe` action checks
the exact release, Community/provider state, services, future timer runs, public
endpoints, pending moderation, expired restrictions and aggregate latency
sample count without emitting messages, media, user IDs or content.

`mark-ready` is a separate mutation and refuses to run until all conditions are
true:

- at least 1,800 seconds elapsed since migration 0029 closed the prior baseline
  with `PRODUCT_SURFACE_CHANGED_BEFORE_ACTIVE_ACQUISITION`;
- at least five normal response samples exist after that boundary;
- response p50 is below 1,000 ms, p95 below 2,000 ms and p99 below 5,000 ms;
- no pending moderation enforcement or expired restriction exists;
- exact provider identity/permissions, services, timers, public WMS, product
  boundaries and both canonical repositories are green.

Only then are `PRE_ACQUISITION_READINESS=GREEN`,
`WMS_REAL_ACQUISITION_READY=true` and the new acquisition-baseline start stored.
No acquisition campaign is launched by this step.

## Product behavior and privacy boundary

The group is 18+ SFW Community access. Its self-attestation is explicitly not
AVS. New members accept the pinned rules before normal posting. Ordinary
violations use one-hour, 24-hour and ban escalation; severe consent, minor-risk,
doxxing, threat or illegal-content reasons ban immediately. One normal strike
decays after 90 days. Evidence stores reason codes and bounded timestamps, not
message bodies or media. Enforcement and its retryable outbox state are atomic.

Group media permissions are disabled. Future media/AVS/consent/moderation,
final-confirmation, withdrawal and takedown flows remain synthetic-test-only.
The official Bot API is the only runtime transport. Because bots cannot start a
private chat and Telegram exposes no per-subscriber channel-join event suitable
for personal welcome, the channel uses its pinned/description/navigation
surfaces while the supergroup provides the immediate rules flow.

## Completion report contract

The final report contains exactly 41 numbered points covering authorization,
source/target commits and trees, both CI states, backup path/digest, pre/post
counts, migration, source baseline closure, identities, group type, BotFather
settings, exact rights, permissions, rules/welcome, moderation, retention,
navigation across all four surfaces, queue rotation, latency sample and
percentile evidence, observation duration, services, timers, nginx, endpoints,
repository cleanliness, readiness flags, business-loop priority, every product
boundary, operator action and final GO/NO-GO. A concise GO/NO-GO matrix follows.

## 2026-09-05 recovery completion

The recovery-only Control change was merged as
`1249a359bc56f7d270dbf4055c66ceaaed222c81`, tree
`1ca95ffbfd364b39af6e9b8f1f5f6f4766e9b803`, with post-merge CI
`33963379729` green. The exact backup is
`/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260905T113100Z-pre-s10-2d-community`;
its checksum-index digest is
`5d92af1f712f20b12e4986989e404ac9461744075e842d0e8e472b0c5e53893b`.

The version-bound rollback restored Application
`f9747088a31ec6c671e82de24e293ebdec99f717`, tree
`7defedef032f6af38bbce0165eb6c2bdec327df7`. Only the three drifted Bot API
command scopes required reconciliation. The complete source profile then
verified green with BotFather group joining disabled. Migration 0029 is absent.
S7, S8 Landing, S8 Telegram, S10 WMS and nginx are active with zero restarts;
all S9/S10 timers are enabled, active, waiting and have future runs.

An S10 health invocation overlapped the controlled restart and failed with the
safe endpoint code. The next natural timer invocation at
`2026-09-05T11:37:12Z` completed successfully, proving the recovered public,
growth and health surface. No target retry occurred. S10.2D activation,
observation, readiness and real acquisition remain NO-GO until a separately
authorized retry starts from a fresh backup and green preflight.

## S10.2D-R1 authorization and provider precheck

The owner separately authorized the S10.2D-R1 retry after confirming the
written plan, risk, fresh-backup and rollback controls. The recovered source
runtime remains green. BotFather group joining for `@wantmeseenbot` was enabled
through the single operator checkpoint and independently verified through the
official Bot API. Privacy mode remains enabled. The existing
`@WantMeSeenCommunity` provider configuration passed the reviewed read-only
identity, rules, permissions and least-privilege administrator verifier.

This SSOT transition authorizes exactly one backup-first R1 cutover using the
already reviewed Application target. It authorizes no new architecture, second
automatic cutover, Adult media, real AVS, payment, external Adult publishing,
Controlled Beta or production. Deployment remains pending until this Control
change is merged with green CI, synchronized exactly and a new verified backup
is bound to the resulting Control commit and tree.
