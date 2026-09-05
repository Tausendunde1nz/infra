# S10.2D deployment gap diagnosis — 2026-09-05

## Scope and safety state

The authorized backup-first S10.2D deployment stopped at the first target S8
health gate and executed the version-bound rollback. No target application,
migration 0029, Adult media, AVS, payment or publishing state remained active.
The source application was restored and its public services were returned to
green after the external BotFather group capability was restored to the source
contract value.

Verified deployment backup:

`/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260905T094523Z-pre-s10-2d-community`

Backup index digest:

`6e3b02205167a4c7c6b1a6cb4ff172fb9d078a1f99f4a00492ef17bba5d53054`

## Observed safe evidence

- Target diagnostic: `S8_TELEGRAM_COMMANDS_MISMATCH`.
- Source diagnostic after technical rollback: `S8_TELEGRAM_GROUPS_ENABLED`.
- Controller result: `S10_2D_COMMUNITY_CONTROL_RED HEALTH_GATE_START_RED`,
  followed by `S10_2D_COMMUNITY_CONTROL_RED DEPLOY_ROLLED_BACK`.
- Migration 0029 table state after rollback: absent.
- Application after recovery: source commit/tree, clean.
- Control after recovery: canonical Control commit/tree, clean.
- S7, S8 Landing, S8 Telegram, S10 WMS and nginx: active with zero restarts.

## Root cause

The target application adds the `/community` command. The original controller
installed the target contracts and units but did not transition the official
Bot API default/localized command profile before running the target S8 health
gate. The target therefore rejected the still-source command profile.

The source rollback contract intentionally requires BotFather group joining to
be disabled. That setting had already been enabled for the S10.2D operator
checkpoint and cannot be changed through the official Bot API. The prior
rollback restored files and the application but did not restore the bot profile
or explicitly park on this external capability mismatch.

## Reviewed correction

The existing controller is extended without a new deployment architecture:

1. Preflight verifies the target bot identity and enabled group capability
   before any quiesce or deployment mutation.
2. The existing versioned `tu1nz_public_s8.brand_migration` entrypoint configures
   and verifies the target default/localized profile before migration and start.
3. Rollback invokes the same entrypoint from the restored source application to
   restore the source profile before source service start.
4. If BotFather group joining is still enabled during rollback, S8 remains
   stopped and recovery reports
   `SOURCE_BOTFATHER_GROUPS_OPERATOR_REQUIRED`. The operator disables the flag
   and reruns the same exact-SHA/tree rollback.

## Retry gate

A new attempt requires a merged Control change with green CI, clean canonical
repositories, BotFather privacy enabled, BotFather group joining enabled for
the target, the existing Community provider verifier green, a fresh verified
backup and a new controller preflight green. No uncontrolled second attempt is
allowed.

## Second controlled attempt diagnosis

After the first correction had been merged and synchronized, a new exact-state
preflight passed. The controlled deployment then stopped at
`PUBLIC_COMMUNITY_CTA_RED` and executed the bound rollback. The technical
source state and database rollback completed; the public S8 Telegram and S10
services remained stopped fail-closed while source bot-profile recovery was
confirmed. The verified backup for this attempt is:

`/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260905T101905Z-pre-s10-2d-community`

Backup index digest:

`f4b1d0c72cdaf9b1855cb5f140aab08708a7d8ee2278d8085ea8ca1d09f812dd`

The target Application switch did not restart the separately deployed S8
Landing service, so the externally served process retained the source product
surface and the exact CTA verifier correctly rejected it. The controller now
quiesces and restarts S8 Landing in the same bounded service set as S8 Telegram
and S10 WMS, for both deployment and rollback.

The profile restore had already completed its writes before a provider rate
limit interrupted the final verification reads. Reissuing the full profile
write set would consume more provider quota without changing state. Source
recovery therefore verifies the current source profile first and only invokes
the existing configuration path when verification shows a real profile
mismatch. A group-capability mismatch remains an explicit operator gate.

No further deployment attempt is permitted until this correction is merged
with green CI, synchronized to the server, source recovery is fully green, a
fresh verified backup exists and a new exact-state preflight passes.

## Third controlled attempt diagnosis

The next exact-state preflight again passed. The controlled deployment stopped
before migration and service activation at `TARGET_BOT_PROFILE_CONFIGURE_RED`.
The target profile reconciliation was still issuing the complete setter set
even when most provider fields already matched, which exhausted the provider's
write limit. The Application correction at commit
`963d80f626a197b564201f92d5164090cf49d102`, tree
`03e25deaba0ec3c3250310f8a4c1bf1cadae87c5`, now reads every default and
localized profile field first and writes only actual drift. Its post-merge CI
`33962072767` is green with 989 unit tests.

The versioned source rollback restored the clean source application,
configuration and services. A health timer naturally fired immediately after
re-arming, so the final controller check observed a transient non-waiting timer
state and returned `TIMER_NOT_WAITING` despite the timer remaining active and
enabled. The controller now waits at most 90 seconds for that narrow transient
state to settle while still failing immediately if any timer is disabled or
inactive. Persistent lack of a waiting state or future run fails closed as
`TIMER_NOT_SETTLED`.

No target migration or runtime remained active. A new attempt still requires
this Control correction to be merged with green CI, synchronized exactly, the
source state formally verified, a fresh backup bound to the new Control
commit/tree, BotFather group joining enabled, and a fully green preflight.

## Fourth controlled attempt diagnosis

The preflight bound to Control `b13295d6a1f64c5261bd73411efa650b822e3e53`
and backup
`/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260905T110800Z-pre-s10-2d-community`
passed. The target profile transition completed with only the three drifted
command scopes written. Target migration and services started, but the final
public Community assertion stopped at `PUBLIC_COMMUNITY_CTA_RED`.

The asserted literal provider display name is not part of the reviewed WMS
page contract. The public surface exposes the Community through the reviewed
`/go/community` route. The controller now verifies the route as an exact HTTP
302 to `https://t.me/WantMeSeenCommunity`, which tests the deployed public
contract without depending on presentation copy.

Technical rollback restored the clean source application, configuration and
removed migration 0029. Source profile inspection found exactly three command
scopes still on the target profile. The source commit's historical configure
path attempts every profile setter and therefore cannot safely reconcile those
three fields inside the provider limit. Source recovery now invokes the
idempotent profile reconciler from the exact `TARGET_SHA` archive against the
restored source contracts. It writes only actual drift, performs the same
strict final verification and deletes its bounded temporary archive.

This is a recovery correction, not authorization for another deployment. It
must be merged with green CI and synchronized before the existing versioned
rollback may resume. A new deployment remains prohibited unless source
recovery is fully green, a new backup is created and a new preflight passes.

## Source-schema recovery follow-up

The archived target reconciler could not load the historical source S8
contract because the target schema requires the new Community fields. It
failed closed before changing the three remaining command scopes. A read-only
field comparison confirmed that default, German and English commands are the
only drift: identity, group capability, names, descriptions, short
descriptions and menu already match the source contract.

The recovery is therefore narrowed further. While the exact `SOURCE_SHA` is
checked out, the controller uses its own reviewed contract and Bot API adapter
to read the default, German and English command scopes and writes only scopes
that differ. No name, description, short-description or menu setter is
reachable from this function. The complete historical source profile verifier
still runs after reconciliation, including identity, webhook and disabled
group capability checks.

This follow-up remains recovery-only. It requires merged green Control CI and
a new backup bound to that Control commit before the same rollback may resume.
