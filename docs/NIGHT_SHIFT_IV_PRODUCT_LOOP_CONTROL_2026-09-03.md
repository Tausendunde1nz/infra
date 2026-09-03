# Night Shift IV — product loop Control evidence

Date: 2026-09-03 (Europe/Berlin)
Scope: public SFW Early Access only

## Canonical result

Application PR #106 was reviewed on exact head
`36fa025e6ee4afa428eb2579395993ac55b9f1b9` after every required PR check
passed. It was integrated by merge commit
`f9747088a31ec6c671e82de24e293ebdec99f717`, tree
`7defedef032f6af38bbce0165eb6c2bdec327df7`. Post-merge CI run
`33809025595` passed the Python 3.10 and 3.13 jobs and both PostgreSQL 17.11
and 18.6 acceptance jobs.

The source adds the missing aggregate `TELEGRAM_CTA` stage, separates
landing-to-CTA from CTA-to-bot conversion, rejects unreviewed attribution
dimensions, and produces exactly one causal product recommendation. The
business priority order places infrastructure last unless a verified runtime
failure blocks the public SFW funnel.

The public experience source is English-first, mobile-first and built around
desire, attention and user control. It retains one repeated primary CTA and a
private SFW boundary. It adds no remote media, remote script, form, explicit
sexual material or legal-text change.

## APE classification

No APE runtime, autonomous task queue, task scheduler or retry backlog exists
in the reviewed Application or Control sources. Status is `APE_ABSENT`. The
new contract explicitly keeps autonomous task creation disabled and requires
product impact for P3/P4 work.

## Deployment and recovery

The source is not partially deployed. S10.2B remains
`WAITING_OPERATOR_SUDO_PREFLIGHT`; the non-interactive preflight stopped before
mutation. Its versioned controller is rebound to the new canonical Application
commit so a later approved privileged run cannot silently deploy the older
source. The verified Telegram recovery point and legacy public path remain
preserved.

The pre-Control-change Git bundle is
`/tmp/tu1nz-night-shift-iv-pre-product-control-732b1de.bundle`, SHA-256
`2690282bf26ad4213042f0038d9fe923beae818a6f1962551bcda0d4dc72e2c3`,
mode `0600`. The Application bundle and audit are recorded in the Application
repository.

## Boundary decision

`GO_SOURCE_NO_GO_PRIVILEGED_DEPLOYMENT`. Adult media, identity/AVS, payment,
external Adult publishing, creator activation, Controlled Beta, production,
new paid services and credential bypass remain closed.
