# Commercial S10.2F — conversion recovery

## Decision

S10.2F is classified as `MULTIPLE_CAUSES`:

- primary: `MEASUREMENT_BUG` and `LOW_QUALITY_TRAFFIC`;
- secondary: `UX_FRICTION`;
- no routing, bot-event, community-event or waitlist-writer defect was found.

The immutable real-acquisition baseline remains
`2026-09-18T00:41:06.710027Z`. Historical counters are evidence and are never
rewritten. Activation creates a separate `S10_2F_CHANGESET_START` state file.

The pre-change snapshot at `2026-09-19 09:05 Europe/Berlin` was 19,435
landing requests, 664 Telegram CTA requests, 31 community CTA requests, 19
bot starts, 9 waitlist joins, and no referral bot start or community event.
These are event counters, not deduplicated people.

## Evidence

The WMS runtime previously counted every `GET /` as `LANDING_VIEW`, including
the local and public root requests made by every S10 health cycle. It also
counted every redirect `GET` as a CTA without classifying preview, prefetch,
crawler or automation requests. `HEAD` was already excluded.

The shared nginx log has no host field and local health requests bypass nginx,
so its aggregate classes are diagnostic samples, not a unique-user or
WMS-only denominator. The compatible-path sample contained normal-browser,
bot, automation and large unknown classes. This is sufficient to reject the
historic landing delta as evidence of 1,625 human visits, but insufficient to
publish a historical human share.

The privacy-safe compatible-path sample classified landing responses as 164
human-like, 6 bot/crawler, 3 known automation and 763 unknown requests. It
also contained 736 health-endpoint requests. Telegram redirect requests were
1 human-like and 1 bot/crawler; community redirect requests were 2
human-like and 13 unknown. The sample is request evidence only: it contains
no identifiers and cannot establish unique people or an exact WMS traffic
share.

The technical downstream paths are green:

- bot target: `https://t.me/wantmeseenbot?start=landing_s10_wms_launch`;
- community target: `https://t.me/WantMeSeenCommunity`;
- `/start` reaches the release-bound single poller and writes `BOT_START` to
  `commercial_s8_analytics_events`;
- duplicate update receipts are idempotent;
- the waitlist path is bot intro → join → explicit consent →
  `WAITLIST_JOINED` in the same analytics source read by reporting;
- Telegram `chat_member` updates drive `NEW` → `RULES_PENDING`; the callback
  drives `ACTIVE`, and all community events use the community aggregate table.

No production user or manual Telegram acceptance event was generated.

## Product funnel

| Transition | User action | Technical target | Event / next state | Known friction |
| --- | --- | --- | --- | --- |
| Landing → bot | Select the primary Want Me Seen CTA | `/go/telegram` → direct `t.me` deep link | `TELEGRAM_CTA`; Telegram bot page | Telegram still requires an explicit Start tap |
| Bot page → intro | Tap Start | release-bound S8 poller and `/start` handler | exactly one `BOT_START`; language/intro | app hand-off and Start are two distinct actions |
| Intro → Full WMS Early Access | Open Early Access, then explicitly consent | existing bot waitlist writer | `WAITLIST_JOINED` | consent is intentionally explicit |
| Landing → community | Select the secondary community CTA | `/go/community` → public community | `COMMUNITY_CTA`; Telegram community page | join is separate from the website redirect |
| Community page → active member | Join, then accept pinned 18+ SFW rules | membership update + callback state machine | `NEW` → `RULES_PENDING` → `ACTIVE` | rules acknowledgement is intentionally explicit |

The primary conversion goal remains landing → bot → Start → Full WMS Early
Access. Community remains the secondary engagement route.

## Intervention

Application merge `1d0dbb88603be49ea172178b77d86451036035a1`
(tree `49f82e23ba16f06ddc27ef13e0b3f3643bc9da3e`) introduces:

1. six privacy-safe aggregate request classes:
   `HUMAN_LIKE`, `KNOWN_AUTOMATION`, `KNOWN_HEALTH`, `BOT_OR_CRAWLER`,
   `PREFETCH_OR_PREVIEW`, and `UNKNOWN`;
2. a separate sidecar aggregate containing only day, route, class and count;
3. real `LANDING_VIEW`, `TELEGRAM_CTA` and `COMMUNITY_CTA` increments only for
   human-like browser navigation;
4. explicit CTA copy: Telegram opens, the user must tap Start, and no upload
   is required.

The community CTA stays visually secondary. The direct bot deep link and
first-touch source/campaign contract are unchanged.

The privileged controller runs every repository Git operation as `chatops`.
Its installable Control artifact is independently pinned to reviewed commit
`1d5e0d84451d35cb4148d0b52209002048db7e88`, tree
`3e6ab73b929cd19a796cc8528cce06809e801d4c`, and annotated artifact tag
`s10-2f-control-artifacts-r1`. Runtime files are read from that pinned object,
while the canonical Control checkout stays on the final merged commit so the
corrected verify/rollback controller remains available. The post-merge
evidence freeze is the separate `s10-2f-conversion-recovery-freeze-r1` tag.

## Measurement contract

`HUMAN_LIKE_BROWSER_NAVIGATION_V1` applies only at and after the exact
deployment timestamp in
`/var/lib/tu1nz-adult-public-s9/s10-2f-changeset.json`. The state file also
binds the original acquisition baseline and is validated by the existing S10
health path. Traffic quality is stored separately in
`wms-traffic-quality.json`; no address, cookie, message, Telegram identifier,
fingerprint or sensitive preference is recorded.

Synthetic code-path tests use in-memory fixtures and do not touch real KPI
stores. Post-deployment health requests are visible only as `KNOWN_HEALTH` in
the sidecar and never enter real acquisition counters.

Expected impact: health, crawler, preview, prefetch and other non-human-like
requests stop inflating the acquisition funnel; real downstream events keep
their existing writers and reporting sources. Product progress is therefore
evaluated only on post-changeset real bot-start, waitlist or community-event
growth. Absence of immediate real volume is `WAITING_FOR_REAL_FUNNEL_VOLUME`,
not a runtime failure.

## Rollback

The versioned controller verifies canonical source state, creates and verifies
Git bundles, copies the runtime manifest, units, configuration, DB schema
shape, aggregate counts and exact aggregate bytes, then writes SHA-256
evidence. A deployment failure restores both repository commits and all
affected installed files, removes newly introduced S10.2F state, reloads
systemd and restarts only the WMS service. The historic acquisition aggregate
is evidence and is not truncated during rollback.

## Product boundaries

`REAL_ACQUISITION_ACTIVE` remains true. Adult media, community adult media,
real AVS, payment, external publishing, controlled beta and production remain
closed. Human acceptance remains `DEFERRED`. `tu1nz-doc.service` and Yoti are
out of scope.
