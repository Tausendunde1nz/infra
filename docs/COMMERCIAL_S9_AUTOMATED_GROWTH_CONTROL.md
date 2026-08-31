# Commercial S9 – Automated Audience Growth & Creator Invite Readiness

## Outcome

S9 adds a bounded, public-SFW growth layer to the stable S8 Early Access
runtime. Organic discovery, curated DE/EN guide pages, cookie-free aggregate
landing counters, daily reports and opt-in nurture run automatically. S8 stays
the waitlist and Telegram entry point.

The active acquisition paths are organic search and the dedicated public SFW
Telegram channel `@tu1nz_adult_publishing`. The channel publisher accepts only
versioned SFW templates plus a fixed first-party attribution URL. Before the
first post and during every health run, it verifies the exact public username
and the Early Access bot's administrator post permission. X is disabled because productive API cost and
credential approval are not authorized. Reddit is disabled because commercial
API approval is absent. No manual posting fallback is permitted.

## Hard boundary

Adult media, submissions, identity documents, biometrics, live AVS, payment,
external adult publishing, Creator Invite, Controlled Beta and the production
Adult workflow remain inaccessible. S9 may calculate eligibility but cannot
advance beyond `ELIGIBLE`. The invite switch is false in configuration,
database constraints and health checks. The price mode is
`FREE_EARLY_ACCESS`; payment is recorded as `PAYMENT_NOT_REQUIRED`, never as a
fabricated success.

## Automated runtime

- The existing landing service writes only daily aggregate counts. It stores no
  cookies, IP addresses, browser IDs or visitor identifiers.
- The deterministic content seed creates twelve weeks of approved DE/EN SFW
  content without free-form public LLM generation.
- The audience timer publishes only due, reviewed SFW templates to the bound
  Telegram channel. Durable leases, retry budgets and uncertain-outcome fencing
  prevent duplicate replay.
- The nurture timer sends only approved copy to users who explicitly opted in.
  Opt-out and waitlist leave are checked again immediately before claiming a
  delivery.
- The daily report stores aggregate funnel results in PostgreSQL and emits a
  privacy-safe operational envelope.
- The five-minute health timer requires Telegram channel identity and bot post
  permission to remain green, treats X and Reddit as `DISABLED_EXPECTED`, and
  fails on any opened product boundary.

All periodic automation is implemented with systemd timers. Cron and manual
routine operation are prohibited.

## Deployment and rollback

The S9 controller requires an exact Control SHA/tree, a clean application
baseline, S7/S8/landing/nginx with zero restarts, closed Adult runtimes and a
verified backup. It fetches only canonical application `main`, pins the reviewed
S9 merge commit/tree, validates source hashes, applies the dedicated migration
0026 exactly once, installs hardened units and performs local, Telegram and
external health checks before the first SFW channel publication.

The two inherited S8 credential files remain bound to the established
`root:root` / `0600` baseline. S9 reads them only through systemd
`LoadCredential`; it does not widen ownership or permissions for `chatops`.

Failure disables all S9 timers, deactivates the Telegram channel gate, restores
the pinned organic-only S9 application release and backed-up S9 configuration
and units, then proves organic S9 and S8 green. Publication and funnel evidence
is preserved; an automatic destructive database restore is forbidden.

## Provider decisions

X remains `DISABLED_FOR_NOW`: official API access is usage-priced, URL posts
carry a materially higher unit charge, and productive credentials/budget have
not been authorized. Reddit remains `DISABLED_FOR_NOW`: commercial use requires
prior permission and TU1NZ has no approval. Browser automation, scraping and
manual posting are not alternatives.
