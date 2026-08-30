# Commercial S8 – Automated Public Telegram Early Access

## Scope

S8 connects the existing public SFW landing page to a dedicated public Telegram bot and an automated PostgreSQL waitlist. The bot supports German and English, explicit waitlist consent, status, notification opt-in/opt-out, deletion, allowlisted attribution and privacy-safe funnel analytics.

## Hard boundary

S8 cannot ingest or download media and cannot create a real submission. Adult content, AVS, identity collection, payment, publishing, creator invites, Controlled Beta and the production Adult workflow remain disabled. The 18+ declaration is not age verification. Automated state progression stops at `WAITLISTED`.

The bot accepts only private `message` updates. Groups, channels, forwards, bot traffic, media and unknown update types are rejected by default. The Telegram adapter has no `getFile` or download capability.

## Data and consent

PostgreSQL is the operational SSOT. Only a pseudonymous subject ID, Telegram user/chat IDs, language, timestamps, first-touch source/campaign, waitlist status, accepted legal versions and notification preference are stored. No username, name, phone number, bio, profile image or message body is persisted. Early Access deletion removes the user-to-Telegram mapping while retaining an unlinkable append-only audit event.

## Notifications

Notifications default to off and require explicit opt-in. Delivery uses versioned approved copy, a provider-neutral queue, cohort materialization, idempotency, bounded retry, receipts and an opt-out filter. There is no manual individual sending path.

## Operations

The Telegram process and its five-minute health check run as separate hardened systemd units. Credentials are root-owned files exposed only through `LoadCredential`; no token is stored in Git, the database, logs or evidence. Health reports only aggregate counters and state-safe component results.

The database-backed kill switch sets public access, new joins and notifications to false without deployment. Existing waitlist data is preserved and the bot returns the versioned maintenance response. Rollback closes this switch, stops and disables S8, restores the prior S7 application release and leaves S8 database records intact.

## Deployment sequence

1. Verify the exact application/control commits and trees and a fresh recovery point.
2. Verify S7 green and S0/S3 inactive.
3. Install the dedicated token through a non-echoing local-to-SSH prompt.
4. Apply migration 0022 and versioned configuration/unit files.
5. Configure and verify the dedicated bot identity, commands, empty webhook and disabled group joining.
6. Restart S7 for the landing deep link, start S8, run local and external health, then enable S8 and its health timer.
7. Perform the bounded live acceptance with the single internal test account and only harmless SFW input.
8. Observe health and aggregate metrics for at least two hours before canonical integration.

No cron, manual waitlist operations, manual broadcasts or daily manual status maintenance is permitted.
