# Commercial S10.2D-R7 aggregate recovery

Status: `P0_SOURCE_PUBLIC_RECOVERY_AUTHORIZED_PENDING_EXECUTION`

## Objective and boundary

Restore the already selected safe source application and its public SFW
endpoints after the versioned R7 rollback stopped at public startup. This is a
one-time state-shape recovery, not a second Community cutover and not a source
feature change. It performs no database, Telegram profile, Community, Adult,
AVS, payment, publishing, acquisition or production mutation.

## Root cause

The target application validly added `COMMUNITY_CTA` to the shared, anonymous
landing aggregate. The source application accepts only `LANDING_VIEW` and
`TELEGRAM_CTA`. R7 restored the source Git/configuration/systemd surface but its
backup set did not include this aggregate file. The source services therefore
failed closed when they read the forward-shaped file.

## Backup-first recovery

The recovery requires the exact clean source Application commit/tree and the
exact clean, post-merge Control commit/tree. It also verifies the hash-bound
source configuration and systemd surface, requires all aggregate writers to be
stopped, and rejects unknown events, duplicate JSON keys, unsafe metadata or an
unexpected path.

Before replacing anything it creates a root-only recovery directory and saves:

1. the exact original aggregate bytes;
2. the source-compatible `LANDING_VIEW` and `TELEGRAM_CTA` view;
3. the isolated forward-only `COMMUNITY_CTA` view;
4. hashes, ownership/mode and count-conservation evidence without dimensions,
   content, messages, media or identifiers.

The source-compatible view replaces the shared file atomically with its
original owner, group and mode. Forward-only aggregates are not deleted; they
remain in the protected backup beside the exact original bytes. If startup or
verification fails, the script stops all affected writers, restores the exact
original bytes atomically and remains fail-closed.

## Success gate

Success requires source Application and Control to remain exact and clean,
the recovered baseline hash to match its backup, the live aggregate to contain
only source-supported events without count regression, all S7/S8/S10/nginx
services active with zero restarts, every S9/S10 timer enabled with a future
run, the S8/S9/S10 health guards successful, internal and public health
`ok=true` with the exact SFW brand/mode, public SFW pages HTTP 200, the German
domain HTTP 308, and all Adult/AVS/payment/publishing/beta/production boundaries
closed.

No follow-on infrastructure sprint or cutover is authorized by this recovery.
