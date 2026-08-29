# Commercial S3 — controlled server-staging SSOT

Date: 2026-08-29

Decision: **GO for one bounded server-staging maintenance window; NO-GO for
enablement, restart, persistent operation, real AVS, real payment, external
publishing, adult media, controlled beta or production.**

## Bound release

The only permitted Application source is
`Tausendunde1nz/adult-publishing-core` `main` at merge commit
`aba69dfc706fc71e7b1ff12446e5a24f94642762`, tree
`ad67864654c2a1c80b992960163696e20de9998b`. The Application was integrated
through PR #67 by a merge commit and the post-merge Python 3.10/3.13 and
PostgreSQL 17.11/18.6 CI matrix is green.

The Control authorization is
`manifests/adult-publishing-commercial-s3-server-staging.json`. Its offline
gate verifies the exact versioned Application artifacts, disabled templates,
single-start boundary, isolated database identity, secret boundary, and
non-production product boundary. The final merged `control-main` SHA and tree
cannot be embedded self-referentially; both must be captured after merge and
bound into the root-private external live contract before installation or
start.

## Exact target state

| Purpose | Target |
| --- | --- |
| Application checkout | `/opt/tu1nz_repos/adult-publishing-core` |
| Configuration and credentials | `/etc/tu1nz` |
| Runtime state | `/var/lib/tausendunde1nz/adult-commercial-s3` |
| Harmless media | `/var/lib/tausendunde1nz/adult-commercial-s3/media` |
| Logs | `/var/log/tausendunde1nz` |
| Unit | `/etc/systemd/system/tu1nz-adult-commercial-s3.service` |
| Evidence | `/opt/tu1nz_repos/backups/commercial-s3-server-staging/<UTC>` |
| Database | `tu1nz_adult_commercial_s3` |
| Database role | `tu1nz_adult_commercial_s3_runtime` |
| Service | `tu1nz-adult-commercial-s3.service` |

The runtime identity remains the reviewed `chatops:chatops`. The
project-specific runtime-state path is intentionally introduced here and may
be writable only by that identity. No other service, timer, container or
agent may mount or mutate these S3 paths.

## Credential boundary

All six external values are root-owned mode `0600` beneath `/etc/tu1nz` and
are passed only through systemd `LoadCredential`: Telegram token, PostgreSQL
DSN, subject key, live contract, allowlist, and media manifest. The token is
never accepted through Git, a unit value, a CLI argument, environment, logs,
database, or evidence. The live contract and allowlist may contain binding
metadata but no token.

## Database boundary

Server staging creates a new isolated database and minimally privileged role.
No existing S0 or other TU1NZ database is migrated. The complete migration
chain through `0017_commercial_s2_1_telegram_live_test_readiness` must match
SHA-256
`24c116ae3f37eba0be1470f1b401fd4edcb03f8679dd0c95e9881ad20cafb42f`,
and business rows must be zero before acceptance. Existing databases and S0
evidence are protected inputs, never rollback targets for S3.

## Recovery point and rollback

Before the first mutation, record a root-private recovery point containing
the current Control SHA/tree, Application refs, PostgreSQL globals and
database inventory, plus any pre-existing S3 unit/config/state/log targets.
Each member receives a SHA-256 inventory. Restore proof must reconstruct the
recovery material in an isolated directory and verify all hashes before
installation.

Rollback first stops the S3 unit, preserves evidence, restores only any
pre-existing S3 Application/unit/config/state targets, and restores Control
to its recorded reference. The new S3 database is retained for evidence; it
is never deleted automatically. If safe database rollback cannot be proven,
the unit remains stopped and rollback fails closed.

## Prestart and single acceptance

Immediately before the start, revalidate release SHA/tree, merged Control
SHA/tree, all artifact hashes, migration digest, database emptiness, private
credential modes, bot identity `8729546284` / `TU1NZ_Adult_Test_bot`, empty
webhook, STANDARD Telegram environment, one private allowlisted user/chat,
network boundary, mocked AVS/payment, synthetic publishers, disabled adult
media/external publishing/production, competing processes, and available
resources.

Exactly one sequence is authorized:

`PRESTART → VALIDATE → START → READY → OBSERVE → STOP → POST-VERIFY → EVIDENCE`

The unit uses `Restart=no`, `RuntimeMaxSec=1800`, has no `[Install]` section or
`WantedBy`, and must not be enabled. The product acceptance may run exactly
once, after READY, using only the operator's private allowlisted test chat and
the registered harmless JPEG document. AVS and payment remain mocks; all
Telegram, X and Reddit publishers remain synthetic.

Final state must be loaded/inactive/dead/static, `NRestarts=0`, with no
candidate process, no enablement, no foreign network destination, no external
publication, no real payment, no adult media, and unchanged S0 unit/evidence.
