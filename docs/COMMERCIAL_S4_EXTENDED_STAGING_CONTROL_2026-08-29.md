# Commercial S4 extended staging control

## Goal

Commercial S4 prepares provider contracts and a creator/moderator beta journey while keeping all real provider and production capabilities closed. The only operational acceptance permitted by this control is a bounded server-staging window with the dedicated test bot, one allowlisted operator and harmless synthetic data.

## Release binding

- Application branch: `feat/commercial-s4-provider-beta-readiness`
- Application commit: `ffce727d8e1e45c93323bd805e77e5965e8b3941`
- Application tree: `6492a0cc6efcfaca8d8c8fd19e38ccb770f9c85a`
- Database schema: `0018_commercial_s4_provider_beta_readiness`
- Migration-chain SHA-256: `2a7763b33834493ca612f06b9762a3b00fef9f6af042154bba7918f624c32dae`

The Control commit and exact recovery point are deliberately bound only after a fresh pre-mutation backup exists. Until both are versioned, the manifest decision is `NO_GO_SERVER_ACTIVATION_UNTIL_RECOVERY_POINT_BOUND`.

## Risk assessment

The staging process performs Telegram long polling against the already dedicated standard-environment test bot and connects to the isolated local PostgreSQL database. The service can therefore use network access for those two established staging dependencies. It must not call AVS, payment or publishing providers. It must not ingest adult media, identity documents, biometric material, real payment data or non-allowlisted users.

The S4 installation source `systemd/tu1nz-adult-commercial-s4.service` replaces the installed `tu1nz-adult-commercial-s3.service` only inside the authorized stopped maintenance transaction. The historical S3 unit artifact remains immutable. The S4 unit remains static, has `Restart=no`, has no `[Install]` section and has an absolute six-hour runtime ceiling. A narrower active contract is mandatory for every run. Continuous operation is implemented at application level only as a refused future mode; it is not authorized here.

## Backup and rollback

Before any server delta, create a root-owned `0700` recovery point below `/opt/tu1nz_repos/backups/commercial-s4-extended-staging/`. It must contain Git provenance/bundles, current configuration and unit copies, a PostgreSQL dump, state and log metadata, and strict SHA-256 indexes. Restore instructions must be verified without starting the service.

The first attempt at `20260829T202100Z-pre-mutation` is intentionally retained as incomplete evidence and is not a recovery point. `analysis/COMMERCIAL_S4_BACKUP_CONFIG_ARCHIVE_2026-08-29.diagnose` records the fail-closed tar-pattern and inherited-mode findings. Only a fresh path produced by `scripts/tu1nz_adult_commercial_s4_backup.sh` and verified by its strict index may be bound into the manifest.

Rollback is: stop the static service; restore the previous unit, disabled contract and runtime authorization; restore the database dump only if migration rollback is required; restore the previous application and Control Git commits; run `daemon-reload`; verify inactive/dead/static, `Restart=no`, `NRestarts=0`, and the prior release hashes. Rollback never starts or enables the service.

## Extended-staging acceptance

A staging window is valid only when all of the following hold:

1. The service is inactive/dead/static with no process and no restart count.
2. Application and Control SHA/tree are exact and both worktrees are clean.
3. The bound recovery point verifies with strict SHA-256 checks.
4. Provider-readiness and beta-readiness contracts remain inactive and fail-closed.
5. The active staging contract is generated for 7,200–21,600 seconds and remains mock/synthetic/private-only.
6. A fresh prestart validates the release, database, credentials, state, network boundary and product boundary.
7. Observation captures only aggregate, privacy-safe service health, resource, database, journal and network-class evidence.
8. The service is stopped and the disabled contract/bootstrap authorization are restored before the window closes.

Manual stop/start cycles inside the same valid window may be used to prove Telegram reconnection and cursor continuity. `restart`, `enable`, persistent operation and unattended recovery are forbidden.

## Provider decision record

- AVS primary: Yoti, subject to a later contract/legal/data-protection gate and real-credential authorization.
- AVS fallback: VerifyMy, pending equivalent diligence.
- Payment primary: Segpay, subject to underwriting, merchant-account and webhook/security review.
- Payment fallback: CCBill, subject to the same later gate.

The adapters in S4 are offline contracts and deterministic simulators. No credential or first real provider call is authorized by this document.

## External risk gates

The sprint must stop before any real AVS/payment credential, first provider call, real identity or biometric data, real payment instrument or money, Telegram Stars, adult media, external publishing, open registration, controlled beta or production activation.
