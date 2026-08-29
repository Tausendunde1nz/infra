# Commercial S3.1 — bootstrap and cursor-ownership Control SSOT

Date: 2026-08-29

Decision: **GO for the stopped S3.1 installation delta, exactly one database
bootstrap, read-only bootstrap verification and dry prestart; NO-GO for a
second service start, restart, enablement, product acceptance, provider
activation, external publishing or production.**

## Confirmed cause and bounded repair

The first Commercial-S3 server process consumed its single authorized start and
failed closed before READY. The schema-0017 database contained zero reference
and zero business rows. Runtime therefore had no synthetic creator, S3 policy or
TEST destinations. Independently, deployment preparation created
`telegram-offset.json` as `root:chatops` although the unit runs as
`chatops:chatops`. No product workflow began.

The historical recovery point, failed-start evidence, prestart evidence,
contract history and S0 evidence are immutable. S3.1 creates a new recovery
delta and never rewrites the old run.

## Bound Application and bootstrap

The only permitted Application release is merge commit
`2ff3af411ed58328ee4189255f13c7d5766552ad`, tree
`82b8f5f888309a3dce47f8609c78b96dd1bd2200`. The canonical bootstrap-reference
digest is
`3f7ac26960ac29aea471d33cac634ca1f6e8d572724701cf7fd8268101c0442a`;
the migration-chain digest remains
`24c116ae3f37eba0be1470f1b401fd4edcb03f8679dd0c95e9881ad20cafb42f`.

The root-private installed authorization is sourced from
`config/adult-publishing/staging-s3/commercial-s3-bootstrap-authorization.s3-1.json`.
It grants exactly one STAGING bootstrap against database
`tu1nz_adult_commercial_s3` as role
`tu1nz_adult_commercial_s3_runtime`. It explicitly sets
`service_start_authorized=false` and cannot authorize a systemd start.

The bootstrap creates exactly twelve reference rows: one anonymous synthetic
creator, one policy version, one country rule, three platform rules, three TEST
integration accounts and the three destinations `REDDIT_TEST`, `TELEGRAM_TEST`
and `X_TEST`. It creates zero submissions, payments, publications, dispatches or
other business rows. The mutating command may be invoked once and must return
`CREATED`; the next operation is the separate read-only verifier, which must
return `S3_BOOTSTRAP_READY` with 12 reference, 0 business and 0 external-target
rows. The idempotent `ALREADY_CORRECT` behavior remains Application-tested but
is not exercised as a second server bootstrap in this sprint.

## Recovery and state repair

Before repository synchronization or any installation, run the versioned
controller's `snapshot` action through SSH standard input. It captures the
loaded unit, all S3 configuration/credential files, the complete S3 state tree,
database custom dump, PostgreSQL globals, Git refs and a SHA-256 inventory. Tar
comparison and `pg_restore --list` provide the restore proof. The new recovery
directory is root-private. The existing historical evidence directory is only
hash-checked.

State repair accepts only the observed closed legacy shape: chatops-owned
parent mode `2700`, empty `evidence`, `media-test` and legacy `media`
directories, plus one regular root-owned mode-0600 cursor. The old cursor and
offset are preserved in the recovery delta. The live cursor is removed only
after that proof, the empty obsolete `media` directory is removed, the parent
becomes mode `0700`, and Application code running as `chatops` atomically
creates the replacement cursor with the preserved offset. There is no `chown`,
implicit takeover, symlink acceptance or broad deletion.

## Versioned stopped installation sequence

1. Revalidate inactive/dead/static, `NRestarts=0`, no process, zero DB rows,
   exact old evidence hashes and no competing mutator.
2. Execute `snapshot` before any server repository change.
3. Fast-forward only Application `main` and Control `control-main` to their
   reviewed merge commits; reject dirty, divergent or non-fast-forward state.
4. Execute `install` with the actual post-merge Control SHA/tree. This refreshes
   the editable local Application package, installs the root-private bootstrap
   authorization and S3.1 unit, then performs only `daemon-reload`.
5. Execute `repair-state` and prove chatops ownership/modes and the preserved
   offset.
6. Execute `bootstrap-once`; require `CREATED`.
7. Execute `verify`; require `S3_BOOTSTRAP_READY`, business rows 0 and external
   targets 0.
8. Execute `prestart` using the disabled contract. It uses the same dependency
   graph as runtime, performs the service-role DB rollback probe and runtime-user
   state write probe, performs no Telegram call and must return
   `S3_PRESTART_READY` with `service_started=false`.
9. Execute `finalize` to recheck inactive/dead/static, `NRestarts=0`, no
   process, exact release/state/unit/DB results and historical hashes, then
   produce the final SHA-256 evidence inventory.
10. **Stop.** A later bounded service start requires a new human authorization.

Rollback restores only the archived pre-S3.1 unit/config/state targets and the
recorded repository refs. The database dump is retained and never automatically
deleted. If any recovery hash, legacy path, owner, mode, Git binding, database
identity or expected result diverges, the controller stops fail-closed.

## Hard boundary

S3.1 contains no systemd start/restart/enable, Telegram polling, adult media,
real user data, real payment, AVS provider access, external publisher, product
acceptance or production path. A fully green prestart means only that the two
deployment causes are repaired and the system is ready to be considered for a
new separately authorized bounded start.
