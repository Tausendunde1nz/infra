# S10.2D-R7.1 aggregate compatibility and rollback contract

## Decision and scope

This is a source-only hardening change. It does not authorize or perform a
runtime cutover, server synchronization, service action, database mutation,
Telegram change, Community activation, or real acquisition.

The source-level release path is ready only when the repository tests, full
release simulator, same-SHA review, merge commit, post-merge CI, and immutable
freeze are all green. Runtime activation remains a separate explicit gate.

## Bound baseline

- Application main: `312db84d5db6d76c9d6bb448459c9404b1dfcbe4`
- Application tree: `ac4f8bca1fd796626742a8ef6c6afcdda482fc68`
- Application CI: `34057828638`
- Safe server/source Application: `f9747088a31ec6c671e82de24e293ebdec99f717`
- Safe source tree: `7defedef032f6af38bbce0165eb6c2bdec327df7`
- Control base: `c8b8e692f172ff16a8319063c9b2546d1c43ff88`
- Control base tree: `efae513d13478890814521cf3766bdd6c8a5c3ed`
- Control base CI: `34248366545`
- Source bundle backup: `backups/commercial-s10-2d-r7-1-source/20260908T171601Z`

The historical recovery evidence under
`/opt/tu1nz_repos/backups/commercial-s10-2d-r7-aggregate-recovery/20260908T155418Z`
is immutable and is not touched by this change.

## Aggregate inventory

| Property | Contract |
| --- | --- |
| Live path | `/var/lib/tu1nz-adult-public-s9/landing-aggregates.json` |
| Format | ASCII JSON object |
| Key | `date|event|source|campaign` |
| Value | non-negative integer counter |
| Payload schema | historical v1 counter map; no embedded metadata keys |
| Retention | 35 days in the Application writer |
| Writer | `tu1nz_growth_s9.counter.AggregateCounter` |
| Source readers | S8 Landing and S9 reporting/health paths |
| Target reader/writer | S10 WMS through the same `AggregateCounter` |
| Process locking | in-process `threading.Lock` |
| File write | mode `0600`, temporary file, `fsync`, atomic rename, parent `fsync` |
| Ownership | runtime account owning the existing file; captured numerically in backup metadata |
| Previous cutover backup | did not make this file mandatory |
| R7 emergency recovery | byte backup, forward archive, source projection |

An embedded `schema_version` is deliberately not added. The historical source
reader treats every object member as a counter key, so an embedded metadata
member would itself be forward-incompatible. The version is instead bound in
the immutable backup and reconciliation sidecars.

## Event matrix

| Event | Source support | Target support | Rollback class |
| --- | --- | --- | --- |
| `LANDING_VIEW` | yes | yes | `SOURCE_COMPATIBLE` |
| `TELEGRAM_CTA` | yes | yes | `SOURCE_COMPATIBLE` |
| `COMMUNITY_CTA` | no | yes | `TARGET_ONLY_PRODUCT` |

The shared file currently has no `TARGET_ONLY_TECHNICAL` event. Every other
event is `UNKNOWN` and produces
`AGGREGATE_RECONCILIATION_UNKNOWN_EVENT_RED`. Unknown events are never ignored.

## Exact R7 incompatibility and RED reproduction

The target writer validly wrote `COMMUNITY_CTA` into the shared file. After the
target failed, the old Application was restored without projecting the shared
file back to the source event set. The historical source parser therefore
raised `S9_AGGREGATE_STATE_INVALID`; the public Landing and WMS paths then
failed closed.

The extended release simulator executes the actual target counter writer and
loads the actual source counter implementation from the bound source commit.
It proves the pre-fix RED, performs the new rollback projection, and proves the
same source reader accepts the resulting file.

## Mandatory byte-backup contract

`tu1nz_adult_public_s10_2d_backup.sh` extends the existing runtime backup. A
future S10.2D backup is invalid unless it contains:

- the exact aggregate bytes;
- SHA-256, size, numeric owner/group, and mode;
- the exact restore path;
- source/target release and cutover run identifiers;
- event-schema version and non-sensitive event/count summary;
- entries in the backup-wide `SHA256SUMS` index.

The preflight exposes and verifies these four mandatory facts:

- `AGGREGATE_BACKUP_PRESENT=true`
- `AGGREGATE_BACKUP_HASH_VALID=true`
- `AGGREGATE_BACKUP_MODE_VALID=true`
- `AGGREGATE_BACKUP_RESTORE_PATH_VALID=true`

A missing, modified, mis-moded, or misbound aggregate backup makes the cutover
preflight RED before mutation.

## Rollback and reconciliation order

The production controller now enforces:

1. quiesce target timers, workers, and public writers;
2. preserve the current aggregate bytes and metadata;
3. classify every event;
4. archive target-only events with release/run ownership and hashes;
5. build and validate the source-compatible projection;
6. atomically install the projection;
7. reconcile and downgrade target migrations;
8. restore the source Application and technical surface;
9. prove the actual source aggregate reader accepts the file;
10. start the source services and timers;
11. run the complete source health contract, including another source-reader check.

This ordering ensures an old source process is never started against a known
forward-only aggregate state.

## Conservation, atomicity, and idempotency

The current bytes are archived before parsing or classification. Target-only
counts are retained in a separate hash-bound archive. Source-compatible counts
must be greater than or equal to the pre-cutover counts on every existing key;
natural recovery/test traffic is recorded as a non-negative per-event delta.
The partition must conserve all entries and counts.

Projection uses a new mode-preserving file, file `fsync`, atomic replacement,
and parent-directory `fsync`. An unknown or corrupt input never reaches the
replacement step. A post-replacement failure restores the exact archived
bytes and metadata. Retrying reuses the first archive and projection; it cannot
archive or subtract a count twice.

## Full release simulator

The source-only simulator covers:

- SOURCE → TARGET → `COMMUNITY_CTA` → FAILURE → ROLLBACK → SOURCE;
- multiple `COMMUNITY_CTA` values mixed with normal source events;
- failure before any target aggregate event;
- explicit empty target-technical event set;
- unknown event fail-closed behavior;
- malformed/incomplete JSON;
- backup checksum mismatch;
- two failed recovery attempts with exact original restoration;
- final success followed by idempotent retry;
- source counter regression rejection;
- real source parser acceptance after projection;
- existing migration-down, source-service restoration, WMS listener, bot, and health-gate scenarios.

The simulator operates on real temporary files using the production aggregate
contract and actual Application counter implementations. It does not claim a
runtime deployment.

## Product boundaries and remaining uncertainty

Public SFW WMS and automated SFW growth remain the protected source baseline.
Community runtime and real acquisition remain inactive. Adult media, identity
or AVS data, payments, external publishing, Controlled Beta, and production
adult workflow remain closed.

After all source gates and the immutable freeze are green,
`S10_2D_NEXT_RUNTIME_CUTOVER_READY=true` means only that the next separately
authorized cutover may be considered. Remaining uncertainty is limited to a
future real server execution of the newly versioned backup/rollback contract;
no such execution occurs in R7.1.

Required proof chain:

`SOURCE → TARGET → FAILURE → ROLLBACK → SOURCE → PUBLIC HEALTH GREEN`

## Source validation and integration

- Application (unchanged): 1006/1006 tests GREEN.
- Control: 454/454 tests GREEN.
- Aggregate compatibility: 9/9 focused tests GREEN.
- Full simulator: 8 release, 9 health, 9 listener, and 9 aggregate
  scenarios GREEN.
- Secret, private-key, PII, cron, and destructive-shortcut scans: GREEN.
- Implementation commit: `c8343df7b0f86e91f69614ebef1d7109eba54806`.
- Implementation tree: `326934d28f496f3feb5a4e0553a9ac0ca1444b7d`.
- Pull request: `#142`; CI `34258300367` GREEN.
- Same-SHA review: P1/P2 clean.
- Merge commit: `e73c3798e43dffa35faab98a462f6a13739a98e2`.
- Post-merge CI: `34258458476` GREEN.

These source gates make the separately gated next runtime cutover technically
ready. They do not activate it. The immutable
`s10-2d-r7-1-source-freeze` tag is created only after the final evidence merge
and its post-merge CI are GREEN.
