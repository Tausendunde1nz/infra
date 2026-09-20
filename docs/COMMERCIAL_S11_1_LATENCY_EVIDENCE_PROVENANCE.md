# Commercial S11.1 latency evidence provenance and tri-state SLO

## Decision contract

The S11 deployment gate uses only `REAL_USER_DIRECT_LATENCY`. It requires five
`REAL` `DIRECT_BOT_RESPONSE` samples in the rolling 24-hour window. The metric
is end-to-end bot response time, measured from the Telegram event timestamp to
send acknowledgement. Its unchanged limits are p50 `<1000ms`, p95 `<2000ms`
and p99 `<5000ms`; maximum is reported for diagnosis but is not a separate
acceptance threshold.

Fewer than five relevant samples is `INSUFFICIENT_EVIDENCE`, never `GREEN`.
Unknown provenance, sample type or interaction path is fail-closed `RED`.
Only `GREEN` may continue into the backup-first S11 deployment. `RED` and
`INSUFFICIENT_EVIDENCE` leave S11 disabled with no live-start timestamp.

## Provenance and profiles

New samples bind `evidence_class`, `release_id`, `run_id`, `sample_type`,
`recorded_at` and `interaction_path`, without Telegram identifiers or content.
Canonical evidence classes are `REAL`, `INTERNAL_TEST`, `SYNTHETIC`, `HEALTH`,
optional `PROVIDER_PROBE`, and fail-closed `UNKNOWN`.

- `REAL` is written only by the explicitly configured public runtime path.
- `INTERNAL_TEST` requires an explicit acceptance-runtime marker.
- `SYNTHETIC` is reserved for simulators and fixtures.
- `HEALTH` is reserved for non-user health and monitoring probes.
- `UNKNOWN` is never counted as acceptable evidence.

The defined profiles are `TECHNICAL_RUNTIME_LATENCY` (handler duration for
internal tests), `REAL_USER_DIRECT_LATENCY` (end-to-end direct response),
`COMMUNITY_JOIN_LATENCY` (join/welcome response), and `MODERATION_LATENCY`
(moderation handler duration). They are not mixed.

Poll lag remains stored and reported separately. It is intentionally included
in the real-user end-to-end response metric, while the technical runtime
profile uses handler duration. The 19,079ms historical sample, including its
18,720ms poll lag, is retained unchanged.

## Historical evidence

Migration 0032 is additive. It does not update or delete existing latency rows;
`recorded_at` is a generated alias of immutable `occurred_at`. Legacy
`TECHNICAL_ACCEPTANCE` remains stored exactly as written and evaluates as
`UNKNOWN` unless the separate versioned reconciliation proves its origin.

The reconciliation records only timestamps, latency values and safe provenance
assertions. It classifies the three confirmed external interactions on
2026-09-20 as `REAL`; the three earlier legacy samples remain `UNKNOWN`. The
current six-sample fixture is therefore fail-closed `RED`, not forced green.

## Runtime and deployment separation

The S11.1 contract deployment installs only the provenance writer, additive
migration, reader, reconciliation and non-S11 S8 units. It keeps the existing
S11 schema disabled, preserves `live_start = null`, preserves real acquisition
and its baseline, and never installs the S11 experience configuration. A
separate S11 deployment remains gated by a genuine `GREEN` result.

## Backup mode hardening

The first r1 server attempt stopped before fetch or runtime mutation because the
backup directory inherited a parent setgid bit and therefore had mode `2700`
instead of the controller's required `0700`. The r2 controller explicitly sets
`0700`, removes setgid, records owner/mode evidence, and verifies checksums and
both Git bundles before arming rollback. The r1 freeze and its intact failed-run
backup remain immutable evidence.

## Runtime interpreter binding

The r2 server attempt created and verified its backup, installed the frozen
contract, started the provenance-aware S8 runtime, and completed the S8 health
check. The final contract verification then failed closed and restored the
clean source release. Root-cause evidence showed that the installed reader was
invoked through its system-Python shebang while `psycopg` is intentionally
available only in the frozen Application virtual environment. The reader
contract itself remained valid and returned fail-closed `RED` when invoked with
that environment.

The r3 controllers therefore bind every runtime SLO-reader invocation to
`/opt/tu1nz_repos/adult-publishing-core/.venv/bin/python`. No system package is
installed, no evidence is rewritten, and the SLO thresholds or acceptance
states are unchanged. The r2 backup and diagnosis remain immutable evidence.
