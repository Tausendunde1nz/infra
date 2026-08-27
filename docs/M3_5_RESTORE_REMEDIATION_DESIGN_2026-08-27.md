# TU1NZ M3.5 restore remediation design

- Date: 2026-08-27
- Classification: Control SSOT design only
- Control baseline: `5beb00f7a96bea6ebc90da48082edb9bc9c8ac8d`
- Current reviewed application `main`:
  `c574d958d5db624f516f70bda7f36b68ddbd9230`
- Host: `ubuntu-8gb-nbg1-2`
- Runtime implementation: not authorized
- Formal design result: **READY FOR REVIEW**
- Runtime result: **NO-GO**

## 1. Objective

This design defines the complete remediation required to turn backup existence
into reliable, current-revision restore evidence for TU1NZ Adult Publishing. It
addresses:

1. drift between the active restore script and Control SSOT;
2. false-success systemd results after required assertions fail;
3. selection of the wrong backup class;
4. lack of an exact expected-application-SHA assertion;
5. missing negative-test evidence;
6. missing RPO/RTO measurement; and
7. rollback when installation or validation fails.

This document creates no executable, unit, timer, manifest, backup, restore
directory or server change. Names and paths below are reserved future targets,
not activation permission.

## 2. Established baseline and blockers

| Item | Current evidence |
|---|---|
| Installed generic restore script | `/usr/local/bin/restore_test.sh`, SHA-256 `45f7d7f2c5d9d7cc680b45c941fdcf0c67ab37352832649ed82e70a2855c1702` |
| Tracked generic restore script | `scripts/restore_test.sh`, SHA-256 `dc86808cbd644a840f8cf62db29d3cfd270c99c980d5364cffb5ef578da1c4e8` |
| Installed/tracked backup script | bit-identical SHA-256 `11252a9438e4ba6d4580ee284c8ef663bbf5a7518c780f158f56f92c8179763f` |
| Active generic unit | `restore-test.service` executes the installed drifted script |
| Generic result defect | journal contains `FAIL`; systemd reports exit status `0` |
| Weekly smoke source | 2025 documentation snapshot, not current application backup |
| Latest archived application SHA | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Current reviewed application SHA | `c574d958d5db624f516f70bda7f36b68ddbd9230` |
| Hetzner rollback | no snapshot, backup, Cloud firewall or delete/rebuild protection |

The current monthly and weekly jobs are not accepted as Adult Publishing
restore evidence.

## 3. Separation of responsibilities

The remediation has two independent lanes.

### Lane A — generic false-green containment

The legacy monthly `restore-test.service` must either:

- execute an installed file that is bit-identical to the reviewed Control
  `scripts/restore_test.sh`; or
- remain disabled and explicitly classified as non-evidence until a separately
  reviewed replacement exists.

It must never report success if its own required checks produce `FAIL`.
Fixing the generic job does not prove Adult Publishing recovery.

### Lane B — dedicated Adult Publishing restore gate

A new dedicated gate must verify the exact Adult Publishing system-backup class
and reviewed application revision. Proposed future Control artifacts:

```text
scripts/tu1nz_adult_restore_verify.sh
systemd/tu1nz-adult-restore-verify.service
systemd/tu1nz-adult-restore-verify.timer
manifests/adult-publishing-staging-release.json
```

The service is on-demand first. Its timer remains disabled until a successful
negative/positive acceptance cycle, an approved schedule and documented
retention exist.

## 4. Release-manifest contract

Before any checkout, installation or backup mutation, a reviewed, non-secret
release manifest must bind:

```json
{
  "environment": "STAGING-S0",
  "application_sha": "<40 lowercase hexadecimal characters>",
  "control_sha": "<40 lowercase hexadecimal characters>",
  "outbound_providers_enabled": false,
  "synthetic_data_only": true,
  "migration_hashes": {"<relative migration path>": "<sha256>"},
  "dependency_lock_sha256": "<sha256>",
  "rpo_target_seconds": "<approved positive integer>",
  "rto_target_seconds": "<approved positive integer>",
  "approved_utc": "<RFC3339 UTC timestamp>"
}
```

Rules:

- no branch name may substitute for `application_sha` or `control_sha`;
- no token, key, account ID, media reference or personal data belongs in the
  manifest;
- missing, malformed or non-approved RPO/RTO values block execution;
- `outbound_providers_enabled` must be exactly `false` for S0;
- the current reference SHA is `c574d958...`, but every future run must use the
  exact reviewed SHA from its own manifest rather than a hard-coded value; and
- the manifest itself must be merged before it may be consumed.

RPO and RTO values are deliberately not invented by this design. Their business
approval remains a mandatory input to implementation.

## 5. Backup selection and evidence contract

The dedicated gate may select only remote objects matching:

```text
gcrypt01:backups/tu1nz_system_backup_*.tar.gz
```

It must reject legacy `bot_system_backup_*`, documentation smoke archives,
pre-change bundles and every other class. Selection must use remote metadata and
a deterministic newest-object rule; an empty or ambiguous selection fails.

The source backup workflow must record, without secrets or PII:

- archive basename and UTC completion timestamp;
- local and downloaded SHA-256;
- expected application and Control SHAs;
- archived application and Control SHAs;
- schema/migration identity;
- required object/media counts when storage exists;
- encryption target name, but not key material; and
- coverage result for every required namespace.

An archive containing a clean Git repository at the wrong SHA fails. Backup
service success alone is not coverage evidence.

## 6. Isolated restore algorithm

Every run uses a new root-owned timestamped directory beneath:

```text
/opt/tu1nz_repos/backups/restore-tests/<run-id>/
```

The gate must execute in this order and stop on the first required failure:

1. validate the reviewed manifest and environment;
2. assert outbound provider integration is disabled;
3. select only the approved backup class;
4. download to the new run directory without overwriting an existing file;
5. compare the download byte-for-byte with the corresponding local source
   archive when local source retention is required;
6. verify SHA-256 and compressed-archive integrity;
7. extract below the run directory only, rejecting absolute paths, parent
   traversal, special devices and unexpected ownership semantics;
8. require restored `control/.git` and `adult-publishing-core/.git`;
9. run full Git object-integrity checks for both repositories;
10. require both restored worktrees to be clean;
11. require restored application `HEAD` to equal manifest `application_sha`;
12. require restored Control `HEAD` to equal the Control revision recorded for
    the backup run;
13. verify migration/dependency hashes against the manifest;
14. when database/media components exist, restore them with all outbound
    providers disabled and verify record/object bindings, quarantine and
    deletion semantics;
15. measure recovery point and wall-clock recovery time against approved RPO/
    RTO targets;
16. write a non-sensitive evidence record; and
17. emit the final success marker only after every required assertion passes.

No restored application process may contact Telegram, X, Reddit, AVS, payment
or production storage. A restore is never promoted over an active path.

## 7. Exit and marker contract

Required success markers:

```text
RESTORE_PREFLIGHT=PASS
RESTORE_ARCHIVE_COMPARE=PASS sha256=<sha256>
RESTORE_ARCHIVE_INTEGRITY=PASS
RESTORE_REPOSITORY=PASS repo=control head=<sha>
RESTORE_REPOSITORY=PASS repo=adult-publishing-core head=<sha>
RESTORE_EXPECTED_SHA=PASS expected=<sha> actual=<sha>
RESTORE_RPO=PASS target_seconds=<n> measured_seconds=<n>
RESTORE_RTO=PASS target_seconds=<n> measured_seconds=<n>
RESTORE_VERIFY=PASS run_id=<id>
```

Every required failure must:

- emit one normalized `ERROR code=<stable-code>` record;
- omit `RESTORE_VERIFY=PASS`;
- exit non-zero;
- make systemd `Result`/`ExecMainStatus` report failure; and
- retain the isolated evidence directory for investigation.

A generic `done`, successful shell pipeline or successful notification cannot
override a failed assertion. Notifications run after the final result is fixed
and may not change the process exit status.

## 8. Mandatory negative-test matrix

All tests use synthetic fixtures and a disposable isolated directory.

| Test | Injected condition | Required result |
|---|---|---|
| N01 | release manifest missing | non-zero; `MANIFEST_MISSING` |
| N02 | manifest environment is not `STAGING-S0` | non-zero; `ENVIRONMENT_MISMATCH` |
| N03 | outbound providers enabled | non-zero; `OUTBOUND_NOT_DISABLED` |
| N04 | no approved remote archive | non-zero; `ARCHIVE_NOT_FOUND` |
| N05 | ambiguous archive selection | non-zero; `ARCHIVE_AMBIGUOUS` |
| N06 | remote download failure | non-zero; `DOWNLOAD_FAILED` |
| N07 | local/downloaded bytes differ | non-zero; `ARCHIVE_COMPARE_FAILED` |
| N08 | checksum mismatch | non-zero; `CHECKSUM_MISMATCH` |
| N09 | corrupt or unsafe tar content | non-zero; `ARCHIVE_INVALID` |
| N10 | required restored repository missing | non-zero; `REPOSITORY_MISSING` |
| N11 | Git object check fails | non-zero; `GIT_INTEGRITY_FAILED` |
| N12 | restored worktree dirty | non-zero; `WORKTREE_DIRTY` |
| N13 | application SHA differs from manifest | non-zero; `APPLICATION_SHA_MISMATCH` |
| N14 | migration/dependency hash differs | non-zero; `ARTIFACT_HASH_MISMATCH` |
| N15 | RPO target missed | non-zero; `RPO_MISSED` |
| N16 | RTO target missed | non-zero; `RTO_MISSED` |
| N17 | database/object/quarantine assertion fails | non-zero; stable component error |
| N18 | notification fails after a verified restore | restore result retained; notification failure separately visible |

For N01-N17 the systemd test invocation must also report failure. A single
false-green negative case blocks installation and timer activation.

## 9. Positive acceptance

The positive test must use a newly produced encrypted archive whose application
SHA equals the reviewed manifest. Acceptance requires:

- all markers in section 7 exactly once;
- no `ERROR` or `FAIL` marker;
- both Git repositories clean and object-complete;
- exact application SHA equality;
- all required database/object/quarantine assertions when applicable;
- RPO and RTO within approved targets;
- no provider/network side effect;
- systemd `Result=success`, `ExecMainStatus=0`; and
- a retained evidence record linked from Control SSOT.

## 10. Future installation transaction

This sequence is not authorized by this document. A future execution approval
must perform it as one controlled maintenance transaction:

1. re-run the read-only server/path/writer inventory;
2. verify exact Control and application remote SHAs;
3. obtain an acceptable infrastructure rollback; the current server has no
   Hetzner snapshot or backup;
4. create an encrypted pre-change bundle of the installed restore script, unit,
   timer, enablement state and relevant non-secret configuration;
5. download that bundle into an isolated location and verify its checksum and
   extraction before changing the host;
6. install only reviewed Control artifacts with fixed root ownership/modes;
7. verify installed hashes exactly equal Control hashes;
8. run shell/static systemd verification before daemon reload;
9. keep the timer disabled;
10. execute N01-N18 and require every expected outcome;
11. update the application through a separately reviewed immutable-release
    procedure, never an unguarded in-place branch pull;
12. create a fresh encrypted backup containing the manifest application SHA;
13. run the positive isolated restore and record RPO/RTO;
14. observe the service result and scan evidence for secrets/PII; and
15. enable a timer only after a separate schedule/retention approval.

No Telegram, X, Reddit, AVS, payment, media or production action belongs to the
transaction.

## 11. Proposed systemd constraints

The dedicated service design requires at least:

- `Type=oneshot`, `User=root`, `Group=root`, `UMask=0077`;
- explicit `ExecStart` to the installed reviewed script;
- `NoNewPrivileges=true`, `PrivateTmp=true`, `PrivateDevices=true`;
- `ProtectSystem=strict`, `ProtectHome=read-only`;
- explicit read-only access to source/manifest/configuration paths;
- the restore-test root as the only application-specific writable path;
- bounded runtime, memory and process count;
- network access limited to the encrypted backup transport and never provider
  APIs; and
- no secret value in the unit, command line, journal or notification.

Exact directives must pass `systemd-analyze verify` on server systemd 255 before
installation. The final sandbox must account for the approved rclone credential
mechanism without copying credentials into Control or the restore directory.

## 12. Rollback design

Rollback is required if installation hashes differ, static verification fails,
any negative test is false-green, positive restore fails, RPO/RTO is missed or
monitoring exposes sensitive material.

Rollback sequence:

1. keep/return the new timer to disabled and inactive;
2. stop only the new or changed oneshot unit if still running;
3. restore the exact pre-change script/unit/timer files from the verified
   rollback bundle;
4. restore their prior ownership, modes and enablement state;
5. run daemon reload and verify installed hashes equal the recorded baseline;
6. do not delete the failed run directory, logs or downloaded archive;
7. record the failed acceptance and rollback result in Control SSOT; and
8. leave STAGING-S0 deployment `NO-GO`.

Rollback must not restore application/database/media state over an active
environment and must not issue provider requests.

## 13. Approval gates

```text
Remediation design documentation                    GO FOR REVIEW
RPO target                                           REQUIRED USER/BUSINESS DECISION
RTO target                                           REQUIRED USER/BUSINESS DECISION
Restore evidence retention                           REQUIRED DECISION
Infrastructure rollback method                       REQUIRED DECISION
Generic restore-script installation                  NO-GO / SEPARATE AUTHORIZATION
Dedicated restore artifacts implementation           NO-GO / SEPARATE AUTHORIZATION
Server checkout/release update                        NO-GO / SEPARATE AUTHORIZATION
Backup execution and isolated restore                 NO-GO / SEPARATE AUTHORIZATION
Timer enablement                                      NO-GO / SEPARATE AUTHORIZATION
STAGING-S0 deployment                                 NO-GO
Live providers, real data or production               NO-GO
```

## 14. Design validation and rollback

This design must pass Markdown/whitespace review, stable-marker and negative-
matrix completeness checks, credential sentinel scanning and exact-head PR
review. Control currently has no GitHub Actions workflow, so lack of a remote CI
check must be stated rather than treated as a pass.

Before merge, rollback is branch abandonment from
`5beb00f7a96bea6ebc90da48082edb9bc9c8ac8d`. After merge, rollback is a normal
revert of the exact documentation commit. No runtime rollback applies to this
design-only change.
