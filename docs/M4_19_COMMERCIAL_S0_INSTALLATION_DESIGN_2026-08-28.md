# M4.19 — Isolated commercial S0 installation design

Date: 2026-08-28

Control branch: `feat/m4-19-commercial-s0-installation-design`

Parent Control commit: `db1ce1d2cd90646b630fcce6c452d4389a98f644`

Application candidate observed: `183c5479246a27e7844670bf53c7e34200de92ea`

Decision: **GO / COMPLETE for local Control design; NO-GO for server
installation, systemd activation, database migration and every real provider**

## Product trace and boundary

This sprint remains on the direct TU1NZ product path: Telegram intake, adult
and consent verification, human moderation, paid Telegram/Reddit distribution,
and separately authorized uncompensated X automation. M4.19 does not build an
unrelated subsystem. It defines how the already implemented M4.17 commercial
state machine can later run persistently in one isolated synthetic environment.

The current application candidate still uses synthetic data, synthetic
publishers and local PostgreSQL only. Telegram intake, real media, real payment,
AVS and external Telegram/X/Reddit providers remain disabled. M4.19 performs no
server connection, file installation, account creation, database action,
systemd action, token access, media transfer, payment, publication, deployment
or merge. Existing S1 and legacy workloads are untouched.

## Versioned artifacts

| Artifact | Purpose | Runtime effect in M4.19 |
| --- | --- | --- |
| `scripts/tu1nz_adult_commercial_s0_manifest.py` | Bind exact clean application/Control SHAs, migration/dependency hashes, unit/readiness hashes and an exact backup archive | None |
| `manifests/adult-publishing-commercial-s0-release.schema.json` | Freeze the fail-closed manifest shape | None |
| `scripts/tu1nz_adult_commercial_s0_release_gate.py` | Read-only verification of immutable releases, configuration, empty initial state, virtual environment, unit and optional archive | None |
| `systemd/tu1nz-adult-commercial-s0.service` | Hardened local-only process design | Uninstalled; no enablement section or timer |
| `config/adult-publishing/staging-s0-commercial/runtime.env.example` | Exact local Unix-socket DSN with no credential or provider secret | Example only |
| `scripts/tu1nz_encrypted_backup.sh` | Preserve existing behavior before provisioning; include commercial release/config/state/database when all five roots exist; fail on partial provisioning | Versioned only; installed script unchanged |

## Immutable release and identity contract

The M4.18 names remain authoritative:

| Resource | Exact future value |
| --- | --- |
| Application release | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/application/<APPLICATION_SHA>` |
| Control release | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/control/<CONTROL_SHA>` |
| Virtual environment | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/venv/<APPLICATION_SHA>` |
| Configuration | `/etc/tu1nz/adult-publishing/staging-s0-commercial` |
| State | `/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial` |
| OS identity | `tu1nz-adult-commercial-s0:tu1nz-adult-commercial-s0` |
| Database | `tu1nz_adult_commercial_s0` |
| Migrator role | `tu1nz_adult_commercial_s0_migrator` |
| Runtime role | `tu1nz_adult_commercial_s0_runtime` |

Application, Control and venv release directories are root-owned, group-readable
by the non-login runtime group and mode `0750`. The configuration root is
root-owned mode `0750`. `runtime.env` and `release-manifest.json` are root-owned
mode `0640`. The application currently requires `core-identities.json` to be
mode `0600`; it is therefore owned by the locked runtime identity and made
read-only to the service by `ProtectSystem=strict` plus `ReadOnlyPaths`. The
state root is runtime-owned mode `0700`; state, status and lock files are mode
`0600`.

The mutable canonical Control checkout is never a release source. Both
application and Control use clean SHA-named repositories and `*-current`
symlinks only after an approved installation transaction. This avoids the
known five-minute Control reset process recorded by M4.18.

## Manifest and release gate

The generator refuses dirty repositories, output overwrite, missing migration
0014 or its rollback, an archive not matching the TU1NZ name contract, a backup
completed after approval, missing commercial archive roots, path traversal in
the archive, or Control artifacts outside their exact versioned locations.

The resulting mode-`0600` sidecar binds:

- exact application and Control SHAs;
- every SQL migration hash and the dependency lock hash;
- M4.18 readiness and M4.19 unit hashes;
- the backup archive name, byte hash and normalized member-inventory hash;
- exact SHA-specific application, Control and venv backup roots;
- configuration, state and commercial PostgreSQL dump membership;
- explicitly approved RPO, RTO and retention values; and
- the invariant that only Reddit and Telegram are paid while X is
  uncompensated.

The gate never installs or changes anything. It rejects any real media/payment,
network, Telegram intake or external-provider switch; remote database DSNs;
wrong identities, modes or ownership; mutable or non-SHA release paths; dirty
Git state; missing entrypoints; migration/dependency/readiness/unit drift;
nonempty initial conversation state; unit drift; and, when supplied, backup
archive drift.

The archive cannot contain the manifest that hashes that same archive without
a self-reference. Therefore the first qualifying archive and generated
manifest are an inseparable two-file recovery set. A later installation window
must copy both to encrypted remote storage under the same release evidence
record and verify both exact hashes before activation. Subsequent daily archives
may contain the prior manifest, but each newly generated manifest still remains
the sidecar for the archive it hashes.

## Network and service isolation

The unit has deliberately no enablement section and no timer. It can be
installed or started only in a separately approved root window. Its runtime
boundary includes:

- `PrivateNetwork=yes` and `IPAddressDeny=any`;
- `RestrictAddressFamilies=AF_UNIX`, allowing only the local PostgreSQL socket;
- no network-online dependency and no IP address family;
- empty capabilities, `NoNewPrivileges`, strict filesystem protection and
  kernel/namespace hardening;
- read-only application, Control, configuration and PostgreSQL socket paths;
- one writable state root only; and
- the exact M4.17 `--enable-network-free-commercial-candidate` flag.

No Telegram token, provider token, AVS credential, payment credential or media
path exists in the unit or example configuration.

## Backup and restore contract

Before the commercial roots exist, the versioned backup script behaves exactly
like the existing S1 backup. Once any commercial root exists, all application,
Control, venv, configuration and state roots must exist or backup fails closed.
When complete, the root backup process creates a custom-format dump of
`tu1nz_adult_commercial_s0` as the local `postgres` identity and includes the
five roots plus `commercial-s0-database.dump` in the encrypted archive.

A qualifying later restore rehearsal must be performed in a disposable root
and isolated temporary database, never over the live S1 or commercial paths.
It must prove:

1. archive SHA-256 and member-inventory SHA-256 match the sidecar;
2. every SHA-specific release root, configuration root, state root and database
   dump exists with no absolute or parent-traversal member, no hardlink/device
   entry and no file written beneath an archived symlink;
3. restored application and Control repositories have the exact SHAs and clean
   Git object graphs;
4. the custom database dump lists successfully and restores only into a new
   isolated database;
5. migrations through 0014 and the commercial schema verifier pass read-only;
6. the release gate passes against restored paths without activating the unit;
   and
7. the disposable restore is removed only after evidence has been recorded.

No RPO, RTO or retention number is invented by this design. The manifest tool
requires those positive values as explicit inputs from the later approval.

## Rollback contract

Before first start, rollback is removal of the unactivated installed candidate
and restoration of prior absent-path/identity state from the pre-install
snapshot. After first start, rollback first stops the candidate, preserves its
state and database evidence, restores the exact manifest/archive pair into
isolated locations, and only then repoints or removes candidate release links.
Existing S1 remains independent and must never be a rollback target.

Migration `0014_m4_15_durable_commercial_persistence.down.sql` intentionally
refuses rollback when commercial dispatch evidence exists. In that case the
approved recovery is full database restore, not a forced down migration. No
destructive cleanup is authorized by M4.19.

Repository rollback is branch abandonment before merge or a normal Git revert
after merge. There is no server rollback for this sprint because server state
was not changed.

## GO / NO-GO matrix

| Gate | Result |
| --- | --- |
| Versioned exact manifest generator and schema | **GO** |
| Read-only release and optional archive gate | **GO** |
| Network-free hardened unit design | **GO** |
| Commercial-aware fail-closed backup design | **GO** |
| Restore and rollback contract | **GO** |
| Local positive/negative contract suite | **GO** |
| Application candidate merged to main | **NO-GO** |
| M4.18 and M4.19 Control merged to `control-main` | **NO-GO** |
| Final SHA-named releases and venv installed | **NO-GO** |
| OS/database identities or commercial database created | **NO-GO** |
| Migration 0014 installed on the server | **NO-GO** |
| Exact archive/manifest pair uploaded and restore-rehearsed | **NO-GO** |
| Unit installed, enabled or started | **NO-GO** |
| Telegram intake, real media/payment, AVS or external publishers | **NO-GO** |
| Production | **NO-GO** |

## Local validation evidence

- all five explicit Control modules: **83/83 passed**;
- M4.19 positive/negative installation module: **14/14 passed**;
- unchanged application M4.17 contract/runtime modules: **12/12 passed**;
- exact M4.18 gate against clean application SHA
  `183c5479246a27e7844670bf53c7e34200de92ea`:
  `M4_18_COMMERCIAL_READINESS_OK`;
- M4.19 JSON schema parsed, backup shell syntax passed and Git whitespace
  validation passed;
- static checks found no enablement target, timer, IP address family,
  network-online dependency, cron instruction or provider/payment/AVS token in
  the M4.19 runtime artifacts; and
- macOS has no native `systemd-analyze`; that nonfailure and the required later
  Linux verification are recorded in the M4.19 diagnosis.

## Exact next steps

1. Review and merge M4.18 Control, then M4.19 Control, without deployment.
2. Review and merge the application Draft chain through PR #58 in dependency
   order; rerun all CI and record the final main-reachable application SHA.
3. Re-run a fresh Tailscale-only privileged preflight for path, identity,
   service/timer/container/open-file interference and capacity. Native Linux
   `systemd-analyze verify` is mandatory because it is unavailable on macOS.
4. Obtain a separate root installation-window approval with final RPO, RTO,
   retention, backup and rollback targets.
5. Only in that window, stage immutable releases, create identities and the
   isolated database, install migrations through 0014, build the venv and
   private empty configuration/state, create the exact encrypted archive,
   generate and remotely store its manifest sidecar, and complete the isolated
   restore rehearsal.
6. Run the gate with the exact archive. Installation and a manual first start
   remain separate approval points; enabling is not available in this unit.
7. After network-free runtime acceptance and rollback rehearsal, design the
   next product sprint for synthetic Telegram-to-commercial composition. Real
   providers and real money remain later, separately approved windows.

Recommended continuing branch after review:
`feat/m4-19-commercial-s0-installation-design` until its stacked Draft PR is
merged.
