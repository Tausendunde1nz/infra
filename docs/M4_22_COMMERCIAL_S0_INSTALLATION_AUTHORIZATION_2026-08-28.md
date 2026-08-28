# M4.22 - Commercial S0 installation authorization

Date: 2026-08-28

Environment: `ubuntu-8gb-nbg1-2` via Tailscale `100.121.130.51`

Scope: final post-merge, read-only installation authorization checkpoint

## Result

**Technical decision: GO for a separately approved root installation window.**

**Execution decision: GO for the fresh pre-install backup and the isolated,
stopped installation. First start and every external provider remain NO-GO.**

M4.22 did not install, stage, activate or start anything. It changed no server
path, identity, ACL, PostgreSQL rule, database, service, timer, container,
token, provider or network setting. The existing synthetic S1 service remained
untouched.

The operator approved RPO 24 hours, RTO 4 hours, encrypted retention 7 days and
accepted that the known unrelated `tu1nz-doc.service` failure does not block
this isolated, stopped installation window at `2026-08-28T14:35:32Z`. The
fresh encrypted absent-state backup remains mandatory before the first server
mutation.

## Product boundary

The proposed Commercial S0 remains an isolated, network-free and
synthetic-data-only candidate. It does not enable Telegram intake, real media,
payments, AVS, X, Reddit, external providers or production publishing. The
product contract remains:

- compensated targets: Reddit and Telegram;
- uncompensated target: X;
- no TU1NZ compensation for an X action;
- no first start or activation in the installation window.

## Final repository baselines

| Evidence | Observed final value | Result |
| --- | --- | --- |
| Application `main` | `52494d6121660ead53774deb8616701f14bb7a8f` | GO |
| Application tree | `b2820945c52ffdf77c2f5fbdd227c03ee6b245ab` | GO |
| Control `control-main` | `e6426429cd44a57afd22801789ad518952098df0` | GO |
| Control tree | `01c0be0ed03d31901f2132c853771807bbeaebdf` | GO |
| Server canonical Control | clean and exactly `e6426429cd44a57afd22801789ad518952098df0` | GO |
| Server canonical application | clean but stale `5572ea165c11fa9d409d1e76ddf08243ae657ea0` | prohibited as release source |

The future installation must stage the immutable final application and Control
SHAs. The stale canonical application checkout must not be copied or used as a
release source. The active sync agent may continue to update canonical
checkouts; immutable SHA-specific release roots remain mandatory.

## M4.21 host-access closure

Pull requests M4.20 and M4.21 were merged before this observation. At
`2026-08-28T14:21:37Z`, the server had synced the final Control commit and all
seven installation-relevant artifacts matched the local final branch byte for
byte:

| Artifact | SHA-256 |
| --- | --- |
| M4.21 manifest | `9b29c180cc7f7881fc4c25c477a5faad3d41700f2894bbd12f4ce3f1a50991bb` |
| Host-access gate | `c5a130a6e70e0045bd7d2bfd0012376e463402b85f937d8003bd5513f6f57d61` |
| Nonrecursive path-access tool | `8a9bf545c9b147b03b409c7a98c0abb27c03080f1bafd58e278a2212da1ac468` |
| PostgreSQL HBA rule | `6ee9b816caf4bc530f918f8189fca4ea85926a4a817a10b0e93d600029e2ac3b` |
| PostgreSQL ident map | `de628e84ba6f50d12fff6fa45646f84637b1507eed06675592ea67563b55a46a` |
| Commercial unit | `ecec13e294ded68dfeeaba1300eb2f5247aacf5e9085c9838eca3b50f6a56bf3` |
| Commercial-aware backup script | `0de61224be517e08fd0a789673df7977f0581aa92608513d99ca9a26ad4bebe8` |

The design now provides exactly five nonrecursive traversal ACLs, preserves ACL
masks, prohibits `chatops` group membership for the runtime identity and maps
only the runtime OS identity to the runtime database role. The migrator is not
peer-mapped.

## Final read-only server observation

The Tailscale-only root probe completed at `2026-08-28T14:22:05Z`.

- The release, configuration and state roots are absent.
- The commercial OS user and group are absent.
- The commercial database, migrator role, runtime role and connections are
  absent.
- There is no commercial systemd unit, timer, cron reference, process, open
  file or Docker mount.
- PostgreSQL 17.11 is online, listens on `localhost` / `127.0.0.1:5432` and
  uses its Unix socket under `/var/run/postgresql`.
- The active HBA default remains `local all all peer`; no commercial HBA or
  ident record is installed.
- Root storage has 21,029,371,904 bytes available and memory has
  6,109,085,696 bytes available. There is no swap.
- The versioned unit remains uninstalled. Offline native verification fails
  only because the immutable executable has not been staged; its systemd
  security score remains `0.6 SAFE`.
- The host remains `degraded` solely because of the previously known,
  independent `tu1nz-doc.service` failure. This is not silently accepted for
  an installation window.

The root Git portion of the first combined probe was rejected by Git's
ownership protection. It created no exception and changed nothing. Repository
identity and cleanliness were immediately repeated under `chatops`; only those
successful values are credited. The diagnosis is versioned in
`analysis/M4_22_ROOT_GIT_OWNERSHIP_PROBE_2026-08-28.diagnose`.

## Backup and rollback state

The latest encrypted baseline archive remains remotely present:

- archive: `tu1nz_system_backup_20260828T03-31-58Z.tar.gz`;
- bytes: `45,142,464`;
- SHA-256: `5110d1e85d4256e22af6ad44cf23cb0333cd759c763219ce35a10dcc0f1496e5`;
- daily restore smoke: passed at `2026-08-28T06:16:52Z`.

This proves recovery of the current pre-install state but is not a substitute
for the mandatory fresh snapshot immediately before the first mutation. The
installed backup script remains the legacy digest
`068eccb256b4f5f9d3abed8bcc58b03145bdb2745b003ca60616daf4c07d0f78`;
the versioned commercial-aware digest is
`0de61224be517e08fd0a789673df7977f0581aa92608513d99ca9a26ad4bebe8`.

The future rollback target is the verified fresh absent-state archive. The
versioned backup script must be installed after that backup and before any
commercial root is created. A commercial archive/manifest pair and isolated
database restore rehearsal remain mandatory before the stopped unit can be
considered installed successfully.

## Operator decision recorded

M4.19 intentionally requires explicit values rather than inventing them. The
recommended starting profile, matching the existing S1 operating target, is:

| Item | Selected value | Approval |
| --- | --- | --- |
| RPO | 24 hours (`86400` seconds) | approved |
| RTO | 4 hours (`14400` seconds) | approved |
| encrypted retention | 7 days | approved |
| known unrelated `tu1nz-doc.service` failure | accepted only for this isolated, stopped installation window | approved |

The approval authorizes the fresh backup and stopped installation sequence in
this document. It does not authorize first start, network access, providers,
tokens, real media, real payment or publication.

## Authorized installation sequence

1. Validate, commit, push and merge this operator-approved authorization.
2. Create a fresh encrypted absent-state archive with the currently installed
   backup process, verify its remote checksum and run a non-disruptive restore
   smoke. Abort on any mismatch.
3. Open one separately documented root window. Install and hash-verify the
   versioned commercial-aware backup script before creating commercial paths.
4. Stage immutable application, Control and virtual-environment roots; create
   the isolated OS identity, least-privilege ACLs, database roles, database and
   peer mapping; validate every gate after each reversible boundary.
5. Apply migration `0014`, create the exact commercial backup/manifest pair and
   prove an isolated database restore rehearsal.
6. Install the unit stopped and disabled, run native verification and the
   release gate. First start and provider activation remain separate approvals.

## Machine-verifiable evidence

`manifests/adult-publishing-commercial-installation-authorization.m4-22.json`
binds this result. Its gate requires the exact approved profile while keeping
fresh-backup, installation, activation, networking, provider and server-change
claims fail-closed. The negative test suite covers all critical transitions.
