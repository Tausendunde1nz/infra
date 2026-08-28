# M4.21 — Commercial host-access remediation design

Date: 2026-08-28

Control branch: `design/m4-21-commercial-host-access-remediation`

Control parent: `7bcf6e1eb064e1d7328caa160030685f9ed10595`

Final application main: `52494d6121660ead53774deb8616701f14bb7a8f`

Decision: **GO / COMPLETE for versioned Control design; NO-GO for server
installation, ACL or PostgreSQL mutation, systemd and activation**

## Product trace and boundary

M4.21 closes the two design gaps discovered by the read-only M4.20 preflight:
the isolated commercial runtime lacked parent-path traversal and its distinct
OS/database names could not authenticate through PostgreSQL peer. This remains
directly on the TU1NZ product path toward persistent synthetic commercial
execution. It adds no provider, payment, AVS, media, Telegram intake or
publication capability.

This sprint read the server only through Tailscale. It did not create an
identity, edit an ACL or PostgreSQL file, reload PostgreSQL, install a script,
touch systemd, access a token, publish, deploy or merge. The versioned path
tool contains explicit future mutation modes but is uninstalled and is not
referenced by any unit or timer.

M4.20 PR #19 was merged as
`7bcf6e1eb064e1d7328caa160030685f9ed10595`. M4.21 is rebased directly onto
that final `control-main` baseline.

## Versioned artifacts

| Artifact | Purpose | Runtime effect in M4.21 |
| --- | --- | --- |
| `manifests/adult-publishing-commercial-host-access.m4-21.json` | Exact ACL, peer, rollback and still-false installation gates | None |
| `manifests/adult-publishing-commercial-host-access.schema.json` | Fail-closed evidence shape | None |
| `scripts/tu1nz_adult_commercial_path_access.sh` | Future `apply`, `verify` and `rollback` of five named ACL entries | Uninstalled |
| `config/postgresql/adult-publishing-commercial-s0.pg_hba.rule` | Exact runtime-only peer rule | Uninstalled fragment |
| `config/postgresql/adult-publishing-commercial-s0.pg_ident.map` | Exact OS-user to DB-role mapping | Uninstalled fragment |
| `scripts/tu1nz_adult_commercial_host_access_gate.py` | Read-only design/artifact and installed-config verifier | No mutation |

## Least-privilege parent traversal

The future runtime remains
`tu1nz-adult-commercial-s0:tu1nz-adult-commercial-s0` and must never join
`chatops`. It receives one named `--x` access ACL on exactly:

1. `/opt/tu1nz_repos`;
2. `/opt/tu1nz_repos/releases`;
3. `/opt/tu1nz_repos/releases/adult-publishing`;
4. `/etc/tu1nz`; and
5. `/var/lib/tausendunde1nz/adult-publishing`.

No backup parent is included because the commercial service never reads or
writes backups. No target child is changed by this transaction; its M4.19
owner/group/mode remains authoritative. The entry permits traversal of known
names only, not directory listing or writes.

The tool validates the exact observed parent metadata, existing ACL mask and
absence of an unexpected commercial entry before any apply action. It uses
`setfacl --no-mask`, never recursion, and revalidates owner, group, mode, mask,
execute access, denied read and denied write. It refuses a runtime identity in
`chatops`.

`rollback` accepts a fully or partially applied exact state, removes only the
named commercial ACL entry with `--no-mask`, preserves the S1 and `chatops`
entries and proves that the commercial identity can no longer traverse the
five private parents. Unknown commercial ACL content is a hard stop rather
than an overwrite.

## Credential-free PostgreSQL peer mapping

The M4.19 identities remain unchanged:

| Resource | Exact identity |
| --- | --- |
| OS runtime user | `tu1nz-adult-commercial-s0` |
| Database | `tu1nz_adult_commercial_s0` |
| Runtime role | `tu1nz_adult_commercial_s0_runtime` |
| Migrator role | `tu1nz_adult_commercial_s0_migrator` |
| Peer map | `tu1nz_adult_commercial_s0` |

The exact future `pg_hba.conf` rule is:

```text
local tu1nz_adult_commercial_s0 tu1nz_adult_commercial_s0_runtime peer map=tu1nz_adult_commercial_s0
```

It must occur exactly once and immediately before the existing generic
`local all all peer` anchor. The exact `pg_ident.conf` mapping is:

```text
tu1nz_adult_commercial_s0 tu1nz-adult-commercial-s0 tu1nz_adult_commercial_s0_runtime
```

This permits only the commercial OS identity to become the runtime database
role for the commercial database. The migrator receives no peer mapping. No
password, `trust`, TCP rule or provider credential is introduced. The service
continues to use its exact Unix-socket DSN and `AF_UNIX` systemd boundary.

M4.20 observed PostgreSQL 17.11 with `pg_hba.conf` SHA-256
`ad0df9635890926d79a12d5627b68af6b85b6254fa23cace2bbe077838969c9e`
and `pg_ident.conf` SHA-256
`b4dfef08731a7d20a3bb724ad4cf3e1cd91ec01fbe51349c6a3acc5704072965`.
Both are `0640 postgres:postgres`. Any drift before installation requires a
new preflight and review; it must not be overwritten by an old patch.

## Controlled future transaction

M4.21 does not authorize this sequence. A later root window must execute it as
one documented transaction:

1. require exact final application/Control SHAs, clean repositories, absent
   commercial unit and stopped candidate;
2. create and restore-verify a fresh encrypted pre-install snapshot;
3. capture byte-exact, mode/owner and SHA-256 backups of both PostgreSQL files
   plus complete `getfacl -p` output for all five parents;
4. create the non-login OS identity and the isolated database/runtime/migrator
   roles, with no `chatops` membership;
5. run the versioned path tool in `apply`, then `verify` mode;
6. insert the byte-exact peer rule before the generic anchor and the byte-exact
   identity mapping, preserving `0640 postgres:postgres`;
7. require error-free native `pg_hba_file_rules` and
   `pg_ident_file_mappings`, then reload PostgreSQL configuration without a
   service restart;
8. as the runtime OS user, connect over `/run/postgresql` and prove
   `current_user = tu1nz_adult_commercial_s0_runtime` in only the commercial
   database;
9. prove the runtime OS user cannot become the migrator and an unrelated OS
   user cannot become the runtime role; and
10. record hashes, native rule views and positive/negative results before any
    release staging or unit installation.

The design gate's `installed` phase validates exact rule count, rule ordering,
mapping uniqueness and rejects `trust`, duplicate or alternative commercial
rules. The path tool's `verify` mode is the separate ACL acceptance gate.

## Rollback

Before any rollback the candidate remains stopped. Restore the two exact
PostgreSQL file backups with their original metadata, validate native rule
views, reload configuration and prove the commercial runtime connection now
fails while PostgreSQL administrator access remains healthy. Then run the path
tool in `rollback` mode and prove all five named commercial ACL entries are
absent.

Rollback must not remove or alter S1 ACLs, stop S1, change canonical Git
checkouts, drop a database, delete state, alter `chatops`, or touch any provider
credential. Database/role deletion is not authorized by this design; evidence
must be preserved for a separately approved cleanup or restore.

M4.21 itself needs no server rollback because it changes no server state.
Repository rollback is branch abandonment before merge or a normal Git revert
after merge.

## GO / NO-GO matrix

| Gate | Result |
| --- | --- |
| Exact five-path execute-only ACL design | **GO** |
| Explicit apply/verify/partial-safe rollback tool | **GO** |
| No `chatops` membership or recursive ACL | **GO** |
| Exact credential-free runtime-only peer rule | **GO** |
| Exact one-to-one `pg_ident` mapping | **GO** |
| Migrator/unrelated-identity negative contracts | **GO** |
| Exact PostgreSQL file backup and rollback design | **GO** |
| Read-only design and installed-config gate | **GO** |
| M4.20 merged to `control-main` | **GO** |
| M4.21 merged to `control-main` | **NO-GO** |
| Root installation window and fresh backup approved | **NO-GO** |
| ACL or PostgreSQL files changed | **NO-GO** |
| Native installed-rule validation and connection tests | **NO-GO** |
| Commercial releases, identities, database or migration installed | **NO-GO** |
| systemd unit installed or started | **NO-GO** |
| Telegram intake, real media/payment, AVS or external publishers | **NO-GO** |
| Production | **NO-GO** |

## Local validation evidence

- M4.21 design gate returned `M4_21_HOST_ACCESS_DESIGN_OK`;
- an installed PostgreSQL fixture returned `M4_21_POSTGRES_PEER_AUTH_OK`;
- all 24 M4.21 positive/negative tests passed;
- all 122 explicitly enumerated Control tests, including M4.20, passed;
- both Python modules compiled, the ACL shell passed syntax validation and
  both JSON documents parsed;
- negative tests rejected recursive/widened ACLs, `chatops` membership,
  missing rollback gates, password/`trust` authentication, wrong rule order,
  duplicate rules, missing/extra identity mappings, migrator mapping,
  artifact drift, live payment and any installation/activation claim; and
- actual server configuration remained unchanged and continues to contain no
  commercial ACL, peer rule or identity mapping.

## Exact next steps

1. Review and merge M4.21 as design only. Do not install its artifacts during
   merge.
2. Re-run the complete read-only M4.20 installation preflight. It must confirm
   current PostgreSQL hashes, parent metadata/ACLs, backups, paths,
   interference, final SHAs and capacity.
3. Only after a fresh GO, request the separately approved root transaction
   above. Completion of ACL/peer acceptance still does not authorize release
   staging or first start.

Recommended current branch:
`design/m4-21-commercial-host-access-remediation`.
