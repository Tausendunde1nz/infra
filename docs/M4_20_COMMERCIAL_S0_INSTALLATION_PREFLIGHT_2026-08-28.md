# M4.20 — Commercial S0 installation preflight

Date: 2026-08-28

Control branch: `preflight/m4-20-commercial-s0-installation-preflight`

Control parent: `2a1b46dfb90fb3e6edcdb7fceaf369bcac0f33e9`

Final application main: `52494d6121660ead53774deb8616701f14bb7a8f`

Decision: **PREFLIGHT COMPLETE; NO-GO for installation, database changes,
systemd installation/start and activation**

## Scope and product trace

M4.20 is the privileged, read-only installation preflight requested after the
M4.19 design was merged. It remains on the direct TU1NZ product path: Telegram
intake, adult and consent verification, human moderation, paid
Telegram/Reddit distribution and separately authorized uncompensated X
automation. It does not add a side project.

The observation was performed only through Tailscale against
`ubuntu-8gb-nbg1-2` (`100.121.130.51`) as root. It read Git, filesystem,
identity, service/timer, container, process/open-file, PostgreSQL,
backup/restore and capacity state. It created no server file or identity,
changed no permission, database, service, timer, container or token, installed
nothing and performed no deployment. Real media, Telegram intake, payment,
AVS and external Telegram/X/Reddit providers remain disabled.

## Final development and repository state

| Item | Observed state | Result |
| --- | --- | --- |
| Application GitHub `main` | PR #58 merged as `52494d6121660ead53774deb8616701f14bb7a8f`; tree `b2820945c52ffdf77c2f5fbdd227c03ee6b245ab` | **GO baseline** |
| Control GitHub `control-main` | PR #18 merged as `2a1b46dfb90fb3e6edcdb7fceaf369bcac0f33e9`; tree `6f3ace3fec2d7d0aa78b409ad108f474d2ae468b` | **GO baseline** |
| Server Control checkout | `/opt/tu1nz_repos/control`, clean, exact final Control SHA | **GO** |
| Server application checkout | `/opt/tu1nz_repos/adult-publishing-core`, clean but stale at `5572ea165c11fa9d409d1e76ddf08243ae657ea0` | **NO-GO as release source** |
| Local Control work | clean final parent, then dedicated M4.20 branch; origin `https://github.com/Tausendunde1nz/infra.git` | **GO** |
| Local application work | clean M4.17 head `183c5479246a27e7844670bf53c7e34200de92ea`; its tree equals final merge tree; no application change made | **GO evidence only** |

The canonical server application checkout must not be pulled in place or used
as a release. A future approved installer must create a new immutable
SHA-named release at the final main SHA. The five-minute `tu1nz_agentmode`
process mutates canonical checkouts and is therefore another reason to use only
immutable release roots.

## Intended paths and work-user rights

The M4.19 targets remain unambiguous and absent:

| Resource | Exact target | Current state |
| --- | --- | --- |
| Release root | `/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial` | absent |
| Configuration | `/etc/tu1nz/adult-publishing/staging-s0-commercial` | absent |
| State | `/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial` | absent |
| OS identity | `tu1nz-adult-commercial-s0:tu1nz-adult-commercial-s0` | absent |
| Database | `tu1nz_adult_commercial_s0` | absent |
| DB roles | `tu1nz_adult_commercial_s0_migrator`, `tu1nz_adult_commercial_s0_runtime` | absent |

The normal work user `chatops` owns the mutable repository base
`/opt/tu1nz_repos` (`2770 chatops:chatops`) and the canonical repositories are
clean. The immutable release parents are root-managed (`2750 root:chatops`),
so installation correctly requires a separately approved root window rather
than ordinary work-user writes.

The runtime identity would not currently be able to traverse all required
parents:

- `/opt/tu1nz_repos`, `/opt/tu1nz_repos/releases` and
  `/opt/tu1nz_repos/releases/adult-publishing` deny access to users outside
  `chatops`;
- `/etc/tu1nz` is `0750 root:chatops`; and
- `/var/lib/tausendunde1nz/adult-publishing` is `2750 root:chatops`.

Existing ACLs grant the S1 identity only the minimum `--x` traversal needed on
these parents. There is no corresponding ACL for
`tu1nz-adult-commercial-s0`. Adding that user to `chatops` would expose a much
broader control surface and is not an acceptable implicit fix. M4.19 contains
no versioned ACL transaction, validation or rollback. This is installation
blocker 1.

## PostgreSQL readiness

PostgreSQL 17.11 is online and listens only on `127.0.0.1:5432` and the local
Unix socket under `/run/postgresql`. The planned database and roles are absent,
and there are no matching active connections.

The active local authentication rule is `local all all peer`; `pg_ident.conf`
has no active mapping. M4.19's exact DSN asks the OS user
`tu1nz-adult-commercial-s0` to connect as database role
`tu1nz_adult_commercial_s0_runtime`. Peer authentication rejects that unequal
identity pair unless a reviewed mapping exists. No such mapping, installation
transaction, validation or rollback is versioned. A password would contradict
the reviewed credential-free local-socket design. This is installation
blocker 2.

## Service, timer, container and path interference

No installed service, timer, cron entry, process, open file or Docker mount
references any commercial S0 target or identity. The M4.19 unit remains only
versioned in Control and is not installed. Existing persistent S1 links remain
separate at application/venv SHA `91d0ae139604bfe8eb61812797cac1056fa2c7d2`
and Control SHA `a6a7740ed854238aa575e741bf7812f601a20217`.

The server reports `degraded` only because the known unrelated
`tu1nz-doc.service` is failed. It does not reference a commercial target, but
the separately approved installation window must explicitly accept or clear
that host-health condition.

The native Linux unit review produced:

- versioned SHA-256
  `ecec13e294ded68dfeeaba1300eb2f5247aacf5e9085c9838eca3b50f6a56bf3`;
- no enablement section, no timer, `PrivateNetwork=yes`,
  `IPAddressDeny=any` and `RestrictAddressFamilies=AF_UNIX`;
- `systemd-analyze security --offline=yes`: exposure `0.6`, `SAFE`; and
- `systemd-analyze verify`: expected nonzero result only because the immutable
  executable does not exist before installation.

Native verification must be repeated and return zero after immutable staging
and before any manual first start.

## Capacity

The root filesystem has 21,014,937,600 bytes available at 73% use. Available
memory is 6,137,077,760 of 8,127,746,048 bytes; no swap is configured. The
final published application tree contains 332 blobs and 3,047,701 bytes; the
Control tree contains 92 blobs and 382,053 bytes; the current local reference
venv is 31,920,128 bytes. Both GitHub tree inventories were complete rather
than truncated.

Capacity is therefore not an installation blocker for one isolated candidate,
although the no-swap condition remains an operational risk to monitor. No
runtime load test is inferred from these storage figures.

## Backup, restore and rollback

The encrypted backup timer is enabled. Its latest service run completed
successfully on 2026-08-28 and uploaded
`tu1nz_system_backup_20260828T03-31-58Z.tar.gz` with 45,142,464 bytes. A direct
read of the encrypted remote object reproduced SHA-256
`5110d1e85d4256e22af6ad44cf23cb0333cd759c763219ce35a10dcc0f1496e5`.
The daily non-disruptive restore smoke downloaded and validated that exact
archive at `2026-08-28T06:16:52Z`.

This is valid evidence for the current pre-install state, in which every
commercial target is absent. It cannot prove recovery of an installation that
does not yet exist. The installed backup script SHA-256 is
`068eccb256b4f5f9d3abed8bcc58b03145bdb2745b003ca60616daf4c07d0f78`,
while the M4.19 commercial-aware versioned script is
`0de61224be517e08fd0a789673df7977f0581aa92608513d99ca9a26ad4bebe8`.
The versioned script must be installed and verified before the first commercial
path is created.

The daily restore smoke proves download and archive readability. The monthly
legacy restore service has known false-green logs, and the weekly legacy smoke
still checks an old 2025 documentation archive; neither is accepted as
commercial recovery evidence. M4.19's exact archive/manifest pair and isolated
database restore rehearsal remain mandatory.

M4.20 itself needs no server rollback because it made no server change. Its
repository rollback is branch abandonment before merge or a normal Git revert
after merge. The future installation rollback must restore the immediate
pre-install absent state, preserve any created database/state evidence, and
must never target the existing S1 release.

## GO / NO-GO matrix

| Gate | Result |
| --- | --- |
| Final application and Control commits published | **GO** |
| Exact target paths and identities unambiguous | **GO** |
| No service/timer/container/process/open-file collision | **GO** |
| PostgreSQL local-only and capacity sufficient | **GO** |
| Current encrypted pre-install backup remotely present and smoke-read | **GO** |
| Least-privilege parent traversal for commercial runtime | **NO-GO** |
| Peer mapping between commercial OS user and DB runtime role | **NO-GO** |
| Final immutable application/Control/venv releases staged | **NO-GO** |
| Commercial OS/database identities and migration 0014 installed | **NO-GO** |
| Commercial-aware backup script installed | **NO-GO** |
| Exact commercial archive/manifest and isolated restore proven | **NO-GO** |
| Unit installed and native verification passing | **NO-GO** |
| Manual first start separately approved | **NO-GO** |
| Telegram intake, real media/payment, AVS or external publishers | **NO-GO** |
| Production | **NO-GO** |

## Risks

1. **Blocking:** M4.19 lacks a least-privilege ACL transaction for the new
   runtime identity. Installation as currently written would create an
   unreachable runtime tree or tempt an over-broad `chatops` membership.
2. **Blocking:** the credential-free DSN cannot authenticate through the
   current peer rule because OS and DB role names differ.
3. **Blocking:** the canonical server application checkout is stale and must
   never be updated in place as a release shortcut.
4. **Blocking before commercial paths:** the installed backup script does not
   yet include M4.19's fail-closed commercial behavior.
5. **Known host risk:** the monthly restore test can report success despite
   legacy compose failures; only the exact daily archive smoke is credited.
6. **Non-blocking preflight risk:** the Tailscale client CLI/daemon versions
   differ locally, a newer client exists and the route used DERP NUE rather
   than a direct path. The VPN remained authenticated and stable for all
   read-only checks.
7. **Non-blocking capacity risk:** the host has no swap and is already at 73%
   root-filesystem use.

## Local validation evidence

- the direct evidence gate returned
  `M4_20_INSTALLATION_PREFLIGHT_NO_GO_CONFIRMED`;
- all 15 M4.20 positive/negative preflight tests passed;
- all 98 explicitly enumerated Control tests passed;
- both M4.20 JSON documents parsed, both Python modules compiled, the existing
  backup shell still passed syntax validation and Git whitespace validation
  passed;
- the static gate check found no service, container, SSH, Tailscale, cron or
  subprocess mutation behavior; and
- two harmless local validation mistakes (a malformed read-only GitHub tree
  query and a missing executable bit) plus the repository's zero-test default
  discovery behavior are preserved in `analysis/` rather than hidden. Their
  corrected reruns are the evidence credited above.

## Exact next steps

1. Create a new Control-only remediation design from final `control-main` for
   explicit `--x` ACLs on only the required parents for
   `tu1nz-adult-commercial-s0`, including pre/post validation and exact ACL
   rollback. Do not add the runtime identity to `chatops`.
2. In the same design or a separately reviewed PostgreSQL design, choose and
   version a credential-free peer mapping between
   `tu1nz-adult-commercial-s0` and
   `tu1nz_adult_commercial_s0_runtime`, including rule ordering, reload,
   positive/negative connection tests and rollback.
3. Native-test both designs in a disposable fixture. Merge their Control PRs;
   do not install them as part of those design sprints.
4. Re-run the read-only M4.20 preflight. It may issue installation-window GO
   only when both design blockers are closed and all final SHAs remain clean.
5. Request one separately approved root installation window with explicit RPO,
   RTO, retention and acceptance of the unrelated failed Doku unit. At the
   start of that window, make and restore-verify a fresh pre-install snapshot.
6. Install and checksum the versioned commercial-aware backup script before
   creating any commercial root. Then apply the reviewed ACL/auth transaction,
   create the dedicated identities/database, stage immutable application
   `52494d6121660ead53774deb8616701f14bb7a8f`, final Control and venv, and
   install migration 0014.
7. Create the exact encrypted archive/manifest pair and prove isolated
   filesystem plus database restore. Install the unit stopped and disabled;
   repeat native verification and the M4.19 release gate.
8. Request a separate approval for one manual network-free synthetic first
   start. Real Telegram/media/payment/AVS/provider work remains later.

Recommended current branch:
`preflight/m4-20-commercial-s0-installation-preflight`.
