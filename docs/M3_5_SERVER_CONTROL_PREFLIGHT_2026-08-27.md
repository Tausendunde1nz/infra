# TU1NZ Adult Publishing – M3.5 server and Control preflight

- Date: 2026-08-27
- Host: `ubuntu-8gb-nbg1-2`
- Tailscale address: `100.121.130.51`
- Administration path: Tailscale SSH only; public-IP fallback was not used
- Scope: read-only host, repository, writer, scheduler, container, database,
  network, backup, restore and Hetzner inventory
- Runtime or deployment change: none
- Formal result: **NO-GO for STAGING-S0 deployment**
- Path/writer isolation: **PASS**
- Backup existence: **PASS WITH STALE APPLICATION REVISION**
- Restore readiness: **FAIL**

## 1. Authorization and containment

Tailscale SSH required a fresh web authorization. The tailnet identity was
verified as the Apple private-relay identity already recorded by Tailscale. The
SSH session then identified the server as `ubuntu-8gb-nbg1-2` and the remote
work user as `chatops`.

The inventory used only read operations. It did not fetch or check out Git
objects, write Control or application files, start/restart/enable a service,
alter cron, inspect secret values, create a database, change a firewall, create
a Hetzner snapshot, install a package or contact an application provider.

Final Git status remained clean in both audited server repositories.

## 2. Host and path inventory

| Item | Verified value |
|---|---|
| Operating system | Ubuntu 24.04, Linux 6.8.0-87-generic |
| systemd | 255 |
| Server Tailscale | 1.102.2, online |
| Root filesystem | 75 GiB total, 52 GiB used, 21 GiB free (72% used) |
| Memory | 7.6 GiB total, 5.8 GiB available |
| Canonical project path | `/opt/tu1nz_repos/adult-publishing-core` |
| Project path owner/mode | `chatops:chatops`, `2770` |
| Control path | `/opt/tu1nz_repos/control` |
| Control path owner/mode | `chatops:chatops`, `2770` |
| Configuration root | `/etc/tu1nz`, `root:chatops`, `0750` |
| Shared runtime root | `/var/lib/tausendunde1nz`, `chatops:chatops`, `2775` |
| Shared log root | `/var/log/tausendunde1nz`, `chatops:chatops`, `2775` |

No dedicated Adult Publishing configuration, runtime or log namespace exists.
The shared runtime and log roots are not accepted as the final privacy boundary;
future subdirectories need dedicated ownership and least-privilege modes before
deployment.

## 3. Repository truth

### Control SSOT

| Item | Verified value |
|---|---|
| Branch | `control-main` |
| Local commit | `56afa854f1d4908361dc07727c68a3803d16b0f3` |
| Remote `control-main` | `56afa854f1d4908361dc07727c68a3803d16b0f3` |
| Worktree | clean |
| Git lock | none |
| Extra worktree | none |

### Adult Publishing checkout

| Item | Verified value |
|---|---|
| Branch | `main` |
| Server commit | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Remote `main` | `069dc964444b8d9b08a73fe7ed7eb5d73681c10b` |
| Worktree | clean |
| Git lock | none |
| Extra worktree | none |

The server checkout is intentionally treated as stale. The read-only remote
query did not update local Git references. No future release may use the server
checkout until a separately authorized exact-SHA release process verifies the
reviewed remote commit and its artifacts.

## 4. Writer and scheduler isolation

The canonical application path has:

- no systemd unit reference;
- no active or inactive cron-file reference;
- no Docker mount;
- no open file handle;
- no inotify watcher; and
- no legacy Git-sync write path.

The legacy Git-sync unit remains restricted to `/opt/spicymila_bot`,
`/opt/telegram_chatbot` and `/opt/trendwatch_bot`. This establishes path
isolation for the current checkout.

Platform-wide scheduler conformance is not complete. `cron.service` is active.
The read-only scan found uncommented relevant entries for
`/usr/local/bin/codex_syscheck.sh` and a malformed or user-less
`monthly_sysstatus` entry, while several other relevant files contained only
comments or inactive material. No system cron location references the Adult
Publishing checkout. Cron retirement remains a separate infrastructure gate;
it must not be mixed into an application release.

## 5. Runtime, database, network and health inventory

No PostgreSQL package, process, cluster or container exists. No Adult
Publishing service, timer, container, listener, database, user or object/media
namespace exists. This is correct for a pre-deployment host but blocks S0 until
an isolated architecture is approved and implemented.

Existing host findings that prevent inheriting the host as a trusted staging
boundary without remediation:

- public listeners include ports `80`, `443`, `2222`, `3000`, `8080`, `8081`,
  `8090`, `9090` and `9100`;
- Grafana, Prometheus, cAdvisor and legacy bot endpoints are among the publicly
  published Docker ports;
- `spicymila_bot` reports `unhealthy`;
- `tu1nz-doc.service` is failed;
- UFW is inactive and the unprivileged inventory could not read nftables or
  iptables rules; and
- no Adult Publishing hostname, TLS certificate or reverse-proxy route exists.

These findings do not prove that every public port is externally reachable;
they prove that the host bindings and firewall evidence are insufficient for
an S0 GO.

## 6. Backup and restore evidence

The installed encrypted-backup script is bit-identical to the Control SSOT
copy. Its current archive includes `control` and `adult-publishing-core`.

| Item | Verified value |
|---|---|
| Latest local archive | `tu1nz_system_backup_20260827T03-30-58Z.tar.gz` |
| Timestamp | 2026-08-27 03:31 UTC |
| Size | 12,853,020 bytes |
| Archive owner/mode | `root:chatops`, `0640` |
| Archived Control commit | `56afa854f1d4908361dc07727c68a3803d16b0f3` |
| Archived application commit | `5572ea165c11fa9d409d1e76ddf08243ae657ea0` |
| Backup service result | success |

The archive does not cover remote application `main` at `069dc964...` because
the server checkout has not been advanced. It is therefore rollback evidence
for the old server checkout only, not for the current reviewed product state.

Restore evidence fails the M3.5 gate:

1. the monthly restore journal contains multiple `FAIL` records for missing
   compose environment files but the service completed with exit status `0`;
2. the installed `/usr/local/bin/restore_test.sh` differs from the tracked
   Control implementation;
3. the weekly restore smoke test uses a 2025 documentation snapshot rather than
   the current application archive; and
4. the last accepted M1 restore proves only application commit `5572ea...`.

The exact script drift and containment are recorded in
`analysis/M3_5_RESTORE_FALSE_GREEN_2026-08-27.diagnose`.

## 7. Hetzner rollback inventory

The existing read-only `hcloud` context reported:

| Item | Verified value |
|---|---|
| Server | `109772243`, `ubuntu-8gb-nbg1-2`, running |
| Server type | `cx32` |
| Attached volume | `103688924`, `media-volume`, 100 GiB |
| Hetzner snapshots | none |
| Hetzner backups | none |
| Hetzner Cloud firewalls | none |
| Delete protection | disabled |
| Rebuild protection | disabled |

The encrypted repository archive remains useful, but it is not an
infrastructure rollback and does not cover the attached volume, future
PostgreSQL state or future media objects.

## 8. Risk register

| Risk | State | Required evidence before S0 deployment |
|---|---|---|
| Stale application checkout | `BLOCK` | exact reviewed SHA release procedure |
| False-green restore service | `BLOCK` | installed script equals SSOT and fails non-zero on every failed assertion |
| No current-head restore | `BLOCK` | fresh encrypted backup plus isolated restore of exact reviewed SHA |
| No infrastructure rollback | `BLOCK` | approved snapshot/backup design and tested recovery path |
| No PostgreSQL/runtime isolation | `BLOCK` | dedicated roles, database, paths, units and object namespace |
| Public legacy/monitoring bindings | `BLOCK` | firewall and network exposure review with least-privilege bindings |
| Failed/unhealthy legacy components | `HOLD` | explicit host-sharing decision and clean health baseline |
| Platform-wide cron residue | `HOLD` | independent inventory, migration and rollback plan |
| Tailscale DERP/client drift | `HOLD` | reviewed client reconciliation and VPN health proof |

## 9. Formal decision

```text
VPN/Tailscale server identity                       PASS
Control SSOT identity and cleanliness               PASS
Canonical path ownership                            PASS
Exact project-path writer isolation                 PASS
Current encrypted backup exists                     PASS
Backup covers current remote application main       FAIL
Current reliable isolated restore                   FAIL
Hetzner snapshot/backup rollback                     FAIL
Dedicated PostgreSQL/runtime/storage boundary        MISSING
Firewall/public-exposure evidence                    FAIL
STAGING-S0 implementation on the server              NO-GO
STAGING-S0 deployment                                NO-GO
Live providers, real data, tokens or production      NO-GO
```

The read-only inventory is complete. Its result does not authorize a checkout
update, package installation, PostgreSQL creation, systemd activation, network
change, snapshot, provider credential or deployment.

## 10. Exact next sequence

The inventory report and diagnosis were merged as Control commit
`5beb00f7a96bea6ebc90da48082edb9bc9c8ac8d`, and the application M3.5 preflight
now references that immutable evidence. The restore remediation design is
frozen in `docs/M3_5_RESTORE_REMEDIATION_DESIGN_2026-08-27.md`; it does not
authorize execution.

1. Obtain explicit business values for RPO, RTO and restore-evidence retention.
2. Obtain separate authorization to implement and locally test the Control
   restore artifacts without installing them.
3. Define the S0 host/network/database/storage/secret/monitoring architecture
   and its RPO/RTO in Control SSOT.
4. Obtain a pre-change infrastructure rollback or explicitly stop if no
   acceptable rollback can be demonstrated.
5. Only after the implementation artifacts and all synthetic negative tests are
   reviewed may server installation/restore authorization be requested.

## 11. Rollback for this documentation change

This report changes documentation only. Before merge, rollback is branch
abandonment from Control baseline
`56afa854f1d4908361dc07727c68a3803d16b0f3`. After merge, rollback is a normal
revert of the exact documentation commit. No runtime rollback is required
because this step does not change the server.
