# M3.9 persistent Telegram STAGING-S1 deployment evidence

Date: 2026-08-27
Host: `ubuntu-8gb-nbg1-2` via Tailscale only
Result: **GO / enabled / active / READY**

This is post-activation evidence. Its later documentation-only Control commit
is not the active runtime Control artifact and does not change the manifest.

## Manifest-bound release

| Evidence | Exact value |
| --- | --- |
| Application SHA | `91d0ae139604bfe8eb61812797cac1056fa2c7d2` |
| Active Control SHA | `a6a7740ed854238aa575e741bf7812f601a20217` |
| PostgreSQL | `17.11 (Ubuntu 17.11-1.pgdg24.04+2)` |
| Release manifest SHA-256 | `f3a901ea7ff0ae4152123b96a582f606af7ecacfaaae10bef3be0fe3173341ab` |
| Installed unit SHA-256 | `a51dbb1fb8feabff7890914ffe727a7abb4799bb76d0199ff3d5d6fa40164ec0` |
| Approved UTC | `2026-08-27T21:49:54Z` |

The application release came through application PRs
[#37](https://github.com/Tausendunde1nz/adult-publishing-core/pull/37),
[#38](https://github.com/Tausendunde1nz/adult-publishing-core/pull/38) and
[#39](https://github.com/Tausendunde1nz/adult-publishing-core/pull/39). The
runtime Control artifact includes the reviewed Control sequence through
[#14](https://github.com/Tausendunde1nz/infra/pull/14). All required GitHub
checks passed before their exact heads were merged.

## Backup and restore proof

| Evidence | Exact value |
| --- | --- |
| Archive | `tu1nz_system_backup_20260827T21-14-45Z.tar.gz` |
| Bytes | `45104488` |
| SHA-256 | `bcb7197e5643580798d3d0ecae3b274fe767c13f5dd41774871d8b2bea75636d` |
| Completed UTC | `2026-08-27T21:48:55Z` |
| Remote count | exactly `1` at `gcrypt01:backups` |
| Archive entries checked | `11463` |
| Database dump bytes | `222988` |

The exact dump was restored into a randomly named isolated database. The
restore verified `1` synthetic creator, `0` raw Telegram creator IDs, `1`
active synthetic policy, `3` active TEST destinations and `0` non-TEST
destinations. The throwaway database, extracted dump and temporary directory
were removed afterward. The pre-change backup remains separately available.

## Runtime acceptance

- `tu1nz-adult-publishing-s1.service` is enabled and active.
- The versioned release gate passed both manually and as `tu1nz-adult-s1`.
- Fresh health was `READY`, PostgreSQL major `17`, consecutive failures `0`.
- Controlled restart completed; cursor was monotonic and health returned to
  `READY`; automatic restart count remained `0`.
- Telegram `getMe` matched `TU1NZ_Adult_Sandbox_Bot`, group joining was false
  and no webhook was configured.
- State contained `0` processed updates, `0` submissions and `0` terms
  acceptances at acceptance time; raw allowlisted Telegram IDs were absent.
- Database boundary was `0` raw Telegram IDs, `0` publications and `0`
  platform dispatches; exactly `3` active destinations were TEST-only.
- The token was absent from the process command line and service journal.
- No S1 listener, S1 timer, container mount or temporary transfer material
  remained.

At the final post-merge observation (`2026-08-27T22:02:07Z`), systemd still
reported the service active with the same main process, result `success` and
automatic restart count `0`; the runtime-owned status file had been rewritten
five seconds earlier. The chatops identity could not execute the safe health
reader against that 0600 file, and non-interactive sudo correctly required a
password. No privilege was added and no runtime action was taken. This
observation does not replace the successful privileged `READY` acceptance
recorded above; the rights-limited check is captured in the matching diagnosis.

## Preserved safety boundary

External Telegram intake is enabled only for the dedicated sandbox bot.
Payment remains mock-only. Telegram, X and Reddit publishing remain synthetic
and network-free. Live publishers, real payment, live AVS, public posting and
real adult media are not enabled by M3.9.

Accepted residual operational risks are the previously approved GitHub Free
model, a Tailscale DERP-relayed path and slow encrypted remote backup uploads.
The unrelated legacy failed/unhealthy services discovered during preflight
remain outside the S1 paths and were not modified.
