# V11 independent dispatcher candidate — 2026-10-03

**LIVE_NO_GO. Primary request only partially completed.** Parent Infra
`e9aeaa406618a90d0b59936905def0e96cb8bf22`. No live operation or PR.

## Material delta

Added `scripts/v11_dispatcher`: independent durable journal/gate, fixed root
adapter, boot/worker/watchdog unit templates and self-contained hash-bound payload
builder. The outer code/state paths are outside the inner Guard cleanup set:
`/usr/local/libexec/tu1nz-v11-dispatcher`, `/var/lib/tu1nz-v11-dispatcher`.
The retained anchor survives inner cleanup; its eventual removal is not implemented
or implicitly authorized by a successful inner rollback.

Dispatcher order is exclusive lock → close/verify gate → read/validate journal →
resume pending fixed step → durable completion → reverify terminal → release.
Repeated runs re-read persistent state. Gate release never follows elapsed time.
An invalid journal remains fenced. Boot fencing is separate from the worker so
starting the original timer does not synchronously wait for the same boot job.
The root adapter reconstructs the original-byte and receipt chain from protected
inner evidence and uses fixed file targets and fixed systemctl argv only.

Bundled code imports only embedded pinned modules, not the author checkout.
Dispatcher/watchdog/installer payloads have separate SHA-256 values:
- dispatcher: `b2f819db3987e84c483b5915b8def9288b41d73d2754493b3d7bfb6d7fe34eca`
- watchdog: `32efe5f7b848c776333a7aafa8c4f8f46682a35b93a67c9dbb10df6c83240816`
- installer: `f0030e6319c322c17738f4f5cdd6ce104f569dd49ba4a100d39ab3281db646b0`

These are **offline candidate** hashes, not an activation manifest. The manifest
has `production_admitted=false`, enforced by the root entry before dispatch. The
installer entry is deliberately refusal-only: **a transactional publication,
bootstrap-resumption and installer rollback implementation is not complete**.
Do not flip this field or use these artifacts as a ready launcher.

## Validation and limits

- Existing targeted tests **2164/2164**, new dispatcher tests **124/124**;
  workflow **108/108**. Two optional Application cases skipped: both expected
  checkouts still absent.
- Original PR68 **35/35**, original PR69 **7/7** Linux ACL/descriptor cases;
  governance **8/8**. No PR69 skip shim accepted a skip.
- New matrix uses hard exits and fresh processes with persistent journals,
  simulated boot changes, repeated completion, corrupt state, and lock exclusion.
  Host/systemd actions in these process tests are modeled. They do not prove
  the root adapter's real cleanup, ownership restore or loaded-manager behavior.
- `systemd-analyze verify` passes the fixed dependency graph using isolated
  stub consumer units and substituted executable locations. Role capabilities
  and writable paths are narrowed, but actual sandbox execution is unverified.
- Unprivileged root/mount namespace creation failed with `uid_map: Operation not
  permitted`. No sudo, package installation or live service fallback was used.
- The full real-systemd installer/cleanup/reboot matrix, complete base-unit and
  loaded-execution-property binding, and integration with post-seal forward
  recovery remain open. The full pre-seal recovery boundary is **not closed**.
  Later V11 phases were not claimed complete or activated.

## Concurrent Control forward change

The final baseline comparison detected an external Control advance from `05b1270`
to `c13358d9adaf783f42feb5c627b6f12825f5805e`, tree
`371d099af59b965b6722712bfc820a91ebbb2e04`. GitHub verified merge PR72:
three commits ahead, zero behind, merge-base `05b1270`; exactly three RC5 repair
paths changed. Its **10/10 current tests pass**. All 190 tracked files match;
index uid/gid1001, 0600, nlink1, SHA-256
`2af9ed310910d3c5aed48f274e2ff3d2b2074a3c7af624945b5be0207b47c36c`.
No Git locks or targeted active writer found. The accessible ignored listing has
82 known entries; 17 protected historical entries were not freshly enumerated.
No actor attribution, no claim that Control remained unchanged, and no completed
automatic adoption/freeze of this new production basis in the V11 contracts.
The initial baseline assertion failure is explained by this forward change.

## Preservation / next boundary

42 Hardening files, 701 baseline files, 1125 historical private hashes, 30 V9
sources and ancestor `1cf0d79` preserved. Existing tracked files were not edited.
Final tested source-map SHA-256: `17d9fe841fc31317584adf89d23243f44049a42673f4f052667ad8f6d9e1a05d`.
Private backups and compact evidence: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-dispatcher-20261003T030643Z`.
Offline rollback: revert the candidate commit; historical evidence remains in Git
and private backups. No production restoration is needed for this source-only work.

No production service, container, credential, permission, firewall/network, SSH,
Tailscale or watchdog was changed by this run. No new privileged reads. No PR/merge.
The next work is installer publication/recovery and real adapter integration;
there is **no MacBook/sudo request yet**, because safe offline preparation remains.
