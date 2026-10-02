# V11 baseline supersession and production recovery gate — 2026-10-02

This delta supplements, never rewrites, the prior authority/preparation evidence. Infra starting commit: `1f0e1c89b9c6c1d012447363f2fddca6696343ab`. No live activation, root collection, service call, token rotation, container/network change, PR or merge occurred.

## Authorized Control basis

New HEAD `e60aa2f515c89f94bce1dbd6496d358cdfb85300`, tree `4640102c40af0111be62b845842f0d7b99ca69f2`. GitHub compare confirms eight commits ahead, zero behind, merge-base exactly `21e822f8cadecf5eb186693d1ceac2d5d0bf6969`, and exactly the four PR #68 RC5 files. This is an authorized ancestry-preserving merge, not a claim that its Git history contains no merge commit. No local sync-actor investigation was repeated.

All 187 tracked files matched Git blobs; tracked diff empty; no Git lock files; regular index link count one, chatops:chatops 0600, inode 1460623. Index bytes/identity stayed stable across the read-only examination. Index SHA-256 `623fd407ab393599423b2aee4a3a603466198cc8767deef3abe87fbb8749e863` also matched after tests. These observations do not claim that a future writer cannot appear; activation must recheck. Git reads used optional locks disabled, neutral global/system configuration and hooks/fsmonitor disabled. Neither live checkout nor Gitdir was switched.

Current authority constants, current contract and dedicated Control candidate deployment pin now use the new commit/tree. Historical reports retain their old pins. `b78bb2a` and `21e822f` are prohibited restore destinations. The new validator distinguishes authorized supersession, unknown/unrelated commits, wrong trees, tracked changes, active/unknown writer flags, root/unsafe indexes and mutation during observation. A previously changed index is accepted only when the new exact commit/tree/authorized path set matches and its own before/after identity is stable.

`V11_BASELINE_SUPERSESSION_2026-10-02.json` contains the four exact GitHub blob and SHA-256 pins. Each GitHub blob was independently recomputed from local file bytes. PR #68 does not authorize RC5 startup.

## RC5 gates

The original PR #68 test module was run unchanged from an isolated Git archive; all 35 no-argument test functions passed, with no pytest dependency installation. It checks the actual shell implementation, including content-free reason codes and outer rollback behavior.

The new V11 aggregate gate admits only all-zero Owner binding, provider reservation, provider lease and delivered-update counts. Heartbeat must be changed and strictly parseable within the recorded start/end window. Transport classification admits zero or one DNS-matching IPv4 Telegram HTTPS socket; unknown, multiple, non-HTTPS and probe failures refuse. It returns aggregate counts/classification only, never endpoint values. Legacy zero-established-socket policy is rejected. The result is a point-in-time transport classification, NOT proof of no egress. The gate grants no RC5 start authority. Its common host invocation remains unbound while the overall production adapter is incomplete.

## Concrete recovery blocker

An additional failure injection called the actual Guard adapter with a journal that persists GUARD_CUTOVER/sealed=true and then raises a simulated coordinator crash. Only the read-only systemd show was reached: neither timer stop nor consumer replacement had happened. This is an offline call trace, not a real reboot or production mutation.

At that point the old enabled timer and old consumer may still exist. The standalone adapter has no persistent boot inhibition, and the shared production watchdog/boot-order binding is not implemented. Thus a durable sealed marker alone cannot prevent the old root guard from executing after reboot. This is a concrete missing recovery guarantee, not a Docs authority or Control-source ambiguity. The existing post-seal `recover()` timer-stop path does not establish reboot ordering by itself.

The overall acceptance gate is NO_GO_RECOVERY_COMPOSITION_UNPROVEN. Passing component tests must not override this gate. Before admitting a transaction, the implementation needs a root-owned persistent boot/start fence and independent recovery entry ordered ahead of the old guard, verified installed payloads and loaded units, durable ownership receipts, and exhaustive crashes around fence installation/barrier publication/consumer swap/unfencing. After the barrier the old mutable guard must never be re-enabled. No live experiment is authorized to fill this proof gap.

## All-phase integration status

| Phase | Concrete prepared component/path | Current integration status |
|---|---|---|
| Independent watchdog | V11 coordinator and bootstrap watchdog decisions; root transaction under `/var/lib/tu1nz-privileged-v11-*` | Production recovery dispatcher and reboot ordering unproven; blocks common transaction |
| Journal / backup | `privileged_v11_offline/transaction_v11.py`, durable state/lock; Guard file receipts | Component tested; shared cross-phase backup/restore binding incomplete |
| Dedicated Control | `/opt/tu1nz_repos/control-deployment-v11-candidate`, chatops Git reader, e60aa2f/tree pin | Fixed command adapter updated; full file backend/consumer migration incomplete |
| Docs authority | `/etc/tu1nz/docs-authority-v11/authority.json`, root:root 0600 | Independent source closed, exact candidate already prepared; no installation |
| Delete Guard | `/usr/local/libexec/tu1nz-docs-authority-v11/guard.py`, service drop-in | Concrete adapter/file backend tested; crash-to-reboot fence missing |
| Checksum | `/usr/local/bin/checksum_verify` reads protected status | Concrete payload tested; depends on guarded cutover |
| emoji map | Versioned `v11_authority/emoji_map.sed`, sealed program descriptor primitive | Source/primitive tested; common installation/consumer binding incomplete |
| Mommyramona | `V11_FINAL_NETWORK_CONTRACT.json`, fixed container and two existing networks | Case-A contract/evidence retained; common production lifecycle and recovery incomplete |
| Agentmode | `tu1nz_agentmode.service`, fixed adapter and recovery claim protocol | Components tested; complete root prologue/host wiring incomplete; no restart |
| Broker / bootstrap | `/usr/local/sbin/tu1nz-codex-ops-v11`, fixed diagnostics; isolated bundle publisher | Components tested; full common installation binding incomplete |
| sudo / Docker paths | `/etc/sudoers*`, `/etc/group`, `/etc/gshadow`, `/run/docker.sock` | Four protected originals still missing; no group, socket or sudo change |
| Trendwatch hardening | Fixed script candidate and four unit drop-ins | Transformations tested; common installer/consumer ordering incomplete |
| Token rotation | Credential candidate and durable forward-only journal | No provider action; common handoff/reload/recovery binding incomplete |
| Final checks | Existing fixed checks and new RC5 gates | Not an end-to-end host proof; no live execution |

No phase is represented as complete solely because an abstract fixture phase passed. The complete host transaction requested by this work is NOT finished. The four protected inputs are therefore NOT the only remaining gate, and a sudo-readiness request would be premature.

## Boundaries and validation

Before a verified security cutover, restore only transaction-owned postimages against saved originals, refusing foreign drift. Atomic replacements can restore bytes/ownership/mode/ACL/timestamps but not inode/ctime identity. After Guard/Docker authority barriers use forward repair or SECURED_STOP, never recreate old unsafe authority. Provider handoff is a separate forward-only barrier; never restore the exposed credential. These remain required boundaries, not a claim of completed common host implementation.

The initial isolated clone inherited private umask 077 and failed workflow 100's unchanged executable-mode check (0700 vs 0755). Only the temporary clone was normalized from Git modes; the corrected harness uses explicit fixture umask. Historical worktree/live modes and security expectations were untouched. Final rerun from step 1 passed 726 targeted tests (704 existing +22 new) and all 108 workflow steps. Two optional application simulations remain skipped: the paired application checkout is absent both in canonical repository and worktree locations. PR #68 additionally passed 35 tests.

Private manifests and test logs remain under `/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-host-20261002`. The JSON companion pins the final run, original PR tests and crash trace. Backups of each changed existing source/contract precede edits. All 42 Hardening files, 701 historical tracked files, 1,125 private evidence files and 30 V9 sources remain byte-identical; `1cf0d79` remains an ancestor. Docs authority, historical manifests and Docs index are unchanged.

The four-file collector remains byte-bound to `ad5a22e16f305a38183378bf5ea45c809d0bd1c3ca5c3f31423deb379dbb9017` and has not run. It will not be requested until the other integration gates close. Production timers, Guard, Agentmode, Trendwatch/token, Mommyramona, MyChatBuddy, Docker socket/groups, networks, firewall, SSH and Tailscale were not changed by this work. No fresh comprehensive live-health claim is made from offline tests.
