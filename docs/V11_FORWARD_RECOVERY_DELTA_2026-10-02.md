# V11 forward basis and pre-seal recovery delta — 2026-10-02

Status: **LIVE_NO_GO**. Offline branch preparation only; no PR, activation,
root execution, protected-input collection or production service operation.
Parent: `64b250b369828d02e888ec8c9b751f1200b5c03f`.

## Confirmed basis and provenance

- Control `05b127033d734aa4abce10b2e5b7d513b99ed5d2`, tree
  `5459b09c4f986ac947dff1466b490a61238cb676`; GitHub verified merge PR69.
- Predecessor/merge-base `e60aa2f515c89f94bce1dbd6496d358cdfb85300`;
  ahead 11, behind 0; exactly the seven approved paths. All seven Git blobs
  and SHA-256 values independently matched; all 190 tracked production files matched.
- “Linear” means ancestry-preserving forward movement here: merges exist.
  The history is not single-parent. Individual unsigned commits are not described
  as signed; the verified GitHub merge anchors the reviewed tree.
- **Ref distinction:** Control uses `main` (no `control-main` ref); Infra uses
  `control-main` (observed `fbb7ea6d5854348567af133d0661aa87a4164843`).
  The new freeze contract binds both refs separately; it never substitutes one
  repository for the other.
- Production index: uid/gid 1001, 0600, regular/nlink 1, inode 1460594;
  SHA-256 `7c5fd653decbfa3a3c89ad00662245ea0147c51e93c7b1a20cb825d6c86cced3`.
  No active targeted writer or Git lock found. Existing ignored-path classification
  retained: 99 entries, no new unclassified entry; 17 protected historical entries
  were not reopened. No fresh protected-content attestation is claimed.

## Material implementation

- Updated current baseline, Docs deployment candidate and Agentmode basis pins;
  historical reports unchanged. Forward-adoption validation requires verified API
  provenance, exact changed blobs, tracked/index/writer integrity and delta tests.
  It is an offline validator, not a newly installed automatic fetch service.
- Activation freeze requires a dedicated deployment checkout, both current refs,
  transaction, boot and monotonic freshness. Ref drift invalidates the activation
  manifest rather than rewriting historical evidence. No activation manifest issued.
- Hash-bound governance regression check covers the reviewed four documents:
  v1.1 operative authority, no micro-gates, unchanged safety/rollback/No-Delete/VPN/
  secret boundaries and evidence compression with failure/evidence exceptions.
- File rollback now durably identifies staged inodes before rename, resumes a crash
  around timestamp restoration, publishes directories with RENAME_NOREPLACE and
  rejects foreign same-byte replacements. Scope-limited restore retains all receipts.
- New immutable pre-seal journal and inhibit marker enforce exclusive recovery and
  ordered intent/verification records. Host receipt generations bind the transaction
  and previous hash. **Production admission is explicitly false.**

## Recovery boundary / reason for stopping

The candidate pre-seal host is unfinished and unreachable through its closed
admission gate. Removing its own program/units or disabling its own watchdog during
cleanup can prevent recovery after a crash. Removing the fence before a later
cleanup failure also needs a proven re-fencing path; stopping the timer alone does
not block manual unit starts. An independent persistent outer dispatcher, replay
hydration of saved receipts and its bounded systemd write permissions remain unbound.

Thus the requested full real-host pre-seal crash/reboot matrix is **not complete**.
The new 11 journal/admission tests and six real isolated filesystem tests do not
claim that proof. The existing 1,160 fault-label coordinator cases remain model
cases, not 1,160 production reboots. Post-seal remains forward repair or secured stop.
No admission constant may be enabled on the strength of this report.

PR69's original repair passed all seven Linux tests, including actual ACL and
retained-descriptor checks. Its in-process `/proc/.../fd` checkpoints alone are not
cross-boot recovery. Its durable V11 outer checkpoint and own pre-RC5 phase remain
pending behind this boundary; it is not represented as fully integrated.
Subsequent common-transaction phases were not skipped or declared ready.

## Aggregated validation and preservation

- **1,979 targeted tests PASS** (all prior 1,945 plus 34 new).
- **108/108 workflow steps PASS**; two optional Application checks skipped because
  both expected Application checkouts remain absent.
- Original PR68 **35/35**, original PR69 **7/7**, zero skips; unchanged zero-argument
  tests executed on Linux. Missing pytest-skip prerequisites were treated as failure.
- Governance **8/8** positive assertions and **5/5** rejection cases.
- 42 Hardening files, 701 historical tracked baseline files, 1,125 private evidence
  hashes and 30 V9 sources byte-identical; `1cf0d79` remains an ancestor.
- Existing tracked documentation unchanged; production Control HEAD/index/tracked
  bytes, Docs index and approved Docs authority unchanged.
- All tested implementation bytes match the worktree. Aggregate source-map SHA-256:
  `13eb8b588a7f984696dee4faf998bf52140e2993607af1230727d0d305271b7d`.
- Aggregate suite-result SHA-256: `ba6c53ed3ecf85207572eaf8e85e71f77beaf401a8636a61c6ddc7346cf97d72`.

Backups, source pins and compact results:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-forward-20261002T183413Z` (private, not committed).
Offline rollback is restoration of the backed-up current sources or reverting this
commit; it requires no service operation. Historical evidence is never rewritten.

No sudoers/gshadow read; no token, root watchdog, service, Container, network,
firewall, SSH or Tailscale change. No fresh full live-health inventory is claimed.
Next required work is the independent recovery lifetime/re-fencing adapter and its
crash proof. **No unavoidable user intervention yet**: do not request MacBook
readiness until the protected collection is genuinely the sole remaining input.
