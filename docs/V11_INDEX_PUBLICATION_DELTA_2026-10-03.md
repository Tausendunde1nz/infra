# V11 index admission and publication replay delta — 2026-10-03

Parent Infra: `b5029288547d29d897861638bdb46cde958f2063`.
Status: **LIVE_NO_GO; offline implementation still incomplete**. No PR or merge.

## Index and adopted Control basis

Case A: Git 2.43.0 with umask 0002 reproduced a 0600 → 0664 index
refresh and inode replacement with unchanged staged semantics in an isolated
repository. The historical actor remains unattributed. The live index content
matched the protected 03:24:52Z evidence. Its group has only chatops; there was
no independent non-root writer, index lock, or active Git/sync writer observed.
The parent has no default ACL. Known Control readers use GIT_OPTIONAL_LOCKS=0;
the legacy bot sync unit cannot write the Control path through its sandbox.
All further Git reads used GIT_OPTIONAL_LOCKS=0.

Authorized single-file correction via an O_NOFOLLOW descriptor and component-by-
component parent walk: 0664 → 0600. SHA-256, semantic entries, UID/GID and inode
1460707 remained unchanged. No additional ACL exists. Read-only git status caused
no mutation; a monotonic 31-second check and the later suite-end check passed.
SHA-256: `2af9ed310910d3c5aed48f274e2ff3d2b2074a3c7af624945b5be0207b47c36c`.
Private original bytes, metadata and conditional rollback are retained at
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-index-normalization-20261003T032918Z`.
Rollback restores mode/ACL semantics; ctime cannot be reset by chmod.

Adopted Control: `c13358d9adaf783f42feb5c627b6f12825f5805e`.
Tree: `371d099af59b965b6722712bfc820a91ebbb2e04`.
Signed GitHub merge PR72; predecessor/merge-base
`05b127033d734aa4abce10b2e5b7d513b99ed5d2`; ahead 3, behind 0.
Exactly the repair script, its tests and its RC5 plan changed. Regular-file
nlink=1 remains enforced; directory identity no longer wrongly requires nlink=1.
Git blobs and SHA-256 values passed the existing forward-adoption contract.
Activation remains unfrozen until the dedicated deployment and live-window checks.

## Material offline implementation

New fixed-scope publication engine: immutable hash-linked rescue generations,
exclusive lock, original-byte/metadata backup, file-publication receipts,
manager phase intents/completions, restartable preseal restoration, terminal
reverification and fail-closed postseal handling. The manager used in these tests
is a strict persistent **model**, not the actual systemd manager.

The existing file backend now preserves the exact preimage of an interrupted
restore and can remove inode/hash-bound unpublished staging files. Cleanup can
resume after its declared directories were already removed. Foreign postimages
remain errors. Files retain their original content/owner/mode/ACL/time semantics;
atomic replacement cannot recreate original inode or ctime.

A separate pure recovery-routing contract tests coordinator lease, monotonic
expiry, reboot, foreign binding, terminal verification and postseal refusal.
It is not yet connected to the installed watchdog. The previous watchdog's
unconditional worker start must not be armed during an active coordinator lease.

## Aggregated verification

- 2,354 targeted tests passed, including 190 dispatcher/publication/routing tests.
- All 108 workflow steps passed (585 reported test cases; two Application skips).
  Both required Application checkout locations remained absent.
- Original PR68: 35; original PR69: 7; PR72: 10 tests passed.
- Governance preflight active; eight Control governance checks passed.
- 42 Hardening files, 701 historical tracked files, 1,125 protected evidence files
  and 30 V9 sources matched their recorded hashes. `1cf0d79` remains an ancestor.
- Production Control tracked content/HEAD and the corrected index remained stable.
  No service, container, unit, token, network, firewall, SSH or Tailscale changes.

Source backups, adoption record and compressed validation summary:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-installer-20261003T033021Z`.
The full clone run was `/tmp/tu1nz-installer-suite-jc6eiida`; private checksums bind
its aggregate result. Private backups and raw logs are not committed.

## Remaining implementation — not merely a missing root permission

The installed installer entry remains refusal-only. The new publication engine
explicitly rejects production/root use. Bootstrap preflight before directory
creation, root-owned self-contained rescue entry, real loaded-systemd adapter,
watchdog lease routing, outer fence/inner recovery integration and the single
nonactivating root validation launcher are **not complete**. The shared recovery
anchor must survive rollback of its published payloads. Successful model tests
must not be substituted for these remaining implementations or root validation.

No MacBook readiness or sudo request is justified yet. No live admission flag was
changed. This delta records a tested intermediate state, not completion of V11.
