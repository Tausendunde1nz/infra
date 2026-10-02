# V11 bounded root read: completed, no activation

Preparation commit: `9976a36f5246371efd2cfc12551c736b41573e25`.
Daniel confirmed current MacBook availability. Exactly one checksum-bound sudo
collector ran, exit 0. No repeated privileged query or live activation followed.
Root-owned verified copy SHA-256:
`f5bb206c458cfca5375ad7ffca79e31980225b176907b5eae9f6e9969e9de140`.

## Evidence and validation

Root evidence: `/var/lib/tu1nz-v11-untracked-evidence-zmagu4ae`.
Manifest SHA-256: `b5353fe3fa55670b5e0096dc7374c98092678168fe4c1fd8058b6110bbd5666e`.
All 31 sections OK; COMPLETE, no timeout, exception or interruption.
All exported section hashes matched the manifest; files root:chatops 0640.
The protected originals and prior preparation/result documents remain unchanged.
Private verified copies are under the existing private evidence directory's
`root-result-zmagu4ae` child, mode 0700, files 0600. No source contents exported.

Full merged 99-entry classification: `V11_UNTRACKED_ROOT_RESULT_2026-10-02.json`.
Its SHA-256 is `57549682f47c34e604cf54d255ef19f313b76421184a193e6857cac46528cb39`.
The earlier nonprivileged JSON remains an immutable historical snapshot.
All 99 entries now have leaf metadata; 87 have hashes. Twelve runtime/status entries
remain deliberately unhashed, including the empty historical token-rotation lock.
All leaves are regular files. Ignore-rule provenance remains the reviewed snapshot.

## Final dimensions

- TRACKED_INTEGRITY: **PASS**, 186 entries at trusted forward commit 21e822f.
- UNTRACKED_IMPACT: **SECURITY_RELEVANT**; 89 BENIGN, nine EXECUTION_RELEVANT,
  one SECURITY_RELEVANT, zero UNKNOWN metadata classifications.
- CHECKOUT_CONTRACT: **UNPROVEN**.
- Overall: **CHECKOUT_CONTRACT_UNPROVEN**.

These labels do not mean an active attack or blanket checkout drift. Negative checks
are bounded to reviewed reference paths, not proof against any possible manual or
dynamically constructed invocation. No baseline repin or production migration occurs.

## Findings completed by root visibility

The 17 Incident entries are root:root, regular, no POSIX ACL: evidence/lock/backups
0600 and five historical Python tools 0700, inside root:root 0700. Twelve are retained
operator evidence/runtime state; five tools remain EXECUTION_RELEVANT because they
can be manually invoked. No reviewed live unit/helper/cron points at them. Their
contents were only hashed, never displayed or executed. The previously inaccessible
orphan cache is root:chatops 0600 and now hash-verified; no import was attempted.

Caution: the Incident parent `analysis` is chatops:chatops 2775. A writable ancestor
allows renaming/replacing its root-owned child; root ownership of leaf files alone
is not an immutable execution boundary. This is a conditional future root-execution
risk, not evidence that replacement or execution happened. Future privileged use
must pin reviewed bytes into a root-controlled directory and verify there first.
No permissions or existing paths were changed.

Both /proc snapshots had complete visibility and no checkout CWD or writable FD.
The empty historical lock does not establish a running transaction; snapshots cannot
exclude every transient event between scans. No ACTIVE_WRITER claim is warranted.

Four protected installed helpers and both protected nginx files have no literal
checkout, known-name or pandoc_safe references. Both nginx paths were ordinary files
with distinct hashes; no symlink assumption is required. Crontab inventory contains
chatops and a historical chatops backup, no root crontab. The only checkout match is
a comment in chatops's file, not an executable line. No cron was created or changed.
Root/system Git settings show no selected executing hook/filter/include setting and
no safe.directory wildcard or exact checkout grant. Git configuration was not executed.
These settings do not establish the deployment ownership contract.

## Execution paths and remaining contract

Previously proven references remain: pandoc_safe -> emoji_map.sed (sed program input),
checksum_verify -> checksums_reference/current (data), delete_guard -> _filelist_reference
(security baseline). The legacy encrypted_drive_backup is executable without a found
active caller. The five historical Incident tools are potentially manual executables.
No new active execution path was found. Cache, copied units and cAdvisor read-only
visibility are not treated as automatic execution.

The documented target is chatops-owned Control deployment, but that decision states
not activated. Actual detached Control files share Git storage with Infra authoring
worktrees and origin points to Infra. A complete current operative publishing/ownership
contract is still not evidenced. safe.directory settings cannot resolve this discrepancy.
No broad historical search, remote rewrite, permission normalization or cleanup follows.
The conditional prerequisite for accepting all extras as controlled operational state
has not been established, so V11 baseline/adapters are not silently advanced.

## Minimal reversible plan, offline only

Keep all existing files. Do not rerun the historical Incident tools or backup script.
For any future required privileged tool, review/version exact bytes, copy to a new
root-controlled location, verify SHA before execution, and switch only a proven caller
in a separately authorized transaction. Do not use the chatops-writable ancestor as
root authority. For guard/checksum baselines, establish their authoritative producer
and consumer first; version an approved baseline and stage a separate hash-bound copy
before any caller cutover. Retain old bytes, metadata and evidence; rollback must not
reactivate an untrusted privileged path. The sed-map-specific plan remains unchanged.

The existing isolated copy/rollback test covers new-candidate creation, exact hash,
original preservation and removal only of its own matching candidate. This is not a
claim of a tested live consumer migration. No executable remediation launcher is added.
A publishing-contract decision and actual caller requirements are needed before any
live remediation can be proposed concretely; another root inventory is not requested.

## Tests and invariants

Prepared code is unchanged from 9976a36: 594 targeted tests and all 108 workflow blocks
passed there (existing optional source skips remain skips). This result-only delta
adds no executable logic; the 40 collector tests are rerun, plus manifest/hash/99-entry
schema/count checks. Original 701-file baseline, 42 hardening files, 1,125 historical
files and 30 V9 sources remain checksum-preserved; 1cf0d79 stays in ancestry.
Production HEAD/index are checked again. Authorized branch commits necessarily add
objects/refs to shared Git storage, not to the detached checkout's HEAD/index/files.

No Agentmode start, token rotation, service/container/network change, firewall/SSH/
Tailscale change, permission/ACL correction, cleanup, watchdog, PR or merge.
Only private evidence output and repository result documentation were written.
