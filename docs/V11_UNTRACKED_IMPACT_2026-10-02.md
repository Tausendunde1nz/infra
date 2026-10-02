# V11 untracked impact: separate integrity, effect and ownership — 2026-10-02

Infra base: `dd5e11d6776c1ca3c05c9a6b2c5b542949a97c9e`.
GOVERNANCE_V1_1_ACTIVE. No live activation or cleanup. This delta supersedes the
previous blanket treatment of additional ignored entries as full checkout drift.

## Three independent dimensions

| Dimension | Current result | Scope |
| --- | --- | --- |
| TRACKED_INTEGRITY | PASS | Fresh byte/index/tree verification of all 186 tracked entries at 21e822f |
| UNTRACKED_IMPACT | SECURITY_RELEVANT | One guard baseline; four execution-relevant entries; 17 still UNKNOWN; not a claim of active exploitation |
| CHECKOUT_CONTRACT | UNPROVEN | Documented chatops/Control target, shared Infra Git storage and current origin need an explicit operative contract |

Overall: **CHECKOUT_CONTRACT_UNPROVEN**. There is no newly proven active execution
shadow attack. The mere existence of ignored runtime/cache files is not a LIVE_NO_GO
reason. V11 is not activated because bounded evidence and production integration are
still incomplete, not because every untracked file must disappear.

Full individual classification of **all 99 paths**, with per-file lstat metadata,
ACLs, available SHA-256, exact check-ignore source/rule, category, reason and known
references, is in `V11_UNTRACKED_IMPACT_2026-10-02.json`. Inaccessible fields are null
with explicit reasons; unknown is not recoded as benign. This is the nonprivileged
snapshot and must be supplemented by the pending bounded root results.

Current provisional counts: **77 BENIGN, 4 EXECUTION_RELEVANT, 1 SECURITY_RELEVANT,
17 UNKNOWN**. 82 leaf metadata records were readable; 70 regular-file hashes were
obtained. Eleven potentially active runtime/status files were deliberately not opened
for hashing. One regular cache file needs privileged reading; 17 Incident paths need
protected-parent traversal. There were no symlinks/special files among the 82 observed
leaves. No inaccessible leaf type is guessed.

## The moving but trusted RC5 snapshot

The initial assertion against b78bb2a encountered a newer HEAD, not corrupt contents.
GitHub Control comparison verifies PR #67: `21e822f8cadecf5eb186693d1ceac2d5d0bf6969`
is two commits ahead of b78bb2a, zero behind, merge base exactly b78bb2a. The three
changed paths are the RC5 controlled-start helper, its tests and its plan. No actor
forensics or reset was performed. Fresh isolated Git reads prove local commit/tree/index
and all 186 tracked entries match tree `28715cc0b6eaa4ab5c17fd659fffbd1afbacfcc1`.
Index SHA-256: `c383725225e13313986859723a4380c883b0a24326c85b3a76df30852f3e615d`.

The index is now chatops:chatops 0600, inode 1460594. This run did not change it.
The earlier root-owned snapshot remains preserved. Production baseline assumptions in
V11 are not silently repinned; the newly observed snapshot is recorded separately.
The old broad root attestor could not run as chatops because it traverses the protected
untracked Incident directory. A tracked-only comparison was used instead; no security
assertion or test was weakened. Private failed-attempt directories remain preserved.

## Ignore, execution and import evidence

All 99 entries match the committed `.gitignore`, line 2, pattern `*`. This is the
documented deny-by-default staging design, not automatic evidence of harmlessness.
check-ignore was run with --no-index -v -z and an isolated minimal Git configuration,
local ignore files and copied info/exclude, GIT_OPTIONAL_LOCKS=0 and neutral globals.
No local hook/filter was invoked and no index update occurred.

- **31 orphan __pycache__ files:** their corresponding .py source files are absent.
  An isolated Python 3.12 regression proves ordinary import refuses a source-less file
  in __pycache__. The production caches were never imported/executed. Explicit loader
  use remains a separate question; reviewed sources showed no direct cache-file loader.
  The installed S11.2 wrapper mentions PYTHONPATH and the S9 health helper uses
  spec_from_file_location; those facts are recorded, not treated as cache execution.
- **16 legacy/systemd unit copies:** every corresponding installed unit name was
  not-found. These copies are outside the default load paths. No PATH symlink into
  the checkout was found. Do not activate, delete or move them.
- **emoji_map.sed:** chatops:chatops 0660; SHA-256
  `eece58840199bb578c97994246d990c9ef842ced06d29c579e5cc42064d6655b`.
  `/usr/local/bin/pandoc_safe:24` loads it using `sed -f`. This is a program/configuration
  input, not an inert log. The reader is root-owned 0755; no current invocation was
  established in readable units, scripts or chatops crontab. Normal pandoc resolves to
  the system binary, not this wrapper. Privileged cron/helper references remain pending.
- **scripts/encrypted_drive_backup:** executable 0755 legacy script. No installed
  PATH link, direct unit or container command reference was observed. It is retained
  as execution-relevant pending the remaining consumer checks, never executed here.
- **_filelist_reference.txt:** literal baseline path in the installed deletion guard
  `/usr/local/bin/tu1nz_delete_guard.sh:10`; security-relevant data, without proof that
  an active unsafe deletion path is running.
- **checksums_reference.txt / checksums_current.txt:** direct data references in
  checksum_verify; the monitor also tests reference-file presence. No evaluation as
  shell/Python source was shown. Baseline authority remains part of the contract.
- Basename matches for last_sync.ok, monitor_last.txt and checksums.txt in the current
  observer/integrity/wrapper are NOT automatically these checkout paths. The current
  defaults write to /var/lib/tausendunde1nz/agentmode and its integrity subdirectory.
- **Historical n8n snapshots:** no readable nginx configuration includes the checkout.
  Two protected tu1nz.conf paths remain in the targeted root reference scan. Contents
  of the snapshots are not displayed or treated as live configuration.
- **Container visibility:** only cAdvisor's read-only host-root mount at /rootfs covers
  the checkout. No container working directory or command referenced the checkout.
  Visibility for monitoring does not imply execution. No container was changed.

The current chatops crontab contains no checkout/known-file reference. Existing public
unit/reference reads were reduced to source path, line, identity/state and matching
technical token; no environment values or commands containing credentials are saved.
Root crontabs and a few inaccessible installed helpers remain bounded unknowns.

## Checkout/ownership contract, proven versus pending

`governance/ssot-decision.md` explicitly describes a chatops:chatops 2770 deployment
checkout of private Tausendunde1nz/control, separate authoring, read-only repository
access and intentionally excluded runtime/legacy/root-protected Incident material.
Its own activation status is "not activated"; it is a target contract, not proof of
which later migration steps were performed. v1.1 supersedes historical micro-approval
language; no new Fertig gate is introduced.

Observed owner/mode now matches chatops for checkout, HEAD, index, config, refs and
objects. Checkout is 2770; .git/refs/objects 2775; config 0664; HEAD/index 0600.
The parent /opt/tu1nz_repos has access/default ACLs; decoded numeric entries and masks
are in the report. The checkout and .git inspected directories have no POSIX ACLs.
No ACL or ownership was removed or changed.

Important mapping: this preparation worktree and the detached deployment checkout
share `/opt/tu1nz_repos/control/.git` as their common Git storage. The preparation's
Gitdir is its worktrees/codex-privileged-ops-2026-09-27 subdirectory. Thus .git contains
legitimate Infra branch/worktree bookkeeping; it is not a proven root-only publisher.
Normal authorized commits to this branch update shared objects/refs, not the production
HEAD, index or working files. No recursive Git metadata rights correction is appropriate.

Origin still points to Tausendunde1nz/infra; inactive branch upstream metadata includes
control-main and the named Infra branches. The production HEAD is detached, so it has
no currently checked-out branch upstream. No fetch or remote/ref rewrite was run.
This transition differs from the documented Control target. Accepting it as an operative
contract or correcting it requires precise follow-up, not automatic normalization.
chatops/system Git settings were parsed without includes; no executing config was used.
Root-global safe.directory/hook-related settings are in the pending bounded read.

## Minimal reversible proposal, no live command

`V11_UNTRACKED_MINIMAL_REMEDIATION_PLAN_2026-10-02.json` addresses the proven sed-map
reference: first establish the actual caller/identity, then version the reviewed map
and stage a hash-verified immutable runtime copy for a separately approved caller
cutover. Preserve the current map and reader with hashes/metadata. Do not delete the
existing file or change shared directory permissions. Candidate copy/rollback has an
isolated regression: original bytes unchanged; only the newly created matching candidate
is removed. This does NOT prove an installed caller migration or authorize any restart.
If a future cutover cannot safely restore authority, keep its caller stopped rather
than automatically reopening an unsafe privileged path. No active exploit is claimed.
Other unreferenced archive/unit/cache entries need no cleanup proposal merely to pass.

## One remaining bounded privileged read

New checksum-bound collector under scripts/v11_untracked_impact is prepared, not run.
It covers exactly 18 protected metadata/hash paths, four identified unreadable helper
reference scans, the two protected nginx references, root/system Git settings and
reference-only scans of direct crontab spool entries (bounded count/size). It checks
checkout CWD/writable FDs before/after. It never reads Approval payloads, tokens for
comparison, databases, container logs or arbitrary journals; no recursive secret search.
A permitted nginx link is recorded and its separately allowlisted target is read in
its own section; other links are rejected. Runtime .lock/.pid data is never opened.

The fresh bootstrap makes a root-owned 0600 script copy, checks SHA-256 before isolated
Python -I -B execution, and creates only a new private evidence directory. Each section
publishes atomically with fsync. Fifteen-second section timeouts, independent errors,
SIGINT/SIGTERM and unexpected exceptions preserve completed results and mark the
manifest INCOMPLETE. Only reduced reports are exported root:chatops 0640, not source
contents or secret values. No service, network, sudo-rule or production change.
After remote verification ask once for “Ich bin am MacBook bereit”; then provide one
read-only sudo command. No Fertig confirmation or repeated sudo individual commands.

## Validation and preservation

All **594 targeted tests** (40 new) and **108 workflow run blocks** passed in an isolated
clone under umask 0022. Existing optional paired-source skips remain skips. Coverage
includes FIFO/large/runtime/hardlink refusal, ACL masks, credential redaction, parent
links, orphan-cache import, real alarm timeout, fake /proc writable-FD flags, partial
and interrupted manifests, atomic output, checksum/owner refusal and isolated rollback.
Test-manifest SHA-256:
`1e33baf98dbf26d336120651ef2ed6051868ec5f87b54e131afd1be90cd9853c`.
Preserved: 701 worktree baseline files, 42 hardening files, 1,125 historical evidence
files and 30 V9 sources; 1cf0d79 remains an ancestor. Original reports are not rewritten.

No Agentmode start, token rotation, chmod/chown/ACL change, checkout cleanup/reset,
container/service change, firewall/Tailscale/SSH change, watchdog, PR or merge was
performed. New files are offline code, tests and reduced documentation only. The
observed RC5 advancement/index ownership change was not performed by this run.
Private evidence: /opt/tu1nz_repos/network-hardening-private-2026-09-22/untracked-impact-20261002T144106Z.
