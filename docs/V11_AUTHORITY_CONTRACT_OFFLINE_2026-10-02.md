# V11 authority contract and bounded offline remediation

Base Infra commit: 104cf4c21a527cfeff7ef9c18ca64626690b2eb9. Governance v1.1.
No new root collection, historical tool execution or production mutation.

## Contract closed; topology migration remains unactivated

The binding machine contract is `scripts/v11_authority/contract.json`; its validator
is `authority.py`. Control PR #67 was freshly checked through GitHub: merged into
`main`, merge SHA **21e822f8cadecf5eb186693d1ceac2d5d0bf6969**, tree
28715cc0b6eaa4ab5c17fd659fffbd1afbacfcc1. This is now the V11 production basis.
b78bb2a is historical and MUST NOT be restored. Historical reports/pins are retained;
`integration.json` explicitly supersedes their current-baseline assumptions rather
than rewriting evidence or silently permitting an old launcher.

Contract classification: **EXPECTED_CHATOPS_CONTROLLED**. Pinned Control provenance,
not Infra origin or object sharing, establishes source authority. Detached operation
is mandatory: no automatic pull, merge or branch switch. Index is regular, single-link,
chatops:chatops 0600; its identity and bytes must match before/after every Git check.
Privileged Git reads use only the closed runuser/chatops argument allowlist, explicit
safe.directory, GIT_OPTIONAL_LOCKS=0, neutral globals and disabled hooks/fsmonitor.
Root must never update Git metadata. The validator rejects a changed index or old pin.

Ist: detached Control bytes are correct, but `.git` is shared with Infra authoring
worktrees and origin points to Infra. Soll: independent Control Gitdir with no shared
alternates, verified pinned merge/tree, chatops-controlled index and explicit consumers.
The offline migration plan stages a **new** candidate checkout/Gitdir, verifies it,
then requires an explicit consumer cutover. It never moves/deletes the current shared
Gitdir, rewrites history or treats origin as implicit publishing authority. This
migration has not run. A correct source pin does not prove all deployment consumers
have been migrated.

## Newly proven active security path

`tu1nz_delete_guard.timer` is enabled/active/waiting and triggers
`tu1nz_delete_guard.service`, which has no User/Group and therefore runs as root.
Observed last trigger: 2026-10-02 05:00:01 UTC; next: 2026-10-03 05:00:00 UTC.
This targeted unit lookup closes a gap in the earlier bounded reference inventory.
Earlier statements that an active guard caller was unproven are superseded here.
There is no evidence of exploitation, but this is an **active vulnerable authority
path**, not merely a dormant executable.

The guard is an alert detector, not a file-deletion executor. It runs `find -L` on
`/opt/tu1nz_repos/docs`, compares `comm -23` against `_filelist_reference.txt`, creates
a baseline through sudo tee if missing/empty, and copies the current list over the
reference after a deletion alert. Producer and consumer are thus the same mutable
legacy guard. A changed/empty reference can suppress meaningful detection; a replaced
path is not protected with O_NOFOLLOW. Root writes through a chatops-controlled path.
The existing data has 1,150 syntactically valid relative names, but no independently
approved authoritative set. Automatically blessing it would preserve the trust flaw.
No exploit was attempted, timer stopped, file changed or reference recreated.

## Ten path decisions

The exact ten-path matrix with original hashes is `integration.json`.

| Path | Proven use and decision |
| --- | --- |
| `_filelist_reference.txt` | Active root guard input/output. Replace self-updating trust with a reviewed versioned reference and root-installed hash-bound copy. Missing/empty/changed input must fail closed; additions/deletions never auto-authorize a new baseline. |
| `emoji_map.sed` | Code loaded by pandoc_safe via sed -f. Six literal substitutions reviewed and preserved byte-exact in version control. No active caller proven. Future consumer uses a verified root-controlled copy and a sealed program descriptor. |
| `checksums_current.txt` | Mutable measurement; legacy checksum_verify hashes the entire file, not embedded target paths. Current monitor consumer runs as chatops. Postpush helper archives the file; it is not its original measurement producer. |
| `checksums_reference.txt` | Authoritative comparison data is currently as mutable as the measurement. Producer/provenance remains unproven. Both files currently have identical hashes and 797 absolute docs paths; equality does not prove on-disk integrity. |
| `TU1NZ_SECURITY_S3_apply_tokens.py` | Dormant historical Incident tool. No found active caller; denied as privileged workflow source, preserved, not run. |
| `TU1NZ_SECURITY_S3_identify.py` | Same explicit deny/preserve policy; distinct original hash retained. |
| `TU1NZ_SECURITY_S3_reapply_bot_b.py` | Same explicit deny/preserve policy; distinct original hash retained. |
| `TU1NZ_SECURITY_S3_send_tests.py` | Same policy; no message or test notification sent. |
| `TU1NZ_SECURITY_S3_validate_tokens.py` | Same policy; no token readout or validation request performed. |
| `scripts/encrypted_drive_backup` | No active direct reference found in reviewed units/cron/PATH/scripts. Static code mentions tar/rclone/find, a backup log and Telegram helper. No obvious secret-named assignment; absence of every possible secret is not claimed. Functional equivalence with current backups is unproven; preserve, never execute or remove. |

Incident tools are under a root-owned 0700 directory but its ancestor is chatops
writable. Root leaf ownership is not an immutable execution boundary. Mere manual
executability is **not** a V11 blocker: the new source validator rejects these paths
and all unversioned checkout paths. Future archive/quarantine must copy exact bytes
and metadata into a new protected evidence location, verify hashes, retain originals
until an explicit cutover/removal decision, and never make the archive executable
through an automatic privileged workflow. Existing 31-section evidence remains intact.

## Implemented offline primitives and their limits

`authority.py` walks parent descriptors with O_NOFOLLOW, rejects writable/foreign
parents and ACLs, checks owner/group/mode/type/link count/size/hash, and compares
before/after inode metadata. Symlinks, FIFO, hardlinks, replacement and oversized
inputs fail closed. Program bytes may be sealed in an anonymous memfd and passed to
sed using a fixed argv, never a shell or mutable pathname reopen.

The strict checksum parser accepts only a complete allowlisted set of relative names,
no options, control characters, traversal, duplicates or unknown paths. Embedded paths
are **never opened or executed**. A separate offline converter accepts only the pinned
legacy file and the exact `/opt/tu1nz_repos/docs/` prefix. It produced a private 797-row
candidate SHA cdd41db69d0a2e5219e934244694b9fef9741b0146461e123ecbea21ec1c8eb4.
This candidate remains **NOT AUTHORITATIVE**, and no private file list was committed.

`offline_transaction.py` is explicitly a **nonroot /tmp rehearsal**, not a production
installer. It checks all payload pins/preconditions before creating its first state,
backs up bytes/metadata, publishes via fsync+atomic rename, excludes concurrent
participants, journals intent before mutation, uses unique IDs and monotone deadlines,
and supports deterministic recovery after crash/timeout/signal/reboot.
Before consumer cutover it restores exact saved file bytes/owner/mode/empty-ACL state.
At the cutover barrier it records forward-only authority: failures yield SECURED_STOP;
old unsafe authority is not restored. External changes during recovery cause refusal.
A completed/rolled-back/stopped state is idempotent; no old transaction is restarted.

`integration.json` pins 21 existing Mommyramona/network, coordinator, bootstrap,
Agentmode, token rotation and forward-recovery components without changing them.
Their existing test suites run alongside the new rehearsal. **Pins and fixture phase
names do not constitute a completed real-host adapter.** No claim is made that the
entire production migration is end-to-end activation-ready. The root-owned independent
watchdog/bundle mechanisms remain the tested existing components; no watchdog ran.

## Backup and rollback boundaries

Private originals (eight currently readable data/consumer files, metadata and ACLs):
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/authority-offline-20261002/originals`.
Only safe regular bounded reads were used; pre/post identity was compared. No tokens
or private raw baselines were committed. Targeted unit/consumer evidence SHA:
32c9567eaf7b92c36851a1d1832f128633eba2d8c1918cfc2a2702538522e649.

Future live installation must stage a new root-controlled immutable version, verify
its content/metadata, back up actual consumers and units, quiesce the proven writer,
and change only explicit consumers atomically under an independently verified watchdog.
Before cutover: remove only own verified candidate and restore own changes. After
security cutover: safe forward repair or stop the consumer; never restart the old
root guard against a mutable authority. Reference updates require reviewed versioned
input, not auto-rebaseline on missing files. The exact authoritative namespace and
reference update producer remain decisions/evidence needed before a real host adapter
can safely implement those operations.

## Validation

Final run: **641 targeted Python tests (47 new), all 108 workflow run blocks passed**.
Two existing optional paired-application tests skipped; no skip counted as application
validation. Full run repeated after final deadline/conversion changes. Test manifest:
`ff1822840e6eb989b67f70b692e310ae5f94c3e3099ded2ab44cf6f69d8bab37`.
Evidence: `authority-offline-20261002/final` under the established private root.
New tests cover owner/mode/ACL/link/hash/parent refusal, source deny rules, byte-pinned
sed, strict parsing, legacy-prefix conversion, all declared crash/signal/timeout/reboot
boundaries, concurrent start, recovery foreign writer, order and completion gates.

Preservation checks cover 701 baseline files, 42 hardening files, 1,125 historical
files, 30 V9 sources and ancestor 1cf0d79. The result manifest pins all six new module
files. Existing production HEAD/index/tracked bytes are rechecked without modification.
Shared Git object/ref updates from the authorized Infra commit are distinguished from
production working files and index changes.

## Remaining concrete gates; no new root inventory

1. Active root delete guard must receive a separately authorized safe consumer/timer
   cutover. It cannot be safely corrected by relabeling the checkout or blessing its
   self-updating 1,150-entry reference.
2. Establish the reviewed protected docs set and reference update producer. The
   checksum reference's original producer is unproven; its 797 values cannot become
   authority merely by copying/hashing them.
3. Complete real-host adapter composition only against those fixed authority decisions,
   then verify isolated end-to-end consumer behavior and independent watchdog recovery.
4. Dedicated Control Gitdir and all other live V11 phases remain unactivated; current
   Agentmode/token-provider recovery prerequisites remain required.

No readiness prompt or sudo command is issued: this is not yet a complete live bundle.
No Agentmode restart, token rotation, historical tool execution, rights/ACL/ownership
change, cleanup, Gitdir/origin/checkout migration, service/container/network/firewall/
SSH/Tailscale change, watchdog activation, PR or merge took place.
