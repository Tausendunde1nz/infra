# ACL security fix: preparation only, live application locked

## Decision and preserved integration

The user authorized read-only investigation and offline preparation, not live permission changes while away. Integration commit `1cf0d797ab025fb08466b92aed156ca5d7d63035` remains in branch history. All42 original hardening files were compared against `integration-20260927T055938Z/baseline.json` and remain byte-identical. The canonical detached checkout is not changed. No Tailnet/Hetzner/SSH change, restart, deployment, notification, live chmod or live setfacl is part of this work.

Status: **NO-GO for live ACL changes**. This is not a completed production plan. Complete metadata/dependency visibility and real-identity fixture tests still require privileged read-only access. An incomplete inventory must never be presented as a complete rollback backup.

## Evidence and coverage

Protected server evidence: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/acl-security-preparation-20260927T061834Z/`.

- `metadata.jsonl`:86013 visible entries, numeric modes/types, owners/groups, inode/device and symlink targets; no file contents.
- `metadata.acl`: recursive numeric Access/Default ACL snapshot, preserving getfacl restore format. `acl-errors.txt` and `inventory-status.json` explicitly retain25 inaccessible subtrees; getfacl exit1. Not a complete live backup, and no blanket restore is authorized.
- `effective-group-write.json`:2760 visible entries have actual writable group ACL entries after applying the Access ACL mask. The group-mode bit alone is not used as proof because a mask can also represent named-user rights.
- `references.json`:96 matching source/configuration files;27 reference read errors. References include scripts, systemd definitions, logrotate/tmpfiles and canonical repository material; line numbers/path references only, no sensitive source lines.
- `units.json`:71 relevant loaded services/timers with configured User/Group/SupplementaryGroups/UMask, executables, directory boundaries and activation relationships. This is not proof that all installed or indirect units have been covered.
- `container-mounts.json`:no direct source mounts under the two prefixes in current Docker inspect results. Ancestor mounts, alternative resolved paths and indirect namespace usage need the privileged/full mount review; no universal absence assertion.
- `open-files.json`:no visible matching open descriptors in this snapshot;208 permission-denied process inspections. Absence of visible FDs is NOT evidence of no writer, especially for short-lived timers.
- `groups.json`:NSS primary and supplementary membership. Visible GIDs:0 root(root),4 adm(syslog/netdata/chatops supplementary),33 www-data(www-data),985 tu1nz-adult-s1(tu1nz-adult-s1),1001 chatops(chatops),10001 tu1nz-mychatbuddy(tu1nz-mychatbuddy). Actual runtime supplementary groups still require complete process evidence.
- `SHA256.json`:protected evidence checksums. Live logs may change while captured; no claim of an atomic full-tree snapshot.

## Confirmed dependencies and unresolved writers

The visible Agentmode observer, integrity consolidation and monitor wrapper use User/Group chatops and UMask0027. Their state directory is owned by chatops and accessible by owner permissions; the health directory is also chatops-owned. Those identities do not require additional group-write permission for these owner-writable targets.

The wider trees include root-owned records, staging-s1 UID996/GID985, MyChatBuddy UID10001, www-data UID33 and root:adm logs. Root-owned group-writable backup-integrity, historical processed trendwatch records and security/activation logs are present. It is NOT established that every necessary write happens as the owner chatops. The encrypted backup and security audit service use root; other timers and wrappers may perform short-lived or delegated writes. Owner/ACL data alone cannot prove group-write is dispensable everywhere.

Protected paths include backup-integrity rollback directories, staging-s0-commercial, staging-s1/media, MyChatBuddy state and multiple approval/recovery trees. Their purpose and dependent service identities must be reviewed before any rights plan includes their ancestors. Do not change ownership, remove named service ACLs, or recursively normalize either tree.

## Existing focused findings and inheritance

Previous `acl-diagnosis-20260927T060402Z` preserves full focused parent/target ACLs and actual controlled test runs:

- Productive Agentmode state directory2750, its four status files0640, runtime directory0750 and lock files0640.
- Installed observer script root:root0755, byte-equal to current control-main and worktree source.
- Productive health directory2775 chatops:chatops with group::rwx; its log file0640 can still be replaced through directory write/search rights.
- Parent `/var/lib/tausendunde1nz`2775, named group1001:rwx with maskrwx. Its state child is more restrictive but the parent permits entry replacement to that group.
- Groupchatops currently contains only chatops; no visible non-root/non-chatops process with that group was found in the focused scan. This limits current exposure but is not an approved exemption from the strict rights requirement.
- The unchanged Agentmode test creates a missing state directory via the production script's `umask0027; mkdir -p`. Inherited Default ACL produces0770 and the test fails; in a verified ACL-free isolated directory it produces0750 and the same test passes. Generated files remain0640 due to explicit chmod. No test expectation was weakened.

## Target-state constraints, not an approved target list

After dependencies are complete, select each affected path explicitly and pin its inode/device, owner/group, mode and full ACL. Preserve required traversal/read access for confirmed identities. Remove effective group-write only from confirmed security state/Agentmode/health entries; resolve owner-vs-group writers first. Keep setgid and ownership only if an actual inheritance/dependency requirement is documented. Defaults must reproduce intended restrictive rights for every actual creator identity. A mask-only change can also remove necessary named-user rights, so it cannot be applied indiscriminately. The0750 directory and0640-or-stricter status-file requirements remain intact.

No finalized live path list or ACL candidate has been approved in this preparation. The empty live plan is intentional.

## Offline transaction mechanism and tests

`scripts/tu1nz_acl_metadata_transaction.py` implements exact per-target before/after metadata comparison, new0600 checksum-bound backup, no chown/content rewrite, idempotence, immediate postcheck and automatic exact metadata rollback on injected failure. It accepts only marked isolated fixtures in its reviewed test interface. Its live entry point always refuses; `LIVE_PLAN_SHA256` remains unset. This is an offline prototype, not a production-ready activator: live concurrent-writer coordination and privileged multi-identity validation are pending.

Eight offline unit tests passed on the server as chatops in private synthetic fixtures:
1. Apply, idempotent second application and exact ACL/mode/identity rollback.
2. Injected failure after mutation restores original metadata.
3. Baseline drift refuses any mutation.
4. Tampered backup checksum rejects rollback.
5. Ownership/identity changes rejected.
6. Live invocation refused.
7. Symlink target rejected.
8. Synthetic log append/status write and new file/directory inheritance yield0640/0750.

These are not claimed as tests of all production users or a complete clone of86013+ entries. Such a clone requires the missing privileged metadata and isolated owner/group setup. The original Agentmode assertion remains unchanged and its inherited-ACL/ACL-free comparison is retained. The full repository suite remains gated by the unresolved rights finding, not marked passed.

## Next single sudo command: read-only prerequisite only

Do not run until Daniel explicitly says: **Ich bin am MacBook bereit.**

```sh
sudo python3 /opt/tu1nz_repos/worktrees/network-hardening-2026-09-22/scripts/tu1nz_acl_privileged_inventory.py --collect-only
```

Reviewed inventory-helper SHA256:`c05017023a7a7af04a5bf27eb5dfbb5f9d6924abbf082c9b53585f83a7a0fdf3`.

This command only reads both metadata trees, full ACLs, group membership, process identities/open descriptors, installed units, bounded script/config references and Docker mounts. It writes a fresh protected evidence directory. It never changes production metadata, executes a service, sends a notification or activates the transaction. New evidence files alone are assigned to chatops with0600 permissions in a0700 directory. It deliberately returns `dependency_analysis_complete:false` and `live_activation_authorized:false`; readable metadata does not automatically prove a safe live plan.

A single live-application command cannot safely be finalized before these missing prerequisites are reviewed. The eventual combined sudo transaction must pin the complete reviewed baseline/candidate and include all real-user fixture tests, application, immediate service/monitoring/SSH checks and rollback. Do not reinterpret `--collect-only` as live authorization or silently append an apply step. No personal input is requested while Daniel is absent.

## Required later acceptance and rollback

Before live change: complete metadata snapshot plus numeric ownership/modes/ACLs, metadata-only mirror retaining relevant identities, per-user/group write/read/creation tests including timer writers, exact original metadata restore and Agentmode strict test. Protect backups outside changed trees; verify hashes and private permissions. Abort on baseline/concurrent path drift. Use a literal allowlist; never recursive chmod/setfacl.

After authorized live application: verify exact approved Access/Default ACLs/modes and creation behavior, owner/group/setgid justification, systemd service/timer results, monitoring targets, SSH22/2222 and existing user denials without modifying security configuration. Run every current control-validation workflow step, documentation/offline hardening tests and repository consistency checks. Only then prepare PR against currentcontrol-main and require all CI before merge. Preserve1cf0d79, all42 original files and complete historical rollback evidence. The Bot follow-up remains separate and cannot start its privileged/live work without availability confirmation.
