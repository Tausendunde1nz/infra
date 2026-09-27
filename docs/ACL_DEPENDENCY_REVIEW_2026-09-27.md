# ACL dependency review — 2026-09-27

Status: NO-GO for live ACL activation. No production metadata, service, network policy, firewall, or SSH configuration changed. The transaction CLI remains LIVE_LOCKED. No test requirement was relaxed.

## Evidence

Privileged read-only inventory: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/acl-privileged-20260927T063114Z`.
87,526 metadata entries; no walk errors; recursive numeric ACL capture returned zero; process visibility reported no errors. All 11 artifact hashes in its manifest verified. This is a sequential, non-atomic snapshot, not a proof that no later changes occurred.

The first systemd query stopped at `apport-coredump-hook@.service`: an uninstantiated template is not a valid show target. Its 15 returned records were incomplete. Supplementary read-only evidence at `/opt/tu1nz_repos/network-hardening-private-2026-09-22/acl-dependency-review-20260927T063354Z` covers 435 installed non-template and loaded units with return code zero; uninstantiated templates are listed separately. Not-found units remain recorded. This fixes evidence coverage, not live configuration.

## Dependencies and blocking distinction

The tree is not exclusively owned or written by chatops. It includes root, dedicated approval broker/notifier, adult publishing, www-data and MyChatBuddy identities. A live FD snapshot showed UID 996/GID 985 holding the staging-s1 runtime lock read/write. Absence of other open FDs does not rule out timer, short-lived or future writes.

`/var/log/tausendunde1nz/ape-approval-notifier-state` is root (UID 0), group tu1nz-ape-notify (GID 983), mode 2770, ACL user::rwx/group::rwx/other::---. Its state.json, notifier.lock and notify.log are UID 994 (tu1nz-ape-broker), GID 983, mode 0640. NSS lists UID 993 as the primary member of group 983 and no supplementary members. Process-specific credentials must still be considered.

The readable installed notifier explicitly requires the dedicated notifier UID/GID and no supplementary groups before private-core loading. The systemd service starts a root guard. The private core is not readable by chatops; the current evidence captures only its path references and checksum. Therefore the guard credential transition and exact creation/replacement protocol are not yet proven. Removing directory group-write could prevent notifier creation or atomic replacement; keeping it without analysis would not meet the requested target. No permission change to this subsystem is safe on the current evidence.

Numeric group mode bits are not sufficient: backup-integrity and security have mask rwx but group entries r-x, with named chatops user write. The acceptance lock has an rw mask but read-only group entries. These must not be misclassified or have named-user writes removed blindly. Actual group-write remains confirmed on the top-level state directory, health directory and other enumerated entries.

Docker inventory contains no direct writable mount of either target tree; cAdvisor mounts `/` read-only, which also exposes their ancestry read-only. This is not evidence of a Docker writer.

Logrotate currently creates its listed logs as 0644 chatops:chatops. Trendwatch-fetch has UMask 0007. These creation paths require explicit future-inheritance tests; metadata-only changes cannot be assumed to prevent every later permission regression.

## Completion gates

Before a live command: inspect the privileged guard/core credential and file-write logic without exposing secrets; map remaining indirect script dependencies; derive a literal per-path plan preserving dedicated identities and necessary reads. Test creation, append, atomic replace, locks, inheritance and exact rollback under every relevant identity in an isolated mirror. Test concurrent drift and rollback failure handling. Pin the resulting plan and baseline, document and push it before activation.

Only eight synthetic transaction tests were previously passed. They do not prove a full multi-user mirror, production rollback or full repository suite. The full suite previously stopped at the unchanged strict Agentmode 0750 assertion. No new full-suite pass, production apply, PR or merge is claimed. No live sudo apply command is supplied while these gates remain open.

Integration commit 1cf0d797ab025fb08466b92aed156ca5d7d63035 remains an ancestor. All original 42 hardening files match their baseline SHA-256 hashes. Canonical detached checkout HEAD/status/HEAD-file location exactly match the saved baseline.
