# V11 Docs authority preparation — 2026-10-02

Status: OFFLINE_PREPARATION; NO LIVE ACTIVATION. Infra base `3be8beb3b1ef14d73728db256f358963f72015c7`.

## Independent source and authority

GitHub confirms canonical `Tausendunde1nz/docs` main commit `537aa8fd69d755c641246cc1b507c69b3e1cd5f5`, tree `910f981134ad82a171cc0d727604315d50bba4fa`. Every local tree/index path, mode and blob matched the complete GitHub tree. No associated PR or verified signature is claimed. The checkout is main tracking origin/main. The logical Docs path resolves to `/tausendunde1nz/07_docs`; its index hash remains `aa225794c849075a46bd84bad037fa02d7165547ca69bfcc4aa2137b8cec84ce`.

883 regular tracked files form SOURCE_MANIFEST. Two tracked symlinks are excluded. No verified deterministic build/publish contract justified additional outputs, so GENERATED_MANIFEST is empty. Rebuilding with identical creation metadata reproduces the manifest bytes. Creation time is not a trust anchor. APPROVED_AUTHORITY SHA-256 is `5576dbbd0c3fd15048dad66ddd93651bf493b23e7f4c9841d23afe56f3054c55`.

The old 1,150 and 797 entries were comparison inputs only. The union classified 883 TRACKED_SOURCE, 2 EXCLUDED_FROM_AUTHORITY and 1,057 UNEXPLAINED historical entries. 880 source paths occur in the former guard list; seven in the checksum list (five matching and two differing old hashes). These historical differences are not promoted to authority or made blanket blockers. Current observation: all 883 expected files MATCH; 270 additional files reported separately. No contents or private path lists are published.

Full manifests, comparison and reports remain under `/opt/tu1nz_repos/network-hardening-private-2026-09-22/docs-authority-20261002`. Final manifests are in `v2/`; initial files remain historical evidence. The JSON companion records complete source/payload/manifest pins.

## Concrete offline candidates and boundaries

The fixed root guard uses descriptor-based no-follow traversal, validates root identity and stable file metadata, rejects links/special types/path ambiguity, and hashes regular files. It never writes to the monitored checkout or updates authority. Reports are immutable private files; only aggregated status is readable by chatops. The unprivileged checksum consumer verifies status provenance, authority pin, boot/monotonic freshness and successful systemd result. Monitoring does not create root authority.

The JSON companion lists exact root-owned guard, authority, service drop-in and checksum consumer targets and hashes. The oneshot has fixed commands, no network, read-only source access and resource/time limits. Future authority updates require a separately reviewed source commit, regenerated manifests, new pins, offline validation and a separate transaction; surveillance never performs updates.

The concrete Guard file adapter validates originals, persists mutation intents, installs atomically, verifies postimages and restores only its own matching changes. Before cutover, backup contents/ownership/modes/ACLs and restorable timestamps are restored; atomic replacement cannot preserve inode/ctime. A durable security barrier precedes stopping the timer. After that barrier recovery must SECURED_STOP or repair forward; it must never restart the legacy self-authorizing root guard. No timer was stopped and none of these payloads was installed.

A fixed runuser/chatops deployment candidate adapter stages only a new dedicated Control candidate. It does not move or rewrite the live checkout or Gitdir. The complete eleven-component V11 production host, watchdog and rotation composition is NOT yet proven. Guard-specific tests are not evidence that the entire V11 transaction is activation-ready.

## Validation and preservation

Final run: 704 targeted tests (641 existing plus 63 new) and all 108 workflow steps passed. Two application simulator tests in workflow step 100 were skipped because the paired application source checkout is unavailable; they are not reported as passed. Final private `tests-final/results.json` SHA-256: `2abc4f9fff042cb0cd4508e68cadb0f659ef40fbc0e357bba152ca368ea14ca0`.

Coverage includes strict manifests, unsafe file/path types, changed parents, immutable authority on alarm, fixture install/restore, foreign changes, secured-stop, and protected collector failures. An initial isolated fixture failure was corrected by explicitly creating its temporary parents with the required mode; production validation was not weakened. Final code pins match the tested sources.

Final comparison preserved all 42 Hardening files, 701 historical tracked files, 1,125 private evidence files and 30 historical V9 sources byte-for-byte. The ancestry check retains `1cf0d79`. No services, containers, networks, firewall, SSH, tokens or live rights were modified by this work.

## Protected inputs and final blocking drift

Exact sudo/group candidate binding still needs four protected originals: `/etc/sudoers`, `/etc/sudoers.d/99-dokuagent-pandoc`, `/etc/sudoers.d/chatops-nopass`, `/etc/gshadow`. The new collector reads only those files. Original and candidate bytes stay root-private; redacted output contains metadata/hashes only. Its bootstrap makes and verifies a restrictive root-owned copy before isolated Python execution. It is tested but has NOT run. It is not a live configuration installer.

The final read-only preservation gate found production Control HEAD `e60aa2f515c89f94bce1dbd6496d358cdfb85300`, index SHA-256 `623fd407ab393599423b2aee4a3a603466198cc8767deef3abe87fbb8749e863`, instead of pinned `21e822f8cadecf5eb186693d1ceac2d5d0bf6969`. GitHub confirms this commit/tree `4640102c40af0111be62b845842f0d7b99ca69f2`; its first parent is the specified basis. Commit subject identifies merge PR #68, with four RC5 controlled-start/test/documentation files changed. This establishes checkout drift, not who changed the checkout. No actor or malicious action is attributed.

The observed Control change is not overwritten or silently accepted as a new production pin. The Infra branch and Docs index remain at their expected starting values. V11 remains NO-GO: production preconditions must be reconciled with this separately advanced Control state before any future live window. This report explicitly does not claim the detached checkout remained unchanged globally. No activation/readiness command is released in this state; no PR or merge is performed.
