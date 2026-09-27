# Final backup_notify caller/sink reader v3 — preparation only

Base branch security/codex-privileged-ops-2026-09-27 at 6fb9905507a28d6b2dfde237acb3cbf5f2c84869.

## Binding security decision

/opt/telegram_chatbot/.env is untrusted in every root context. No attempt is made to certify its shell/data handling as safe. V1/V2 artifacts, manifests, diagnostics, result statuses and historical source hash remain immutable. V3 does not execute the target, read .env, send messages, alter services or start a watchdog. No production activation and no PR.

## Bounded collection

FROZEN_INPUTS.json binds the existing V2 candidate list, archive guard, parser manifest and vendor bytes. The 3027 existing archived candidates and their exact live paths are the entire input universe: no recursive filesystem scan. The source is the archive with SHA-256 878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311. All archive bytes are hash checked in memory. Missing live candidates are counted and excluded. Changed/unreadable/symlinked live candidates retain UNKNOWN; they cannot establish safety.

V3 reuses the already pinned structural parser only to project commands and edges; there is no new general syntax or safety certification attempt. Parse limitations become UNKNOWN. The earlier column-zero coverage defect is neither used nor silently relabeled.

Each graph node carries its exact catalog path and SHA, resolved edges, unresolved-path flag and current numeric metadata for its path components. ACL presence is recorded; effective chatops influence becomes UNKNOWN if an ACL prevents a bit-only decision. No named secret fields are emitted. Live paths are opened by directory descriptors with O_NOFOLLOW; .env is explicitly forbidden. Root archive checks remain unchanged.

Only the pinned /usr/bin/systemctl show is called: fixed properties, validated unit names drawn from the catalog plus cron.service, serial batches of 80. State includes enabled services, active services and active/enabled timer triggers. Masked inactive units are excluded where verified; disabled-but-triggerable, unfamiliar hooks, overrides and unknown execution identities stay conservative. The caller matrix distinguishes actual fixed execution, source, shell wrapper, PATH resolution and text-only references. Paths in a chain refer back to the per-node SHA and metadata. A graph is a projection of the bounded archive, not a claim that every system activation mechanism has been proved absent.

Sink rows emit only public executable paths from an explicit small allowlist, executable kind, function category, line number, argument position/origin, path categories, shell-evaluation flag and return-status influence (UNKNOWN when not proved). Names, literals, URLs, tokens, chat IDs, messages, env contents and raw ASTs never leave the reader. Unrecognized fixed programs remain FIXED_ABSOLUTE with their path redacted, avoiding accidental disclosure through a command path. Function UNKNOWN is permitted. FILE_DERIVED and env taint are conservative projections, never a safety guarantee.

## Classification and fail-closed disposition

The operational classification is one of the requested three values. ACTIVE_ROOT_CALLER_UNSAFE_OR_UNKNOWN is also the precautionary disposition for unresolved potential root entrypoints; active_root_call_proved explicitly distinguishes this from a proven active call. No claim of active execution is made merely because a possibility exists. NO_ACTIVE_ROOT_CALLER requires closure of the declared root graph; zero literal hits alone is insufficient. ACTIVE_ROOT_CALLER_SAFE_REPLACEMENT_POSSIBLE is reserved and will not be emitted automatically by a generic projection.

For uncertainty, prepare quarantine of the exact root-owned /usr/local/bin/backup_notify.sh entry path and proven callers. The future transaction must verify current hash, inode, root-owned nonwritable parent chain, links, ACLs and metadata, preserve original bytes privately, and replace entry with a fixed root-owned non-shell guard returning controlled failure 78 without reading .env or sending messages. Additional hardlink/copy execution paths must be treated individually if established; pathname quarantine does not certify unrelated code. No guard is installed by V3.

Automatic rollback must keep unsafe entrypoints quarantined; original bytes are only for separately authorized manual recovery. Backup notifications may be unavailable and upstream automation may receive failure; this functional loss must be reported. Do not automatically restore unsafe root code to improve availability. Unknown caller semantics do not require a fourth reader. The actual activation plan will be derived from this one result and any preserved fixed-source evidence, using quarantine rather than an invented functional contract.

The strict_data_parser component is an offline validation fixture with two harmless fixed keys; it is NOT the production notification schema or a drop-in implementation. Real replacement keys and functions must follow the v3 result; if not fully known, quarantine applies. No guessed token contract or mock-only migration is labeled production-ready.

## Tests and limits

46 new tests cover direct/source/wrapped/indirect calls, text-only references, PATH ambiguity, chains/cycles, cron and service/timer states, categories/taint/unknowns, redactions, shell constructs without execution, strict fixed-key parsing and injection rejection, quarantine rollback policy, pinned launch/bundle and descriptor guards. Frozen V2 is unchanged. The sealed Linux memfd bundle is exercised in a fresh unprivileged Python process on the server, never with sudo. Local Python 3.9 lacks the Linux fd-xattr path; its guard returns UNKNOWN/AttributeError, explicitly tested. An initial cross-platform fixture wrongly expected a Linux missing-path result on macOS; only this fixture expectation was corrected, not the Linux guard.

The quarantine test is a policy-invariant test, not proof of a deployed rollback. Full host-adapter failure injection, final root-automation changes, exact Docker-GID carrier handling, installer/watchdog integration and production validation remain dependent on the final protected result. None is falsely represented as complete here.

## Single later privileged read

Generated reader and launcher hashes are in READER_V3_MANIFEST.json. Launcher is not executable by file mode and is invoked explicitly with python3. It makes exactly one sudo call, transferring the pinned script bytes through stdin; root Python -I -S verifies the same SHA before compiling. No mutable imports from the worktree run as root. The bundle is checked, loaded into sealed anonymous Linux memfd and uses no persistent root files.

The launcher stores only structured redacted JSON under a fresh private result directory (0700; file0600), atomically fsynced before rename. It never logs passwords or raw terminal transcripts. Reader deadline240 seconds and CPU/memory bounds are enforced; errors expose exception classes only. No retries. A later run requires Daniel's fresh “Ich bin am MacBook bereit”.

Repository rollback: revert only this additive preparation commit. No live rollback is required. Never overwrite V1/V2 evidence.

## Observed detached-checkout movement

During preparation the unrelated detached checkout was observed clean at 18080ac534eae99b2d35faeba77e739fc169d6c0 (previous observation 7c634d3b82572e8459d51c69f04dce82c624d766). No checkout/reset/write command was issued against it. V3 does not import from or depend on that checkout; all executable bytes are bound to this separate worktree. This observation is not treated as a reason to alter live services.
