# V11 bounded collection result and durable forward barrier — 2026-10-02

Base: `557a42e8edba7f680c4111c146a872f179f8906c`. GOVERNANCE_V1_1_ACTIVE.
Status: **LIVE_NO_GO**. This is an evidence/offline implementation delta, not a
completed production integration, installed watchdog or activation authorization.

## The one authorized root read

The collector ran once after personal sudo input and returned 2. Root evidence:
`/var/lib/tu1nz-v11-scoped-evidence-k9o4crsn`. Its authoritative results remain
root-private; sanitized exported files are root:chatops 0640 in a 0750 directory.
All 47 sections and the manifest (48 files) remain unchanged. No second sudo run
was performed. No services, credentials, configuration, network or firewall were mutated.

Original manifest remains INCOMPLETE, SHA-256:
`eb91e645502bb939a947b4c9a065ad530a098dbe5f5698ccc350ec0ea9849b17`.
35 file sections and the observer-lock/transaction metadata sections succeeded.
Six effective service sections rejected unreviewed credential rendering; four timer
sections succeeded. The failure was not a discovered credential reference:
`systemctl show` renders both LoadCredential properties as `[unprintable]`.

A subsequent nonprivileged, typed D-Bus query proved both arrays empty for each
of the six services (12 properties, signature a(ss), zero entries). The strict
supplement evaluator refuses malformed JSON, other signatures, unknown properties,
nonempty arrays and incomplete proof pairs. It exports no names or secret values.
This resolves the current bounded credential gaps; it does not rewrite history or
claim an all-files/all-consumers inventory. Fresh checks remain mandatory at activation.

Private supplement: `validated-consumer-supplement.json`, SHA-256:
`6c9fd0249e9373c13ff82abf8510830a99ad74d33a717b26fc4cb41447da3e94`.
All private copies, supplementary proofs and tests are below
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-scoped-preparation-20261002`.
Private evidence is not committed.

## Consumer decisions

| Known path or unit | Evidence | Migration consequence |
| --- | --- | --- |
| Four trendwatch2 posting services | Direct live post-script consumers; implicit root; inactive between runs | All four must use the same dedicated identity, immutable candidate and LoadCredential |
| Their four timers | Enabled and active | Quiesce triggers as well as service instances before replacement; inactivity is not retirement |
| trendwatch-fetch.service | Disabled/inactive, chatops; post-script reference in drop-in | Preserve disabled state; migrate or explicitly guard its latent reference before declaring closure |
| Live trendwatch_post.sh | Known exposed token present | Replace literal credential and root sudo/tee path together |
| Historical post backup dated 2025-11-30 | Same exposed token present | Historical private retention; never reactivate after provider handoff |
| Four protected /etc/t1nz files | Successfully read, no old-token match | No additional direct old-token consumer proven; absence of exact match is not proof of arbitrary semantic independence |
| Clone script | Refers to live post/rank and dynamically named variant paths | Do not infer absence of generated variants from the template alone; prevent a stale template from regenerating exposed credentials |
| Agentmode | Inactive, MainPID 0, unchanged invocation; own lock absent; transaction metadata empty | No general empty-Approval gate; recheck own ownership/conflicts at activation |

No Approval/APE payloads were read. No new SIGTERM attribution, network, n8n, NAT or
AppArmor investigation was opened. The historical SIGTERM remains UNATTRIBUTED_SIGTERM.
The absent compose/rank helpers are latent references, not authorization to repair or
enable the disabled fetch service or unrelated workflows.

Targeted source metadata confirms a further integration requirement: the posting
script executes fetch output via eval. The fetch comment mentioning eval is not an
additional executable eval. This alone does not prove exploitability, and no payload
was run. A dedicated-identity adapter must preserve/review this data contract instead
of silently treating the fetch script as a harmless file copy. Affiliate and sender
helper dependencies also require explicit admission; the sender path is a symlink,
not evidence that its target is world-writable.

The output directory /opt/trendwatch is chatops-owned 0755; today_title.txt is 0644,
today_live_title.txt 0664. The desired dedicated account does not yet exist. Therefore
simply switching User= would not prove correct output access. No ownership or ACL was
changed. The referenced yt_api_key.txt is chatops-owned 0644; its content was not read,
and rotation or modification of that separate credential is not part of this delta.

## Durable forward-only journal

New `forward_recovery_journal.py` has no activation CLI and performs no host/service
operations. It binds transaction and manifest SHA, verifies directory/file owner,
mode, type, ACL and link count, traverses parents without following symlinks, uses
short nonblocking locks, fsync and atomic publication. Production use requires root
and protected ancestors; fixture mode supports unprivileged isolated tests only.

Before a provider action may be shown, handoff() must durably publish an immutable
forward-only barrier, then persist the phase, and return successfully. If the process
exits between barrier and phase writes, recovery still chooses forward-only. A missing
barrier after a later phase, corrupt checksum, wrong binding or unknown state refuses
recovery rather than permitting the old credential. Consumers of this library must
turn refusal into safe intervention, never an optimistic rollback.

The journal deliberately does not assert that a new token is valid: it returns
FORWARD_ONLY_VERIFY_NEW_OR_SECURED_STOP. Only a future bound provider/host adapter can
supply real identity, function and old-token-rejection evidence. No Telegram API or
BotFather action occurred. No dual-token phase is assumed.

19 new tests include a real isolated child process exiting after barrier publication,
reopening state, a crash before the phase write, fsync failure, foreign manifest,
symlink, hardlink, modes, corrupt data, missing barrier, illegal phase order, concurrent
lock refusal and no lifetime coordinator lock. These prove the barrier, not a deployed
independent watchdog. Existing Agentmode 660-second and ownership tests remain unchanged.
The typed credential supplement adds 12 focused tests.

## Remaining admission requirements

The protected bounded consumer/state read is now usable with its separate supplement.
V11 is still not fully activation-ready:

- bind the existing host migration phases to the new Agentmode prologue/receipt and
  dedicated Trendwatch output/credential architecture;
- finish the independent root watchdog executable/unit and recovery executor, including
  real coordinator/watchdog crash, restart and boot-change tests;
- integrate the durable barrier with hidden token input, verified provider identity,
  old-token rejection and confirmed consumer-only restart;
- prove the whole transaction's semantic rollback/forward recovery, not just components.

No executable activation launcher is supplied. Earlier launchers remain invalid. No
new MacBook confirmation or personal input is requested until those requirements pass.
No PR is created. Branch CI absence will be recorded separately from local workflow tests.

## Verified tests and newly detected admission failure

519 targeted tests and all 108 workflow run blocks passed in a fresh isolated clone
under umask 0022. Two existing optional paired-application missing-source skips remain
skips, not verified application integrations. Test-manifest SHA-256:
`18df6546f71f3b78391b18c9f8f4d4b2a79c3e2ff87ae6431ffb6ac1ce914b0a`.

Byte preservation passes for 701 worktree baseline files, 42 hardening files, 1,125
historical evidence files, 30 V9 sources and all 48 exported root-run files. 1cf0d79
remains an ancestor. No previously tracked worktree content was changed.

**The detached production baseline check FAILED.** It must not be reported as unchanged:

- Previously saved HEAD: `9b383960291da469671c3888cfa4fdcc3c33cf01`.
- Current HEAD: `b78bb2a753aa815d47a99969668d64960573050b`, still detached.
- `/opt/tu1nz_repos/control/.git/index`: root:chatops, 0600, inode 1460562;
  mtime/ctime 2026-10-02T13:15:31.099272Z. chatops cannot read it.
- `git status --porcelain` cannot establish cleanliness: permission denied.
- HEAD file mtime: 2026-10-02T13:15:30.399239Z. No actor attribution is made.

This run issued no production checkout, index, chmod, deployment, service or credential
mutation. The separate preparation worktree remains at the expected 557a42e base.
The current baseline drift invalidates admission using the old detached pin. Do not
change permissions, reset the checkout, update the pin merely to pass, or infer that
its source is approved. No additional privileged run was started.

Safe continuation requires reconciling this exact checkout update and root-owned
index with the responsible deployment/transaction evidence, then reviewing an explicitly
accepted current baseline. Until then, production adapter binding and live activation
are blocked. Existing backup/history are retained; no rollback of another actor's work
is attempted. This failure is independent of the passing isolated tests and the resolved
credential-rendering gap. No PR or activation launcher is produced.
