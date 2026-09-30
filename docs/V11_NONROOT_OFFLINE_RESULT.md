# V11 non-root preparation: tested application, unresolved exact network recovery

Base: `d8c7ade4c954b837153c2a0fe59b7c930334c094`, branch
`security/codex-privileged-ops-2026-09-27`, 2026-09-30.

## Decision

**NOT ACTIVATION READY — EXACT_NETWORK_RECOVERY_NOT_PROVEN.**

The accepted AppArmor evidence boundary no longer blocks a conservatively
validated non-root remedy. V9 UNRESOLVED remains final, unrelated and unsearched.
No privileged collector, live transaction, watchdog, production restart or
production configuration change was performed. No activation command exists.

The newly demonstrated blocker is compensation of Docker network changes while
preserving both the original dynamic IPAM configuration and the observed IP
assignments, including competing allocation. It is not an application UID,
read-only filesystem or AppArmor-export failure.

## Non-root compatibility completed

The exact application bytes were copied into a private fixture:
`f7119919cd3bff8193b72782ec984633cd222abad87281df011455fb7313a8bd`.
The existing image remained
`sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db`.
Production Compose hash remained
`a6d915ab975934e9957fe62d8281b8d44c679dd015d9fd03475b89877a631a1c`.

Two new isolated starts passed all of:

* effective UID and GID 20001;
* zero effective and bounding capability masks;
* NoNewPrivs=1;
* read-only root filesystem and read-only, rprivate code/configuration bind;
* denied writes to main.py, dummy configuration, new code files, /tmp and /etc;
* import, Flask health test, real server startup and three HTTP health samples;
* successful repeated start of the isolated test container.

No required writable application path was found or exercised by import/start/
health. Therefore no tmpfs, runtime volume or new public port was added to the
candidate. This does not claim exhaustive testing of externally triggered
business operations: no Telegram message, webhook or provider request occurred.
Network=none enforced isolation; only dummy environment values were supplied.
Resource limits were 128 MiB, 0.5 CPU and 64 PIDs.

Actual `docker compose config --format json` renders changed exactly five
service fields: `user`, `cap_drop`, `security_opt`, `read_only`, `volumes`.
The planned values are `20001:20001`, `[ALL]`,
`[no-new-privileges:true]`, `true`, and `.:/app:ro` respectively. Image/build,
command, env_file, published ports, restart policy and declared networks were
unchanged in those renders. Rendering used an isolated copy and dummy `.env`,
not the protected production secret file. No deployable production Compose
file was edited or committed. The additional manually attached production
network remains outside that Compose model and must be handled transactionally.

## Network experiment and exact deltas

The tests used new uniquely named internal bridge networks, no published ports,
no host mounts, and short-lived resource-limited non-root sleeper containers.
They never attached a production network or executed application code. All
temporary networks and containers were removed and absence was verified.

Docker Engine is 28.5.1, API maximum 1.51. The experiment deliberately records
every compared field; IPAM or MAC differences are not filtered away.

| Method | Result |
| --- | --- |
| Stop, disconnect, reconnect original container, restart | IPs and aliases preserved in the isolated uncontended case; both MAC addresses changed despite supplied values. Exact comparison fails. |
| Recreate with both complete endpoints supplied at creation | All compared fields match in the uncontended isolated case. |
| Same recreate after a separate isolated sleeper occupies the released addresses | IPs change from `.2` to `.3` on both test networks. Exact comparison fails. |
| Recreate with explicit original IPv4 addresses in IPAMConfig | Addresses and MACs preserved, but dynamic IPAMConfig becomes static. Exact configuration comparison fails. |

The source-level distinction is consistent with the installed engine's
[Moby v28.5.1 network implementation](https://github.com/moby/moby/blob/v28.5.1/daemon/container_operations.go):
creation remembers a requested MAC separately, whereas the connect path does
not establish the same stored value; startup clears operational endpoint data.
This source review explains the observed result, rather than substituting for
the experiment. Top-level inspected IPAddress is not a reliable static-IP input.

Production currently has `IPAMConfig: {}` on `tausendunde1nz_net` and
`IPAMConfig: null` on `telegram_chatbot_default`. Neither specifies a static
IPv4 address. The isolated reproduction uses dynamically assigned endpoints;
it does not assert that its synthetic addresses are production addresses.

There is no claim that a competing production allocation occurred. It is a
failure-injection result. A preflight observation that an address is free does
not reserve it across subsequent Docker operations. The test's process exit 0
means the experiment and cleanup completed; the per-case `pass: false` records
remain failed activation-preflight outcomes, not successful rollback evidence.

An exact recovery contract therefore still needs a proven allocation-exclusion
mechanism or an explicitly revised persistent-IPAM recovery model. No daemon
upgrade, internal Docker metadata edit, new network, competing-container stop,
or silent conversion of the production endpoints to static IPAM was attempted.
No automatic rollback implementation is presented as complete on this evidence.

## New read-only AppArmor collector

`apparmor_readonly_v11.py` is a new inert module for the later verified root-owned
V11 staging package. It has no activation CLI and was not run as root.
Its SHA-256 is recorded in `V11_NONROOT_OFFLINE_RESULT.json`; there is no reused
launcher, transaction directory or privileged execution command.

It admits only GET of the fixed Mommyramona container and Docker version,
checks the container/image/PID/profile mapping before and after collection,
reads `/proc/<pid>/attr/current`, the one matching SecurityFS profile, ABI,
features, raw-data hash and protected disk sources/includes if present. It
rejects path escapes, unexpected ownership/ACLs, size/count bounds and drift.
No environment values, application content, credentials or journal data are
selected. It has no subprocess, policy loader, compiler or mutating Docker API.

Binary policy data is hashed, not interpreted or represented as readable rules.
Disk source existence is not proof that the kernel loaded those same bytes.
An unavailable human-readable export is a documented technical limit, not a
reason for another broad collector or a permanent non-root-remediation veto.
Results must eventually be handed to the V11 transaction's protected atomic
evidence writer before any production mutation. That integration and the
complete migration/broker/revocation/rollback engine are **not complete** in
this revision, because the required Mommyramona recovery phase has not passed.

## Validation and preservation

* 10 new collector tests passed locally and on the server, using fake files and
  a fake Docker reader; no privileged probe was performed.
* 28 preceding scope/boundary tests also passed: 38 targeted tests this run.
* All 108 existing workflow steps passed in a new isolated Git copy, umask 0022.
* Two optional paired-application simulations were skipped because that separate
  checkout was unavailable. They are not counted as passed application tests.
* The separate exact-network-recovery preflight remains failed as detailed above.

Workflow evidence:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-complete-workflow-20260930T192857Z-8a6de7b3`.
Result SHA-256:
`d7758f2d4992c17fc61184d6c37244c8eaf9cdc1bccfb60df303b8ad2342f5d6`.

The initial static-IP test fixture used automatically allocated network subnets;
Docker rejected explicit addresses there. The corrected fixture explicitly
declares the same disposable subnet before testing. Earlier script versions,
errors and hashes are preserved privately; no production network was changed.
A macOS test-fixture path was resolved before comparison to account for its
`/var` symlink; the collector's path protection was not relaxed.

Final SHA checks preserve all 701 bound existing files, 42 Hardening files,
30 V9 sources and 1125 historical evidence files. `1cf0d79` remains an ancestor.
The detached checkout remains clean at `9b383960291da469671c3888cfa4fdcc3c33cf01`.
Mommyramona retains the original container ID and PID 2444; source and Compose
hashes are unchanged. MyChatBuddy remains inactive/dead, MainPID 0, with its
unchanged unit hash. No historical evidence was rewritten and no PR was opened.

The completed application and collector work is preserved independently of the
failed network preflight. There is no assertion that all V11 work is finished,
no request for MacBook readiness, and no sudo command to execute.
