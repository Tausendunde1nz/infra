# V5.1 completed collection: security review remains open

## Collection outcome

All 26 section envelopes were exported as OK. collection_finished=true; collection_error_class=null. This is collection completion, not completion of the root trust graph or migration.
Private root evidence: /var/lib/tu1nz-root-trust-v51/run-20260927T145810Z-09700d05ed357f5d.
Reported manifest SHA-256: 17ab9113ec1cfa8f88379e18c68418cab5c028647a90f68554e6783e9b3280e7. No independent protected-manifest rehash was performed in this turn.
Sanitized local export SHA-256: 339684d21fdd56046fcc76143aad816a8a409150dd629cf7547e5aeeb2baf484; size 20,964,281 bytes.
The original V4 and V5 reports remain unchanged, including their INCOMPLETE statuses. V5.1 also remains INCOMPLETE as a security assessment.

## Graph interpretation

6,349 nodes and 13,296 candidate edges were exported: 5,396 REVIEW_REQUIRED nodes and 953 NOT_PRESENT candidates. These are lexical/reference candidates, not 953 absent operating-system mechanisms. 64 node records retain errors: 52 ValueError, 2 NotADirectoryError, 10 OSError. Size-limited binary/log reads and namespace pseudo-files must not be conflated with malicious files. None is silently promoted to SAFE.
The 45 systemd query failures comprise 44 uninstantiated template names and the root mount -.mount. A separate unprivileged query with the option delimiter `--` successfully read the active root mount; V5.1 had treated its leading hyphen as an option. Template definitions and actual instances need separate semantic review. No collector or original graph is retroactively rewritten.
The seven journal windows contain seven build_system_doc.sh mentions and 84 check_system_doc.sh mentions. These prove command mentions, not successful builds or notifications. No journal messages were saved in the report.
The expected system_summary symlink again classifies EXPECTED_SAFE_SYMLINK. This is a path relationship check, not a verdict on every command the script executes.

## Expanded authority findings

The already documented Trendwatch and legacy documentation root boundaries remain open.

`tu1nz-bot.service` is enabled, inactive, has no explicit User (system service root), uses /usr/bin/docker compose up, and sets WorkingDirectory=/home/chatops/bot-template-telegram. That working directory is currently absent. /home/chatops is chatops:chatops 0755 and writable by chatops, so the user can create the missing input directory. This is a configured latent root-delegation boundary, not an assertion that the service is currently running or an exploit succeeded. Removing chatops from Docker would not remove this enabled root Compose path.

Fresh read-only Docker inspect plus /proc identity checks show Mommyramona PID 2444/start ticks 1989 and Jellyfin PID 2452/start ticks 1992 with host UIDs 0/0/0/0 and identity UID/GID mapping 0 -> 0. Mommyramona has /opt/telegram_chatbot -> /app RW; Jellyfin has chatops-controlled config/cache parents mapped RW. These grant UID-0 write authority to the user-controlled mounted trees and therefore conflict with the requested strict target boundary. No transient write or container-to-host escape was demonstrated; mount namespaces must not be ignored when assessing actual exploit consequences. No container command, restart, mount or file change occurred.

cAdvisor PID 2466/start 1995 also maps UID 0 identically, but /rootfs and /var/run remain read-only binds. It is not classified as a writable bind. An explicit socket/mount access contract remains REVIEW_REQUIRED; the old read-only monitoring exception does not automatically establish the full Docker API boundary.

17 observed processes carry Docker GID 987. The snapshot includes the previously known public services and Agentmode, user-session processes, and mychatbuddy-private-alpha.service. Some observed processes may be transient collection/session processes. A later revocation plan needs fresh identity-bound enumeration. No general kill or unplanned restart is authorized or prepared for this newly identified service dependency.

The observed root agentmodus_tu1nz.service writes under /opt/agentmode with root-controlled components; it must not be confused with chatops tu1nz_agentmode.service. /dev/null, PTYs and cgroup pseudo-files are not ordinary replaceable application files and must not be counted as equivalent root-write exploits.

## Remaining work and restrictions

ROOT_TRUST_V51_RESULT_2026-09-27.json provides the reviewed decision edges alongside raw collection counts. It is not a complete semantic closure. Environment/import/PATH resolution, conditional hooks, protected source semantics, lifecycle/dependencies of enabled legacy services, and the container authority contracts are not fully resolved. The collector's literal pass cannot by itself prove them.
Runtime /proc environment access was checked only for permission availability on the three named container PIDs and returned PermissionError; no environment bytes were read or exported. Their UID/GID maps and process identities were readable and were checked without elevated privileges. No extra sudo run was made.
A complete installer, joint watchdog and rollback cannot honestly be called ready. The previous phase design is insufficient for the additional enabled root-Compose path and Docker-GID carrier. No live remediation, second collector, countdown, activation launcher or PR was started. Further semantic analysis must resolve the complete graph before a combined migration is represented as safe.

## Preservation and verification

All 42 hardening file hashes and 1,125 V3 evidence file hashes remain identical. V4, V5 and V5.1 sampler sources and old evidence have not been changed in this result-review commit. Canonical Control remains clean/detached and was not edited. The full privilege regression suite is rerun below this review before commit; no production health or exploit tests are implied by those offline tests.
