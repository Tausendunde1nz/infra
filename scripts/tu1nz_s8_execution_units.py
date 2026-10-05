"""Static one-shot unit relationship; never ordinary-claim fallback.

The coordinator is oneshot/RemainAfterExit: failure/interruption stops S8 via
BindsTo, whereas verified completion keeps its active/exited dependency alive.
There is deliberately no After=coordinator ordering (that would deadlock).
"""
from pathlib import Path
import re

from tu1nz_s8_execution_contract import require, UNIT

COORDINATOR = "tu1nz-s8-execution-coordinator-r1.service"
CONTROLLER = Path("/etc/tu1nz/s8-atomic-admission-r1/control/tu1nz_s8_execution.py")


def render(controller=CONTROLLER, *, runtime=UNIT, coordinator=COORDINATOR,
           runtime_user="chatops", runtime_group="chatops", frozen_program=None):
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+",str(controller)), "CONTROLLER_PATH_RED")
    for name in (runtime,coordinator):
        require(re.fullmatch(r"tu1nz-[a-z0-9-]+\.service",name), "UNIT_NAME_RED")
    for identity in (runtime_user,runtime_group):
        require(re.fullmatch(r"[a-z][a-z0-9-]*",identity) and identity != "root", "IDENTITY_RED")
    if frozen_program is None:
        # Existing construction fixtures only. Final provisioning must supply
        # the provenance-checked PID-1-loaded program, never this disk path.
        command = lambda phase: f"/usr/bin/python3 -I -B {controller} {phase}"
    else:
        from tu1nz_s8_frozen_entry import systemd_command
        command = lambda phase: systemd_command(frozen_program, phase)
    common = """Restart=no
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
RestrictRealtime=yes
StandardOutput=journal
StandardError=journal
"""
    root = "/etc/tu1nz/s8-atomic-admission-r1"
    coordinator_text = f"""[Unit]
Description=TU1NZ S8 fixed one-shot recovery coordinator
StartLimitIntervalSec=infinity
StartLimitBurst=1
[Service]
Type=oneshot
User=root
Group=root
RemainAfterExit=yes
TimeoutStartSec=240
TimeoutStopSec=30
ExecStart={command('coordinate')}
ReadWritePaths={root} /run/systemd/system /etc/systemd/system
{common}"""
    runtime_text = f"""[Unit]
Description=TU1NZ S8 immutable atomic admission (no ordinary startup)
BindsTo={coordinator}
After=network-online.target postgresql.service
RefuseManualStart=yes
StartLimitIntervalSec=infinity
StartLimitBurst=1
[Service]
Type=simple
User={runtime_user}
Group={runtime_group}
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=control-group
PrivateMounts=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH CAP_CHOWN
# ! keeps the filesystem sandbox and per-user credential ownership, while
# the narrow launcher starts privileged and must drop to this exact identity.
# + would also bypass the filesystem sandbox and is deliberately forbidden.
ExecCondition=!{command('condition')}
ExecStart=!{command('execute')}
ReadWritePaths={root} /run/tu1nz-s8-execution-r1
InaccessiblePaths=-/opt/tu1nz_repos/adult-publishing-core -/opt/tu1nz_repos/control
LoadCredential=s8_telegram_token:/etc/tu1nz/adult-commercial-s10-2b-telegram.token
LoadCredential=s8_database_dsn:/etc/tu1nz/adult-commercial-s7-database.dsn
{common}"""
    return {coordinator:coordinator_text,runtime:runtime_text}


def runtime_dropin(controller=CONTROLLER, **options):
    """Persistent overlay, not replacement of the historical base unit.

    Provisioning must create and protect a previously absent drop-in directory
    before daemon-reload. A legacy base-unit restoration must never restore
    ordinary claim, automatic restart, extra commands or environment hooks.
    This renderer is not itself a provisioner or a grant.
    """
    runtime=options.get("runtime",UNIT)
    text=render(controller,**options)[runtime]
    reset="""[Service]
ExecStart=
ExecStartPre=
ExecStartPost=
ExecCondition=
ExecStop=
ExecStopPost=
Environment=
EnvironmentFile=
PassEnvironment=
UnsetEnvironment=
LoadCredential=
LoadCredentialEncrypted=
SetCredential=
SetCredentialEncrypted=
ReadWritePaths=
ReadOnlyPaths=
InaccessiblePaths=
SupplementaryGroups=
AmbientCapabilities=
RootDirectory=
RootImage=
WorkingDirectory=/
DynamicUser=no
"""
    # The later explicit Type/User/Group/capability and sandbox assignments
    # come from exactly the same full unit used by the native admission proof.
    return reset+text
