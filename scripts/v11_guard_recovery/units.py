"""Pure payload/unit builder. Templates avoid a manifest/unit hash cycle."""
from pathlib import Path
from runtime import *

def templates(consumer):
 fence="""[Unit]
Requires=tu1nz-v11-guard-recovery.service
After=tu1nz-v11-guard-recovery.service
RequiresMountsFor=/var/lib/tu1nz-v11-guard-recovery /usr/local/libexec/tu1nz-v11-guard-recovery
[Service]
ExecCondition=
ExecCondition=/usr/bin/python3 -I -B /usr/local/libexec/tu1nz-v11-guard-recovery/runtime.py condition @CONTRACT_SHA@
"""
 timer="""[Unit]
Requires=tu1nz-v11-guard-recovery.service
After=tu1nz-v11-guard-recovery.service
RequiresMountsFor=/var/lib/tu1nz-v11-guard-recovery
"""
 recovery="""[Unit]
Description=TU1NZ V11 persistent Guard recovery
DefaultDependencies=no
After=local-fs.target
Before=timers.target tu1nz_delete_guard.timer tu1nz_delete_guard.service
RequiresMountsFor=/var/lib/tu1nz-v11-guard-recovery /usr/local/libexec/tu1nz-v11-guard-recovery
[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tu1nz-v11-guard-recovery /var/lib/tu1nz-docs-authority-v11
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_CHOWN
MemoryMax=256M
TasksMax=16
ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/tu1nz-v11-guard-recovery/runtime.py recover @CONTRACT_SHA@
TimeoutStartSec=180
[Install]
WantedBy=sysinit.target
"""
 watchdog="""[Unit]
Description=TU1NZ V11 independent Guard watchdog
Requires=tu1nz-v11-guard-recovery.service
After=local-fs.target tu1nz-v11-guard-recovery.service
RequiresMountsFor=/var/lib/tu1nz-v11-guard-recovery /usr/local/libexec/tu1nz-v11-guard-recovery
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tu1nz-v11-guard-recovery /var/lib/tu1nz-docs-authority-v11
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_CHOWN
MemoryMax=256M
TasksMax=16
ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/tu1nz-v11-guard-recovery/runtime.py watchdog @CONTRACT_SHA@
Restart=on-failure
RestartSec=1
TimeoutStopSec=10
[Install]
WantedBy=multi-user.target
"""
 return {FENCE:fence,TIMER_DEP:timer,'/etc/systemd/system/'+RECOVERY:recovery,'/etc/systemd/system/'+WATCHDOG:watchdog,CONSUMER:consumer.decode()}

def build(directory,guard_payloads,authority,legacy_sha,legacy_mode):
 d=Path(directory)
 runtime=(d/'state.py').read_text()+'\n'+(d/'runtime.py').read_text().replace('from state import *','')
 compile(runtime,PROGRAM,'exec')
 payload={PROGRAM:runtime.encode(),NEW:guard_payloads[NEW]['bytes'],AUTH:authority,CHECKSUM:guard_payloads[CHECKSUM]['bytes']}
 modes={PROGRAM:0o600,NEW:0o600,AUTH:0o600,CHECKSUM:0o755}
 c={'schema':1,'files':{p:{'sha256':digest(raw),'mode':modes[p],'uid':0,'gid':0} for p,raw in payload.items()},'unit_templates':templates(guard_payloads[CONSUMER]['bytes']),'new_authority_sha256':digest(authority)}
 c['files'][LEGACY]={'sha256':legacy_sha,'mode':legacy_mode,'uid':0,'gid':0}
 raw=encode(c);pin=digest(raw)
 payload.update({p:t.replace('@CONTRACT_SHA@',pin).encode() for p,t in c['unit_templates'].items()});payload[CONTRACT]=raw
 return {'contract':c,'contract_sha256':pin,'payloads':{p:{'bytes':b,'sha256':digest(b),'uid':0,'gid':0,'mode':modes.get(p,0o400 if p==CONTRACT else 0o644)} for p,b in payload.items()}}
