"""Fixed-name systemd graph; retained outer capsule survives inner cleanup."""
from pathlib import Path
PACKAGE='/usr/local/libexec/tu1nz-v11-dispatcher'
ROOT='/var/lib/tu1nz-v11-dispatcher'
BOOT='tu1nz-v11-dispatcher-boot.service'
WORK='tu1nz-v11-dispatcher.service'
WATCH='tu1nz-v11-dispatcher-watch.service'
TIMER='tu1nz-v11-dispatcher-watch.timer'
GUARD='tu1nz_delete_guard.service'
LEGACY_TIMER='tu1nz_delete_guard.timer'
def common(role='recover'):
 # Recovery replaces fixed files within these parents; other roles only write
 # the outer state. READ_SEARCH backs up restrictive originals; CHOWN restores
 # original groups. All admitted target owners are root. No network capability.
 text="""User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN
ReadWritePaths=/etc/systemd/system /usr/local/bin /usr/local/libexec /etc/tu1nz /var/lib/tu1nz-v11-dispatcher /var/lib/tu1nz-v11-guard-recovery /var/lib/tu1nz-docs-authority-v11
MemoryMax=256M
TasksMax=32
"""
 if role!='recover':
  text=text.replace('CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN','CapabilityBoundingSet=')
  text=text.replace('ReadWritePaths=/etc/systemd/system /usr/local/bin /usr/local/libexec /etc/tu1nz /var/lib/tu1nz-v11-dispatcher /var/lib/tu1nz-v11-guard-recovery /var/lib/tu1nz-docs-authority-v11','ReadWritePaths=/var/lib/tu1nz-v11-dispatcher')
 return text
def templates(pin):
 import re
 if not re.fullmatch('[0-9a-f]{64}',pin):raise ValueError('PIN')
 cmd='/usr/bin/python3 -I -B '+PACKAGE+'/dispatcher.py '
 boot='[Unit]\nDescription=TU1NZ independent V11 boot fence\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=timers.target '+GUARD+' '+LEGACY_TIMER+'\nRequiresMountsFor='+ROOT+' '+PACKAGE+'\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'+common('boot')+'ExecStart='+cmd+'boot '+pin+'\nTimeoutStartSec=60\n[Install]\nWantedBy=sysinit.target\n'
 work='[Unit]\nDescription=TU1NZ independent V11 rollback dispatcher\nRequires='+BOOT+'\nAfter='+BOOT+'\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\n'+common()+'ExecStart='+cmd+'recover '+pin+'\nRestart=on-failure\nRestartSec=5\nTimeoutStartSec=900\n'
 watch='[Unit]\nDescription=TU1NZ V11 dispatcher liveness check\nRequires='+BOOT+'\nAfter='+BOOT+'\n[Service]\nType=oneshot\n'+common('watch')+'ExecStart=/usr/bin/python3 -I -B '+PACKAGE+'/watchdog.py '+pin+'\nTimeoutStartSec=30\n'
 timer='[Unit]\nDescription=TU1NZ persistent V11 recovery watch\nRequires='+BOOT+'\nAfter='+BOOT+'\n[Timer]\nOnBootSec=15\nOnUnitInactiveSec=15\nAccuracySec=1\nUnit='+WATCH+'\n[Install]\nWantedBy=timers.target\n'
 guard='[Unit]\nRequires='+BOOT+'\nAfter='+BOOT+'\n[Service]\nExecCondition='+cmd+'condition '+pin+'\n'
 legacy='[Unit]\nRequires='+BOOT+'\nAfter='+BOOT+'\n'
 return {BOOT:boot,WORK:work,WATCH:watch,TIMER:timer,GUARD+'.d/99-v11-dispatcher.conf':guard,LEGACY_TIMER+'.d/99-v11-dispatcher.conf':legacy}
