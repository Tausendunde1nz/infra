"""Fixed preparation contracts. No paths or commands supplied by chatops at runtime."""
from policy_v9 import Refused
SOCKET_UNIT_SHA='96cd0d89474816ddfb03893b44c36e7d744254aed1bf6d30eca65ff396114656'
DOCKER_UNIT_SHA='a12d90fd03761bf79659a185c4a2c40e08934d7ada9e05130e64bd5eb4d634aa'
MYCB_UNIT_SHA='53a2fad8675a6cfa79196d2fea64e56745403cdc4802ae93cb32682c13d71d26'
QUARANTINE_HASHES={
 '/etc/cron.d/system_doc_build':'c7beada82a5a09b29e1db6d9a4c828b3c87c16fb4a405d41d34488898121515e',
 '/etc/cron.d/system_doc_check':'aff2cc9afd2078142ca10ab2e1f3012c537f1b170be385b38c7006e396332789',
 '/etc/systemd/system/tu1nz-bot.service':'fad12c044b08f691ad1fa6a0afb40c748bfba81b4fbb1ef6240d5a442a213c01',
 '/usr/local/bin/backup_notify.sh':'878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311',
 '/usr/local/bin/trendwatch_post.sh':'467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264'}
NO_RESTART=('tu1nz_agentmode.service','tu1nz-adult-public-s8-telegram.service','mychatbuddy-private-alpha.service')
HEALTH_UNITS=NO_RESTART+('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service','tu1nz-adult-public-s10-wms.service','tailscaled.service','ssh.service','fail2ban.service','docker.service')
TIMERS=tuple('trendwatch2-'+x+'.timer' for x in ('morning','midday','afternoon','evening'))
TRIGGER_SERVICES=tuple(t.replace('.timer','.service') for t in TIMERS)+('tu1nz-bot.service',)
MYCB_ID='03fa3d34f799c606fae2e12a5482f816d98ed22b303090a076bffcd05ae9ad4e'
CADVISOR_ID='1de50f305be56ca9f5e3669b52068022f288690452aaa13f391b9dc0822fe795'
FIXED_UNSAFE_TRIGGERS=TIMERS+TRIGGER_SERVICES


def verify_container_continuity(before,after):
 if set(before)!=set(after):raise Refused('container inventory changed')
 for name in before:
  b,a=before[name],after[name]
  for field in ('id','image','pid','started','restarts','running','config_sha256','host_sha256','mounts_sha256','networks_sha256'):
   if b[field]!=a[field]:raise Refused('container continuity: '+name+'/'+field)
  if b['health']!=a['health']:raise Refused('container health changed: '+name)
 return True


def verify_unit_continuity(before,after):
 if set(before)!=set(after):raise Refused('unit set drift')
 for name in before:
  if any(before[name].get(k)!=after[name].get(k) for k in ('MainPID','ExecMainStartTimestampMonotonic','ActiveState','SubState','NRestarts','Result')):raise Refused('service continuity: '+name)
 return True


def watchdog_service():
 return '''[Unit]
Description=TU1NZ independent root-only migration rollback
After=local-fs.target
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 -I -S /usr/local/libexec/tu1nz-root-only-v9/entry_v9.py watchdog
TimeoutStartSec=1200
KillMode=control-group
Restart=on-failure
RestartSec=15s
'''


def watchdog_timer():
 return '''[Unit]
Description=TU1NZ migration rollback deadline checker
[Timer]
OnBootSec=30s
OnUnitActiveSec=15s
AccuracySec=1s
Unit=tu1nz-root-only-v9-watchdog.service
[Install]
WantedBy=timers.target
'''


def schedule_window(now,remaining_seconds,timer_due_ns,mono_ns):
 """Fail before activation if a quarantined trigger can fire during the window.
 Wall time is only calendar interpretation, never an elapsed-time proof.
 """
 from datetime import timedelta
 if now.utcoffset()!=timedelta(0):raise Refused('schedule requires UTC')
 horizon=remaining_seconds+300
 midnight=now.replace(hour=0,minute=0,second=0,microsecond=0)
 candidates=[midnight+timedelta(days=d,hours=h) for d in (0,1) for h in range(0,24,2)]
 until=min((t-now).total_seconds() for t in candidates if t>now)
 # A cron process started in the immediately preceding minute may still run.
 if now.hour%2==0 and now.minute<5:raise Refused('root cron boundary window')
 if until<=horizon:raise Refused('root cron overlaps transaction window')
 if len(timer_due_ns)!=4 or any(not isinstance(n,int) or n<=mono_ns+horizon*1_000_000_000 for n in timer_due_ns):raise Refused('Trendwatch timer overlaps transaction window')
 return True
