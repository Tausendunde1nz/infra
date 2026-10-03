"""Fixed phase-0 systemd graph. Validation names never alias production names."""
import re,os,subprocess
from anchor import Refused,pin,digest,encode
PROFILES={
 'production':{'root':'/var/lib/tu1nz-v11-anchor','unitdir':'/etc/systemd/system','anchor':'tu1nz-v11-anchor.service','watch':'tu1nz-v11-anchor-watch.timer','consumer':'tu1nz_delete_guard.service'},
 'validation':{'root':'/run/tu1nz-v11-anchor-validation','unitdir':'/run/systemd/system','anchor':'tu1nz-v11-validation-anchor.service','watch':'tu1nz-v11-validation-watch.timer','consumer':'tu1nz-v11-validation-consumer.service'}}
ENV={'PATH':'/usr/bin:/bin','HOME':'/var/empty','LC_ALL':'C','SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0'}
PROPS=('Id','LoadState','ActiveState','SubState','UnitFileState','MainPID','NeedDaemonReload','ExecStart','ExecCondition','FragmentPath','DropInPaths','Requires','After','Before','User','Group','UMask','PrivateNetwork','NoNewPrivileges','Result')
def profile(name):
 if name not in PROFILES:raise Refused('UNIT_PROFILE')
 return dict(PROFILES[name])
def templates(name,base_pin,interpreter):
 p=profile(name)
 if not pin(base_pin) or not re.fullmatch('/usr/bin/python3\\.[0-9]+',interpreter):raise Refused('UNIT_INTERPRETER_PIN')
 command=interpreter+' -I -B '+p['root']+'/anchor.py '
 service='[Unit]\nDescription=TU1NZ retained recovery anchor\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=timers.target '+p['consumer']+'\nRequiresMountsFor='+p['root']+'\nStartLimitIntervalSec=120\nStartLimitBurst=3\n[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nPrivateNetwork=yes\nKillMode=control-group\nTimeoutStartSec=360\nTimeoutStopSec=15\nRestart=on-failure\nRestartSec=5\nExecStart='+command+'recover '+base_pin+'\n[Install]\nWantedBy=sysinit.target\n'
 watch='[Unit]\nDescription=TU1NZ recovery anchor watchdog\n[Timer]\nOnBootSec=15\nOnUnitInactiveSec=15\nAccuracySec=1\nUnit='+p['anchor']+'\n[Install]\nWantedBy=timers.target\n'
 fence='[Unit]\nRequires='+p['anchor']+'\nAfter='+p['anchor']+'\n[Service]\nExecCondition='+command+'condition '+base_pin+'\n'
 return {p['anchor']:service.encode(),p['watch']:watch.encode(),p['consumer']+'.d/99-v11-anchor.conf':fence.encode()}
def allowed_calls(p):
 out={('daemon-reload',),('show','--property=Id,NeedDaemonReload','--','*')}
 for role in ('anchor','watch','consumer'):
  out.add(('show','--property='+','.join(PROPS),'--',p[role]))
 for role in ('anchor','watch'):
  for verb in ('start','stop'):out.add((verb,'--',p[role]))
  for verb in ('enable','disable'):out.add((verb,'--no-reload',*(['--runtime'] if p['unitdir']=='/run/systemd/system' else []),'--',p[role]))
 if p['root']=='/run/tu1nz-v11-anchor-validation':
  main='tu1nz-v11-validation-main.service'
  for props in ('Id','LoadState','Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,ExecStart,NeedDaemonReload'):
   out.add(('show','--property='+props,'--',main))
  for verb in ('start','stop'):out.add((verb,'--',main))
  out.add(('start','--',p['consumer']))
  out.add(('show','--property=ExecMainStartTimestampMonotonic,MainPID','--',p['consumer']))
  for unit in (main,p['anchor']):out.add(('kill','--kill-whom=all','--signal=SIGKILL','--',unit))
 return out

class Manager:
 def __init__(self,name,record,close,runner=None):
  self.p=profile(name);self.record=record;self.close=close;self.runner=runner or subprocess.run;self.real=runner is None
  if runner is None and os.geteuid()!=0:raise Refused('ROOT_MANAGER')
 def call(self,args):
  if type(args)!=tuple or args not in allowed_calls(self.p):raise Refused('FIXED_TRANSPORT_SCOPE')
  try:r=self.runner(('/usr/bin/systemctl','--no-pager','--no-ask-password',*args),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=30)
  except (OSError,subprocess.TimeoutExpired):self.close();raise Refused('SYSTEMD_TRANSPORT') from None
  if r.returncode or len(r.stdout)>1_048_576:self.close();raise Refused('SYSTEMD_RESULT')
  return r.stdout.decode('utf-8')
 def show(self,role):
  if role not in ('anchor','watch','consumer'):raise Refused('UNIT_ROLE')
  d={}
  for line in self.call(('show','--property='+','.join(PROPS),'--',self.p[role])).splitlines():
   if '=' not in line:raise Refused('SHOW_SHAPE')
   k,v=line.split('=',1)
   if k in d or k not in PROPS:raise Refused('SHOW_PROPERTY')
   d[k]=v
  if set(d)!=set(PROPS) or d['Id']!=self.p[role]:raise Refused('SHOW_IDENTITY')
  return d
 def action(self,verb,role=None):
  allowed={('daemon-reload',None)}|{(a,r) for a in ('start','stop','enable','disable') for r in ('anchor','watch')}
  if (verb,role) not in allowed:raise Refused('ACTION_SCOPE')
  before={r:self.show(r) for r in ('anchor','watch','consumer')}
  if verb=='stop' and before[role]['MainPID']==str(os.getpid()):raise Refused('SELF_STOP')
  self.record({'state':'INTENT','operation':verb,'role':role,'observed_sha256':digest(encode(before))})
  if verb=='daemon-reload' and self.real:
   permitted={self.p[r] for r in ('anchor','watch','consumer')}
   if self.p['anchor']=='tu1nz-v11-validation-anchor.service':permitted.add('tu1nz-v11-validation-main.service')
   no_foreign_reload(self.call(('show','--property=Id,NeedDaemonReload','--','*')),permitted)
  args=(verb,) if role is None else ((verb,'--no-reload',*(['--runtime'] if self.p['unitdir']=='/run/systemd/system' else []),'--',self.p[role]) if verb in ('enable','disable') else (verb,'--',self.p[role]))
  self.call(args)
  after={r:self.show(r) for r in ('anchor','watch','consumer')}
  if verb=='daemon-reload':ok=all(v['NeedDaemonReload']=='no' for v in after.values())
  elif verb=='start':ok=after[role]['ActiveState']=='active' if role=='watch' else after[role]['Result']=='success' and after[role]['ActiveState']=='inactive'
  elif verb=='stop':ok=after[role]['ActiveState']=='inactive'
  elif verb=='enable':ok=after[role]['UnitFileState']==('enabled-runtime' if self.p['unitdir']=='/run/systemd/system' else 'enabled')
  else:ok=after[role]['UnitFileState'] in ('disabled','static','not-found','')
  if not ok:self.close();raise Refused('ACTION_POSTCONDITION')
  self.record({'state':'DONE','operation':verb,'role':role,'observed_sha256':digest(encode(after))});return after
 def verify(self,base_pin,interpreter):
  p=self.p;rows={r:self.show(r) for r in ('anchor','watch','consumer')}
  if any(x['LoadState']!='loaded' or x['NeedDaemonReload']!='no' for x in rows.values()):raise Refused('PHASE0_NOT_LOADED')
  expected=interpreter+' -I -B '+p['root']+'/anchor.py '
  if re.findall(r'argv\[\]=(.*?) ;',rows['anchor']['ExecStart'])!=[expected+'recover '+base_pin]:raise Refused('ANCHOR_EXEC')
  if expected+'condition '+base_pin not in re.findall(r'argv\[\]=(.*?) ;',rows['consumer']['ExecCondition']):raise Refused('FENCE_EXEC')
  if rows['anchor']['FragmentPath']!=p['unitdir']+'/'+p['anchor'] or rows['anchor']['DropInPaths'] or rows['anchor']['User']!='root' or rows['anchor']['Group']!='root' or rows['anchor']['UMask']!='0077' or rows['anchor']['PrivateNetwork']!='yes' or rows['anchor']['NoNewPrivileges']!='yes':raise Refused('ANCHOR_LOADED_DRIFT')
  if p['anchor'] not in rows['consumer']['Requires'].split() or p['anchor'] not in rows['consumer']['After'].split():raise Refused('FENCE_ORDER')
  return digest(encode(rows))

def no_foreign_reload(text,permitted):
 rows=[];row={}
 for line in text.splitlines()+['']:
  if not line:
   if row:rows.append(row);row={}
   continue
  if '=' not in line:raise Refused('RELOAD_SCAN_SHAPE')
  k,v=line.split('=',1)
  if k not in ('Id','NeedDaemonReload') or k in row:raise Refused('RELOAD_SCAN_PROPERTY')
  row[k]=v
 if not rows:raise Refused('RELOAD_SCAN_EMPTY')
 for row in rows:
  if set(row)!={'Id','NeedDaemonReload'} or row['NeedDaemonReload'] not in ('yes','no'):raise Refused('RELOAD_SCAN_INCOMPLETE')
  if row['NeedDaemonReload']=='yes' and row['Id'] not in permitted:raise Refused('FOREIGN_PENDING_DAEMON_RELOAD')
 return True
