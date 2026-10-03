"""Bounded systemctl transport and independently observed action postconditions.
No arbitrary command, unit, journal verb, shell, inherited environment or sudo.
Stored metadata is supplied by the pinned file backend; loaded state is queried
from the manager separately. Sensitive property values are never logged.
"""
import os,re,subprocess,hashlib,json
import units
from pathlib import Path
from core import Refused,raw,sha
NAMES=(units.BOOT,units.WORK,units.WATCH,units.TIMER,units.GUARD,units.LEGACY_TIMER)
OWNED=(units.BOOT,units.WORK,units.WATCH,units.TIMER)
PROPERTIES=('MainPID','Result','ExecMainCode','ExecMainStatus','Id','LoadState','ActiveState','SubState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload','ExecStart','ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost','User','Group','UMask','Environment','EnvironmentFiles','RootDirectory','RootImage','WorkingDirectory','NoNewPrivileges','ProtectSystem','ProtectHome','PrivateNetwork','ReadWritePaths','Requires','After','Before','Restart','RestartUSec','StartLimitBurst','StartLimitIntervalUSec')
ALLOWED={('daemon-reload',None)}|{(a,n) for n in OWNED for a in ('start','stop')}|{(a,n) for n in (units.BOOT,units.TIMER) for a in ('enable','disable')}|{(a,n) for n in (units.WORK,units.WATCH) for a in ('mask','unmask')}
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0','HOME':'/var/empty'}
class Ambiguous(Refused):pass

def parse_show(data):
 if type(data)!=bytes or len(data)>1048576:raise Refused('MANAGER_OUTPUT_SIZE')
 try:text=data.decode('utf-8')
 except UnicodeError:raise Refused('MANAGER_ENCODING') from None
 out={}
 for line in text.splitlines():
  if '=' not in line:raise Refused('MANAGER_SHAPE')
  k,v=line.split('=',1)
  if k not in PROPERTIES or k in out:raise Refused('MANAGER_PROPERTY')
  out[k]=v
 if set(out)!=set(PROPERTIES):raise Refused('MANAGER_INCOMPLETE')
 return out

def execution_identity(value):
 # Keep executable/argv/ignore-failure exactly; only systemd execution history
 # (timestamps, PID and exit result) may differ after start/stop.
 return re.sub(r' ; start_time=.*?(?= \})','',value)

def configuration(value):
 out={k:v for k,v in value.items() if k not in ('ActiveState','SubState','NeedDaemonReload','MainPID','Result','ExecMainCode','ExecMainStatus')}
 for k in ('Requires','After','Before','DropInPaths'):out[k]=sorted(out[k].split())
 for k in ('ExecStart','ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost'):out[k]=execution_identity(out[k])
 return out

def current_units():
 # MainPID alone misses helper descendants. Membership in the actual cgroup
 # is checked as well; no environment variable can select the execution unit.
 data=Path('/proc/self/cgroup').read_bytes()
 if len(data)>65536:raise Refused('CALLER_CGROUP_SIZE')
 try:lines=data.decode('ascii').splitlines()
 except UnicodeError:raise Refused('CALLER_CGROUP_ENCODING') from None
 found=set()
 for line in lines:
  fields=line.split(':',2)
  if len(fields)!=3 or not fields[2].startswith('/'):raise Refused('CALLER_CGROUP_SHAPE')
  found.update(set(fields[2].split('/')) & set(OWNED))
 return found

class Systemd:
 def __init__(self,record,close_fence,runner=None,timeout=30):
  if not callable(record) or not callable(close_fence) or timeout!=30:raise Refused('MANAGER_CONSTRUCTION')
  if runner is None and os.geteuid()!=0:raise Refused('ROOT_MANAGER_REQUIRED')
  self.record=record;self.close_fence=close_fence;self.runner=runner or subprocess.run;self.offline=runner is not None
 def _run(self,args):
  try:
   r=self.runner(('/usr/bin/systemctl','--no-pager','--no-ask-password',*args),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=ENV)
  except subprocess.TimeoutExpired:raise Ambiguous('SYSTEMCTL_TIMEOUT') from None
  except OSError:raise Ambiguous('SYSTEMCTL_UNAVAILABLE') from None
  if not isinstance(r.returncode,int) or type(r.stdout)!=bytes or type(r.stderr)!=bytes:raise Ambiguous('SYSTEMCTL_RESULT')
  if r.returncode!=0:raise Ambiguous('SYSTEMCTL_NONZERO')
  return r.stdout
 def show(self,name):
  if name not in NAMES:raise Refused('UNIT_SCOPE')
  value=parse_show(self._run(('show','--property='+','.join(PROPERTIES),'--',name)))
  if value['Id']!=name:raise Refused('UNIT_ALIAS')
  return value
 def snapshot(self):return {n:self.show(n) for n in NAMES}
 def action(self,action,name=None):
  if (action,name) not in ALLOWED:raise Refused('MANAGER_ACTION_SCOPE')
  before=self.snapshot() if action=='daemon-reload' else self.show(name)
  if action=='stop' and (name in current_units() or before['MainPID']==str(os.getpid())):
   self.close_fence();raise Refused('RECOVERY_MUST_NOT_STOP_ITSELF')
  self.record({'operation':action,'unit':name,'stage':'INTENT','before_sha256':sha(raw(before))})
  args=(action,) if name is None else ((action,'--runtime','--',name) if action in ('mask','unmask') else (action,'--',name))
  try:
   self._run(args)
   after=self.snapshot() if action=='daemon-reload' else self.show(name)
   if action=='daemon-reload':ok=all(v['NeedDaemonReload']=='no' for v in after.values() if v['LoadState']=='loaded')
   elif action=='start':ok=after['Result']=='success' and (after['ActiveState']=='active' or (name in (units.WORK,units.WATCH) and after['ActiveState']=='inactive' and after['ExecMainStatus']=='0'))
   elif action=='stop':ok=after['ActiveState']=='inactive'
   elif action=='enable':ok=after['UnitFileState']=='enabled'
   elif action=='disable':ok=after['UnitFileState'] in ('disabled','static','not-found','')
   elif action=='mask':ok=after['UnitFileState']=='masked-runtime' and after['LoadState']=='masked'
   else:ok=not after['UnitFileState'].startswith('masked') and after['LoadState']!='masked'
   if not ok:raise Ambiguous('MANAGER_POSTCONDITION')
   self.record({'operation':action,'unit':name,'stage':'DONE','after_sha256':sha(raw(after))})
   return after
  except Exception as error:
   self.close_fence()
   # A timeout/nonzero never proves that a D-Bus action did not happen.
   try:observed=self.snapshot() if name is None else self.show(name);pin=sha(raw(observed))
   except Exception:pin=None
   self.record({'operation':action,'unit':name,'stage':'AMBIGUOUS','error':type(error).__name__,'observed_sha256':pin})
   raise
 def dispatch(self):
  self.record({'operation':'dispatch','unit':units.WORK,'stage':'INTENT'})
  try:
   self._run(('start','--no-block','--job-mode=fail','--',units.WORK))
   state=self.show(units.WORK)
   if state['LoadState']!='loaded':raise Ambiguous('DISPATCH_NOT_LOADED')
   self.record({'operation':'dispatch','unit':units.WORK,'stage':'QUEUED','observed_sha256':sha(raw(state))})
   return state
  except Exception:self.close_fence();raise
 def verify_loaded(self,expected):
  if set(expected)!=set(NAMES):raise Refused('LOADED_SCOPE')
  actual=self.snapshot()
  if any(actual[n]['NeedDaemonReload']!='no' or configuration(actual[n])!=expected[n] for n in NAMES):
   self.close_fence();raise Refused('LOADED_CONFIGURATION_DRIFT')
  return sha(raw({n:configuration(v) for n,v in actual.items()}))
 def restore(self,before):
  if set(before)!=set(NAMES) or any(set(v)!=set(PROPERTIES) or v['Id']!=n for n,v in before.items()):raise Refused('RESTORE_MANAGER_SCHEMA')
  # This bootstrap only admits fresh outer units. It never replaces a foreign
  # installed recovery service or interprets commands from a stored snapshot.
  if any(before[n]['LoadState']!='not-found' or before[n]['ActiveState']!='inactive' for n in OWNED):raise Refused('PREEXISTING_OUTER_MANAGER')
  current=self.snapshot()
  if current_units() or any(v['MainPID']==str(os.getpid()) for n,v in current.items() if n in OWNED):
   self.close_fence();raise Refused('PUBLICATION_RECOVERY_REQUIRES_EXTERNAL_ANCHOR')
  for n in (units.TIMER,units.WATCH,units.WORK,units.BOOT):
   current=self.show(n)
   if current['ActiveState']!='inactive':self.action('stop',n)
   if n in (units.WORK,units.WATCH) and current['UnitFileState'].startswith('masked'):self.action('unmask',n)
   if n in (units.BOOT,units.TIMER) and current['UnitFileState']=='enabled':self.action('disable',n)
  self.action('daemon-reload')
  return self.verify_restored(before)
 def verify_restored(self,before):
  actual=self.snapshot()
  for n in NAMES:
   if configuration(actual[n])!=configuration(before[n]) or (actual[n]['ActiveState'],actual[n]['SubState'])!=(before[n]['ActiveState'],before[n]['SubState']):
    self.close_fence();raise Refused('RESTORE_MANAGER_DRIFT')
  return sha(raw(actual))
