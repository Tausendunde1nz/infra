"""Fixed service adapter, no CLI. Unit installation belongs to the root bundle.
All calls require a caller-owned transaction lock and verified checkpoint.
A changed InvocationID makes rollback refuse instead of stopping a foreign run.
"""
import json,os,re,subprocess
UNIT='tu1nz_agentmode.service'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/var/empty'}
SHOW=('/usr/bin/systemctl','show','--property=Id,ActiveState,SubState,InvocationID,MainPID,User,Group,NeedDaemonReload','--',UNIT)
START=('/usr/bin/systemctl','start','--job-mode=fail','--',UNIT)
STOP=('/usr/bin/systemctl','stop','--job-mode=fail','--',UNIT)
class Refused(RuntimeError):pass

def execute(argv):
 if os.geteuid()!=0 or argv not in (SHOW,START,STOP):raise Refused('ROOT_FIXED_COMMAND_REQUIRED')
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,cwd='/',timeout=90)
 if p.returncode or len(p.stdout)>10000:raise Refused('SYSTEMD_CALL_FAILED')
 return p.stdout.decode()

def state(run):
 r=dict(line.split('=',1) for line in run(SHOW).splitlines() if '=' in line)
 if set(r)!={'Id','ActiveState','SubState','InvocationID','MainPID','User','Group','NeedDaemonReload'} or r['Id']!=UNIT or r['User']!='chatops' or r['Group']!='chatops' or r['NeedDaemonReload']!='no':raise Refused('UNIT_STATE_DRIFT')
 if not re.fullmatch('[0-9a-f]{32}',r['InvocationID']) or not r['MainPID'].isdigit():raise Refused('UNIT_IDENTITY')
 return r

class Adapter:
 def __init__(self,run=execute):self.run=run
 def start(self,checkpoint,admission,save_receipt):
  if admission!={'transaction_lock_held':True,'checkpoint_verified':True,'new_unit_and_source_verified':True,'restart_preflight_passed':True}:raise Refused('PRECONDITIONS')
  before=state(self.run)
  if before!=checkpoint or before['ActiveState']!='inactive' or before['MainPID']!='0':raise Refused('NOT_EXPECTED_STOPPED_UNIT')
  self.run(START);after=state(self.run)
  if after['InvocationID']==before['InvocationID'] or after['ActiveState']!='active' or after['SubState']!='running' or after['MainPID']=='0':raise Refused('START_NOT_CONFIRMED')
  receipt={'unit':UNIT,'invocation_id':after['InvocationID'],'pid':after['MainPID']}
  # Persist immediately; a crash or failed receipt leaves ownership UNPROVEN.
  # The coordinator must not blindly issue STOP when no receipt exists.
  save_receipt(receipt);return receipt
 def stop_owned(self,receipt):
  if set(receipt)!={'unit','invocation_id','pid'} or receipt['unit']!=UNIT:raise Refused('RECEIPT')
  before=state(self.run)
  if before['InvocationID']!=receipt['invocation_id']:raise Refused('FOREIGN_INVOCATION')
  if before['ActiveState']=='inactive' and before['MainPID']=='0':return True
  if before['MainPID']!=receipt['pid']:raise Refused('FOREIGN_PID')
  self.run(STOP);after=state(self.run)
  if after['ActiveState']!='inactive' or after['MainPID']!='0' or after['InvocationID']!=receipt['invocation_id']:raise Refused('STOP_NOT_CONFIRMED')
  return True


def recovery_dropin(expected_head):
 if not re.fullmatch('[0-9a-f]{40}',expected_head):raise Refused('DETACHED_HEAD_PIN')
 return ('[Service]\nExecStart=\nExecStart=/bin/bash /usr/local/libexec/tu1nz-privileged-v11/agentmode_observer.sh --loop\n'
         'Environment=TU1NZ_EXPECTED_DETACHED_HEAD='+expected_head+'\n')
