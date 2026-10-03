"""Retained, read-only parent verification of directional worker results.
No installer, publication or migration host is embedded in this component.
"""
from pathlib import Path
import os,base64
from anchor import Refused,parse,digest,encode,TERMINAL,VALIDATION_ROOT
from seal_boundary import Chain,UNKNOWN,SEALED_STOP
TARGETS=(
 '/run/tu1nz-v11-phase1-validation/worker.py',
 '/run/tu1nz-v11-phase1-validation/config.json',
 '/run/systemd/system/tu1nz-v11-validation-main.service',
)
GUARD='/run/tu1nz-v11-guard-validation/SEALED'
def verify(s,m,result,read):
 if str(s.path)!=VALIDATION_ROOT or s.fixture or os.geteuid()!=0:raise Refused('DIRECTIONAL_PARENT_PROFILE')
 chain=Chain(s);c=chain.context();s.base();s.choose();s.journal()
 if not s.closed() or m.show('consumer')['ActiveState']!='inactive':raise Refused('DIRECTIONAL_PARENT_FENCE')
 plan=parse(s.read('directional-plan.json'))
 if set(plan)!= {'schema','candidates','originals','artifact_manifest'} or plan['schema']!=1 or plan['artifact_manifest']!=c['artifacts'] or set(plan['candidates'])!=set(TARGETS) or set(plan['originals'])!=set(TARGETS):raise Refused('DIRECTIONAL_PARENT_PLAN')
 if result in (UNKNOWN,SEALED_STOP):
  row=parse(s.read('boundary-stop.json'))
  if row!={'schema':2,'state':result,'context_sha256':digest(encode(c)),'fence':'CLOSED','starts':'CLOSED'}:raise Refused('DIRECTIONAL_PARENT_STOP')
  text=m.call(('show','--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,ExecStart,NeedDaemonReload','--','tu1nz-v11-validation-main.service'))
  row=dict(line.split('=',1) for line in text.splitlines())
  if row.get('ActiveState')!='inactive' or row.get('MainPID') not in ('','0'):raise Refused('DIRECTIONAL_PARENT_STOP_ACTIVE')
  return result
 if result=='COMPLETE':
  chain.complete();marker=parse(read(GUARD,0o400))
  if set(marker)!= {'binding','sealed'} or marker.get('sealed') is not True or set(marker['binding'])!= {'transaction','boot','contract_sha256','deadline_ns','coordinator_pid','coordinator_start_ticks'} or marker['binding']['transaction']!=c['transaction'] or marker['binding']['boot']!=c['origin_boot'] or marker['binding']['contract_sha256']!=c['guard_contract_sha256']:raise Refused('DIRECTIONAL_PARENT_BARRIER')
  for path,row in plan['candidates'].items():
   if row['uid']!=0 or row['gid']!=0 or row['mode']!=(0o500 if path.endswith('.py') else 0o644):raise Refused('DIRECTIONAL_PARENT_MODE')
   raw=read(path,row['mode'])
   if digest(raw)!=row['sha256'] or raw!=base64.b64decode(row['bytes'],validate=True):raise Refused('DIRECTIONAL_PARENT_POSTIMAGE')
 elif result==TERMINAL:
  if s.exists('boundary-sealed.json') or s.exists('boundary-complete.json'):raise Refused('DIRECTIONAL_PARENT_SEALED_ATTESTATION')
  if s.exists('boundary-preseal.json'):chain.ready()
  if s.exists('boundary-intent.json'):chain.intent()
  if Path(GUARD).exists() or Path(GUARD).is_symlink():raise Refused('DIRECTIONAL_PARENT_SEALED_ROLLBACK')
  if any(row!={'absent':True} for row in plan['originals'].values()):raise Refused('DIRECTIONAL_PARENT_ORIGINAL_CONTRACT')
  if any(Path(p).exists() or Path(p).is_symlink() for p in TARGETS):raise Refused('DIRECTIONAL_PARENT_ROLLBACK')
 else:raise Refused('DIRECTIONAL_PARENT_RESULT')
 text=m.call(('show','--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,ExecStart,NeedDaemonReload','--','tu1nz-v11-validation-main.service'))
 d=dict(line.split('=',1) for line in text.splitlines())
 if d.get('ActiveState')!='inactive' or d.get('MainPID') not in ('','0') or d.get('LoadState')!=('loaded' if result=='COMPLETE' else 'not-found') or d.get('NeedDaemonReload')!='no':raise Refused('DIRECTIONAL_PARENT_LOADED_STATE')
 return result
