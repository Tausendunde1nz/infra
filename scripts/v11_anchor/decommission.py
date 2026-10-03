"""Separate decommission planning. The anchor never calls this module.
Executable removal is restricted to the literal validation profile and requires
an external root controller; production decommission is planning-only here.
"""
import os,re
from anchor import *
import manager
STEPS=('STOP_WATCH','DISABLE_WATCH','STOP_ANCHOR','DISABLE_ANCHOR','RESTORE_PHASE0_FILES','RELOAD','VERIFY_ORIGINAL_MANAGER')
def normalized(row):
 d={k:v for k,v in row.items() if k not in ('MainPID','Result','SubState')}
 for k in ('After','Before','Requires','DropInPaths'):d[k]=sorted(d[k].split())
 for k in ('ExecStart','ExecCondition'):d[k]=re.sub(r' ; start_time=.*?(?= \})','',d[k])
 return d
def plan(store,host):
 with store.locked():
  store.base();store.choose();host.verify_base();host.confirm_closed();host.no_worker()
  if store.exists('phase1.json'):
   phase=parse(store.read('phase1.json',0o600))
   if not store.exists('terminal.json'):raise Refused('NONTERMINAL_DECOMMISSION')
   if parse(store.read('terminal.json'))!={'state':TERMINAL,'phase1_sha256':digest(encode(phase)),'base_sha256':digest(store.read('base.json'))}:raise Refused('DECOMMISSION_TERMINAL')
   host.verify_rollback(phase)
  return {'base_sha256':digest(store.read('base.json')),'steps':list(STEPS),'production_execution_allowed':False}
def execute_validation(store,installation,systemd):
 if os.geteuid()!=0 or store.fixture or str(store.path)!=VALIDATION_ROOT or installation.profile!='validation':raise Refused('VALIDATION_DECOMMISSION_ONLY')
 state,_,_=installation.j.load()
 if state is None or state['base_sha256']!=digest(store.read('base.json')):raise Refused('DECOMMISSION_BACKUP')
 installation.state=state;installation.f.receipts=state['files']['receipts'];installation.f.created=state['files']['created_directories']
 for role in ('watch','anchor'):
  row=systemd.show(role)
  if row['ActiveState']!='inactive':systemd.action('stop',role)
  if row['UnitFileState'].startswith('enabled'):systemd.action('disable',role)
 installation.f.restore_owned_changes(state['before'],cleanup=False);systemd.action('daemon-reload')
 actual={r:systemd.show(r) for r in ('anchor','watch','consumer')}
 if any(normalized(actual[r])!=normalized(state['manager_before'][r]) for r in actual):raise Refused('DECOMMISSION_MANAGER')
 installation.f.restore_owned_changes(state['before'],cleanup=True)
 if not installation.f.same_restored_snapshot(state['before']):raise Refused('DECOMMISSION_FILES')
 return 'VALIDATION_DECOMMISSION_VERIFIED'
