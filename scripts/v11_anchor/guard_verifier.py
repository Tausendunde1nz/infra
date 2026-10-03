"""Concrete read-only producer verification for an ALREADY completed Guard.
It cannot advance, seal, install or repair Guard. Main-phase admission remains
closed until the ownership of this prerequisite is resolved in the V11 plan.
"""
import os,re
from anchor import *
import runtime as r
class GuardVerifier:
 def __init__(self,base_host):
  if os.geteuid()!=0 or base_host.s.fixture or base_host.profile!='production':raise Refused('PRODUCTION_GUARD_VERIFIER')
  self.h=base_host
 def confirm_closed(self):self.h.verify_base();self.h.confirm_closed()
 def verify_completed(self,c,state):
  self.confirm_closed()
  if state['record_sha256'] is None or state['phase']!='COMPLETED' or state['sealed'] is not True:raise Refused('GUARD_TERMINAL')
  contract=r.contract(c['guard_contract_sha256']);r.verify_files(contract,c['guard_contract_sha256'],True)
  if contract['files'][r.NEW]['sha256']!=c['guard_sha256']:raise Refused('GUARD_CODE_PIN')
  self.h.s.base();p=self.h.p;pin=digest(self.h.s.read('base.json'));py=self.h.s.base()['interpreter']
  g=r.properties(r.command(r.SHOW_GUARD));t=r.properties(r.command(r.SHOW_TIMER))
  anchor_fence=p['unitdir']+'/'+p['consumer']+'.d/99-v11-anchor.conf'
  if set(g)!={'ExecStart','ExecCondition','DropInPaths','Requires','After','ActiveState'} or set(t)!={'Requires','After','DropInPaths','ActiveState','UnitFileState'}:raise Refused('GUARD_LOADED_FIELDS')
  argv=lambda x:re.findall(r'argv\[\]=(.*?) ;',x)
  if argv(g['ExecStart'])!=['/usr/bin/python3 -I -B '+r.NEW] or g['ActiveState']!='inactive':raise Refused('GUARD_LOADED_CONSUMER')
  if argv(g['ExecCondition'])!=['/usr/bin/python3 -I -B '+r.PROGRAM+' condition '+c['guard_contract_sha256'],py+' -I -B '+p['root']+'/anchor.py condition '+pin]:raise Refused('GUARD_LOADED_FENCES')
  if set(g['DropInPaths'].split())!={r.FENCE,r.CONSUMER,anchor_fence} or t['DropInPaths']!=r.TIMER_DEP:raise Refused('GUARD_LOADED_DROPINS')
  if any(r.RECOVERY not in x[k].split() for x in (g,t) for k in ('Requires','After')) or any(p['anchor'] not in g[k].split() for k in ('Requires','After')):raise Refused('GUARD_LOADED_ORDER')
  return True
