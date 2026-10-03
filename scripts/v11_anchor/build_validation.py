"""Render one non-activating root validation artifact; no root execution."""
import base64,re,hashlib
from pathlib import Path
import build_anchor

def fault_worker(normal):
 marker='import host,anchor'
 if normal.decode().count(marker)!=1:raise ValueError('WORKER_ENTRY')
 injected="""
# Validation-only interruption point: once, after restoring phase-1 files.
if PROFILE!='validation':raise SystemExit(78)
import phase1,time
_original=phase1.Installer.__init__
def _validation_init(self,*args,**kwargs):
 _original(self,*args,**kwargs)
 def point(name):
  if name=='restored' and not any(r['event'].get('operation')=='validation_pause' for r in self.s.journal()[0]):
   self.s.record({'operation':'validation_pause','state':'FILES_RESTORED'})
   time.sleep(45)
 self.inject=point
phase1.Installer.__init__=_validation_init
"""
 return normal.decode().replace(marker,injected+'\n'+marker).encode()
def render(directory,interpreter,interpreter_sha256,transaction,handoff=None):
 if not re.fullmatch('/usr/bin/python3\\.[0-9]+',interpreter) or not re.fullmatch('[0-9a-f]{64}',interpreter_sha256) or not re.fullmatch('v11-[0-9a-f]{32}',transaction):raise ValueError('PIN_INPUT')
 d=Path(directory);capsule=build_anchor.build(d,'validation');b=fault_worker(capsule['worker'])
 rows=build_anchor.modules(d)+[(n,(d/(n+'.py')).read_bytes()) for n in ('decommission','root_validation','control_handoff','outer_supervisor','validation_scope','bound_validation')]
 prelude='import os,sys\nif os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode:raise SystemExit(78)\n'
 source=prelude+("raise SystemExit('WAITING_FOR_CONTROL_HANDOFF')\n" if handoff is None else '')+build_anchor.embedded(rows)+'\nimport bound_validation\nCAPSULE='+repr(capsule)+'\nWORKER_B='+repr(b)+'\nHANDOFF='+repr(handoff)+'\nraise SystemExit(bound_validation.launch(CAPSULE,WORKER_B,'+repr(interpreter)+','+repr(interpreter_sha256)+','+repr(transaction)+',HANDOFF,'+repr(hashlib.sha256(__import__('json').dumps(handoff,sort_keys=True,separators=(',',':')).encode()+b'\n').hexdigest() if handoff is not None else None)+'))\n'
 raw=source.encode();compile(raw,'root-validation.py','exec')
 return {'root_validation_ready':False,'offline_stage_b_ready':True,'control_handoff_status':'CONTROL_HANDOFF_PENDING' if handoff is None else 'SUPPLIED_NOT_ROOT_VERIFIED','blocked_by':['CONTROL_HANDOFF_PENDING'] if handoff is None else ['ROOT_VALIDATION_NOT_RUN'],'bytes':raw,'sha256':hashlib.sha256(raw).hexdigest(),'anchor_sha256':hashlib.sha256(capsule['anchor']).hexdigest(),'worker_a_sha256':hashlib.sha256(capsule['worker']).hexdigest(),'worker_b_sha256':hashlib.sha256(b).hexdigest(),'transaction':transaction}
