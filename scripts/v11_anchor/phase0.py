"""Phase-0 preparation only. Root publication of units is a separate adapter.
Preparation is immutable and repeatable; never repairs an unexpected existing
base. No phase-1 payload can be emitted from this module.
"""
from pathlib import Path
import os
from anchor import *

def prepare(path,anchor_bytes,worker_bytes,interpreter,interpreter_sha256,phase1_paths,fixture=False,validation=False,created=lambda identity:None):
 if type(anchor_bytes)!=bytes or not anchor_bytes or type(worker_bytes)!=list or not worker_bytes or len(worker_bytes)>2 or any(type(b)!=bytes or not b for b in worker_bytes):raise Refused('PREPARATION_INPUT')
 if not fixture:
  f=trusted_program(interpreter,interpreter_sha256);os.close(f)
 base={'schema':1,'anchor_sha256':digest(anchor_bytes),'interpreter':interpreter,'interpreter_sha256':interpreter_sha256,'workers':[digest(b) for b in worker_bytes],'phase1_paths':phase1_paths}
 # Validate all paths and pins before creating a preparation directory.
 if not pin(interpreter_sha256) or len(set(base['workers']))!=len(base['workers']):raise Refused('PREPARATION_PINS')
 phase1_scope(phase1_paths)
 existing=Path(path).exists() or Path(path).is_symlink()
 s=Store(path,fixture=fixture,create=not existing,validation=validation,created=created)
 try:
  if existing:
   if s.base()!=base or s.choose()['sha256'] not in base['workers'] or not s.closed():raise Refused('EXISTING_BASE_DRIFT')
   s.journal();return {'state':'PREPARED','base_sha256':digest(encode(base)),'changed':False}
  with s.locked():
   s.record({'operation':'prepare','state':'INTENT','base_sha256':digest(encode(base))})
   s.write('anchor.py',anchor_bytes,0o500);s.write('base.json',encode(base));s.close_fence();s.base()
  s.publish_slot('A',worker_bytes[0])
  with s.locked():s.record({'operation':'prepare','state':'DONE','base_sha256':digest(encode(base))})
  return {'state':'PREPARED','base_sha256':digest(encode(base)),'changed':True}
 finally:s.close()

def phase1_admitted(store,host):
 # Neither directory existence nor a PREPARED marker admits the main phase.
 with store.locked():
  if store.exists('stop.json'):raise Refused('SECURED_STOP')
  store.base();store.choose();store.journal();host.verify_base();host.confirm_closed();host.no_worker()
  phase0=parse(store.read('phase0.json',0o600))
  if phase0!={'state':'PHASE0_VERIFIED','base_sha256':digest(store.read('base.json'))}:raise Refused('PHASE0_NOT_VERIFIED')
  return True
