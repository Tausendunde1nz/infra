"""Phase-1 publication/rollback engine. The caller supplies fixed-scope Files
and an independently verified phase-0 host, never commands from a manifest.
The recovery implementation itself resides in the retained phase-0 worker slot.
"""
from anchor import Refused,encode,digest,tx,pin,parse,TERMINAL
import os
class Installer:
 def __init__(self,store,files,journal,host,inject=lambda point:None):
  self.s=store;self.f=files;self.j=journal;self.h=host;self.inject=inject;self.state=None;self.f.save=self.receipt
 def persist(self):self.j.save(self.state)
 def receipt(self,value):self.state['files']=value;self.persist();self.inject('file_receipt')
 def load(self):
  self.state,_,_=self.j.load()
  if self.state is None:raise Refused('NO_PHASE1_BACKUP')
  if set(self.state)!={'transaction','base_sha256','status','before','manager_before','files','pins','sealed'} or self.state['base_sha256']!=digest(self.s.read('base.json')) or not tx(self.state['transaction']) or set(self.state['before'])!=set(self.f.targets):raise Refused('PHASE1_BACKUP_BINDING')
  self.f.receipts=self.state['files']['receipts'];self.f.created=self.state['files']['created_directories']
 def attest_root(self,transaction):
  if self.s.fixture:return # Component fixtures confer no production admission.
  if os.geteuid()!=0 or self.f.fixture:raise Refused('PHASE1_ROOT_BINDING')
  from attestation import Gate
  from pathlib import Path
  g=Gate(self.s);c=g.context();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  if c['transaction']!=transaction:raise Refused('PHASE1_GUARD_TRANSACTION')
  receipt=g.admit_locked(c,boot,c['recovery_generation'],c['activation_manifest_sha256'],resume=True)
  row=parse(self.s.read('bootstrap.json'))
  if row!={'schema':1,'state':'ATTESTED_BOOTSTRAP','context_sha256':digest(encode(c)),'transaction':transaction,'phase_manifest_sha256':c['activation_manifest_sha256'],'admission':receipt}:raise Refused('PHASE1_ATTESTED_BOOTSTRAP')
 def start(self,transaction,candidates,expected_originals):
  # Serialize publication and recovery; the external systemd timeout is the
  # independent lifetime bound. The fence remains CLOSED throughout publication.
  with self.s.locked(),self.j.locked():
   self.attest_root(transaction)
   self.s.base();self.s.choose();self.h.verify_base();self.h.confirm_closed();self.h.no_worker()
   if parse(self.s.read('phase0.json',0o600))!={'state':'PHASE0_VERIFIED','base_sha256':digest(self.s.read('base.json'))}:raise Refused('PHASE0_NOT_VERIFIED')
   if self.s.exists('stop.json') or self.s.exists('phase1.json') or self.j.load()[0] is not None:raise Refused('DUPLICATE_OR_STOP')
   if not tx(transaction) or set(candidates)!=set(self.f.targets) or set(candidates)!=set(self.s.base()['phase1_paths']) or set(expected_originals)!=set(candidates):raise Refused('PHASE1_SCOPE')
   for path,row in candidates.items():
    if set(row)!={'bytes','sha256','mode','uid','gid'} or type(row['bytes'])!=bytes or digest(row['bytes'])!=row['sha256'] or row['uid']!=0 or row['gid']!=0 or row['mode'] not in (0o400,0o500,0o644):raise Refused('CANDIDATE')
   before=self.f.snapshot(self.f.targets,self.f.directories)
   # Caller pins the complete snapshot, not just content hashes or booleans.
   if before!=expected_originals:raise Refused('ORIGINAL_DRIFT')
   manager_before=self.h.manager_before()
   self.state={'transaction':transaction,'base_sha256':digest(self.s.read('base.json')),'status':'BACKUP_VERIFIED','before':before,'manager_before':manager_before,'files':{'receipts':{},'created_directories':[]},'pins':{p:r['sha256'] for p,r in candidates.items()},'sealed':False}
   self.persist();self.inject('backup')
   phase={'transaction':transaction,'manifest_sha256':digest(encode({'before':before,'manager_before':manager_before,'pins':self.state['pins']})),'paths':self.s.base()['phase1_paths']}
   self.s.write('phase1.json',encode(phase),0o600);self.inject('bound')
   try:
    self.f.create_declared_directories(self.f.directories)
    for p in sorted(candidates):
     self.s.record({'operation':'publish','path':p,'state':'INTENT','sha256':candidates[p]['sha256']})
     self.f.install_exact(p,candidates[p],before);self.f.verify_exact(p,candidates[p]);self.inject('published:'+p)
     self.s.record({'operation':'publish','path':p,'state':'DONE','sha256':candidates[p]['sha256']})
    self.s.record({'operation':'reload','state':'INTENT'});self.h.reload();self.h.verify_published(candidates);self.h.confirm_closed();self.s.record({'operation':'reload','state':'DONE'})
    self.state['status']='PHASE1_PUBLISHED_FENCED';self.persist();return self.state['status']
   except Exception:
    self.s.close_fence();return self._rollback()
 def verify(self,phase):
  self.load()
  if phase['transaction']!=self.state['transaction'] or phase['manifest_sha256']!=digest(encode({'before':self.state['before'],'manager_before':self.state['manager_before'],'pins':self.state['pins']})) or phase['paths']!=self.s.base()['phase1_paths']:raise Refused('PHASE1_MANIFEST_BINDING')
  if self.state['sealed']:raise Refused('POSTSEAL_SECURED_STOP')
  if self.state['status']!=TERMINAL or not self.f.same_restored_snapshot(self.state['before']):raise Refused('ROLLBACK_FILES')
  self.h.verify_restored(self.state['manager_before']);self.h.verify_base();self.h.confirm_closed();return TERMINAL
 def recover(self,phase):
  # The anchor already holds the recovery lock; never reacquire it in its child.
  with self.j.locked():
   self.load();self.attest_root(phase['transaction'])
   if phase['transaction']!=self.state['transaction'] or phase['manifest_sha256']!=digest(encode({'before':self.state['before'],'manager_before':self.state['manager_before'],'pins':self.state['pins']})):raise Refused('RECOVERY_BINDING')
   return self._rollback()
 def _rollback(self):
  self.s.close_fence();self.h.confirm_closed()
  if self.state['sealed']:self.s.stop('POSTSEAL_SECURED_STOP');return 'SECURED_STOP'
  if self.state['status']==TERMINAL:
   self.verify(parse(self.s.read('phase1.json',0o600)));return TERMINAL
  try:
   self.state['status']='ROLLBACK_INTENT';self.persist();self.inject('rollback_intent')
   self.h.quiesce_phase1();self.inject('quiesced')
   self.f.restore_owned_changes(self.state['before'],cleanup=False);self.inject('restored')
   self.h.restore_manager(self.state['manager_before']);self.inject('manager_restored')
   if not self.f.same_restored_snapshot(self.state['before']):raise Refused('ROLLBACK_FILES')
   self.h.verify_restored(self.state['manager_before']);self.h.verify_base();self.h.confirm_closed()
   self.f.restore_owned_changes(self.state['before'],cleanup=True);self.inject('cleanup')
   if not self.f.same_restored_snapshot(self.state['before']):raise Refused('ROLLBACK_FINAL')
   self.state['status']=TERMINAL;self.persist();return TERMINAL
  except Exception as error:self.s.stop(str(error));raise
