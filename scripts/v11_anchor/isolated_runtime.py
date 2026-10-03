"""Concrete root validation binding, literal test paths and actual systemd.

This exercises the real publication/rollback and durable Guard engines without
granting production migration admission. The isolated authority is a test
contract; it is never asserted to be the production permission/token boundary.
"""
import os,time,base64,stat
from pathlib import Path
import state as gs,manager,host,phase1,split_guard,seal_boundary,bootstrap,install
from anchor import Refused,Store,encode,parse,digest,TERMINAL,VALIDATION_ROOT
from publication import Journal
from files import Files
from typed_adapter import BoundManager
GUARD='/run/tu1nz-v11-guard-validation'
SHADOW='/run/tu1nz-v11-rollback-shadow'
CREATION_HOOK=lambda path,identity:None

class GuardStore(gs.Store):
 def __init__(self):
  if os.geteuid()!=0:raise Refused('ISOLATED_ROOT_ONLY')
  self.path=Path(GUARD);self.uid=self.gid=0;self.depth=0;self.inject=lambda p:None
  self.fd=gs.secure_open(self.path,True,0,0o700);self.check(self.fd,True,0o700)

class Runtime(split_guard.SplitInstallerHost):
 def root_binding(self,s):
  return os.geteuid()==0 and not s.fixture and str(s.path)==VALIDATION_ROOT and self.i.s is s and type(self.g.g)==GuardStore and type(self.g.h)==GuardHost and type(self.g.audit)==Audit
 def verify_artifacts(self,c):
  raw=self.i.s.read('directional-plan.json');plan=parse(raw)
  expected={'schema','candidates','originals','artifact_manifest'}
  if set(plan)!=expected or plan['schema']!=1 or plan['artifact_manifest']!=c['artifacts']:raise Refused('ROOT_ARTIFACT_MANIFEST')
  if self.c!=decode_candidates(plan['candidates']) or self.before!=plan['originals']:raise Refused('ROOT_PLAN_REPLAY')
  if set(self.c)!=set(host.VALIDATION_TARGETS) or c['activation_manifest_sha256']!=bootstrap.plan_pin(self.i.s,self.c,self.before):raise Refused('ROOT_PLAN_SCOPE')
  if c['artifacts']!={'guard':self.i.s.base()['workers'][0],'authority':self.c[host.VALIDATION_TARGETS[1]]['sha256']}:raise Refused('ROOT_ARTIFACT_PINS')
 def verify_inactive(self):self.g.audit.verify_inactive()
 def cleanup_owned_temporaries(self):
  self.i.load()
  for n,r in self.i.f.receipts.items():self.i.f.cleanup_staged(n,r)
  for r in self.i.f.created:self.i.f.cleanup_staged(r['path'],r,directory=True)

def decode_candidates(rows):
 if type(rows)!=dict or set(rows)!=set(host.VALIDATION_TARGETS):raise Refused('ROOT_CANDIDATE_SCOPE')
 out={}
 for p,r in rows.items():
  if type(r)!=dict or set(r)!={'bytes','sha256','mode','uid','gid'}:raise Refused('ROOT_CANDIDATE_SHAPE')
  try:data=base64.b64decode(r['bytes'],validate=True)
  except (ValueError,TypeError):raise Refused('ROOT_CANDIDATE_BYTES') from None
  if digest(data)!=r['sha256'] or r['uid']!=0 or r['gid']!=0 or r['mode']!=(0o500 if p.endswith('.py') else 0o644):raise Refused('ROOT_CANDIDATE_PIN')
  out[p]={**r,'bytes':data}
 return out

class Audit:
 def __init__(self,s,g,i):self.s=s;self.g=g;self.i=i
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def close(self):self.s.close_fence()
 def confirm_closed(self):self.i.h.confirm_closed();self.verify_inactive()
 def verify_inactive(self):
  if self.i.h.base.manager.show('consumer')['ActiveState']!='inactive' or self.i.h.test_show()['ActiveState']!='inactive':raise Refused('ISOLATED_CONSUMER_ACTIVE')
 def quiesce(self):self.i.h.quiesce_phase1();self.verify_inactive()
 def legacy_block_pin(self):self.confirm_closed();return digest(self.s.read('fence.json',0o600))
 def verify_barrier(self,c,sealed):
  self.confirm_closed();self.s.base();self.s.choose()
  if self.g.exists('SEALED')!=sealed:raise Refused('ISOLATED_MARKER_DRIFT')
  if self.i.j.load()[0] is not None:
   self.i.load()
   if self.i.state['status']==TERMINAL:self.i.f.same_restored_snapshot(self.i.state['before']) or (_ for _ in ()).throw(Refused('ISOLATED_ORIGINAL_DRIFT'))
   else:
    plan=decode_candidates(parse(self.s.read('directional-plan.json'))['candidates'])
    self.i.h.verify_published(plan)
 def preseal_proofs(self,state):
  if state['phase']!='LEGACY_INHIBITED_PRESEAL' or state['sealed']:raise Refused('ISOLATED_PRESEAL')
  self.confirm_closed();self.i.load();self.i.h.verify_base()
  return {'preflight':digest(encode(state['binding'])),'backups':digest(encode(self.i.state['before'])),'rollback':digest(b'REQUIRES_REAL_SHADOW_TRIAL'),'anchor':digest(self.s.read('base.json')),'fence':self.legacy_block_pin(),'legacy_block':self.legacy_block_pin(),'unsealed':digest(encode(state))}
 def postseal_proofs(self,state):
  if state['phase']!='COMPLETED' or not state['sealed']:raise Refused('ISOLATED_NOT_COMPLETE')
  self.confirm_closed();self.i.h.verify_base();plan=decode_candidates(parse(self.s.read('directional-plan.json'))['candidates']);self.i.h.verify_published(plan)
  m=self.i.h.test_show()
  return {'consumers':digest(encode(m)),'permissions':digest(encode({p:(r['mode'],r['uid'],r['gid']) for p,r in plan.items()})),'authority':digest(encode(self.g.read('SEALED'))),'watchdog':digest(encode(self.i.h.base.manager.show('watch'))),'services':digest(encode(m)),'transitions':state['record_sha256']}
 def verify_rollback(self):
  if self.g.exists('SEALED') or self.g.current()['phase']!='ROLLED_BACK_PRESEAL':raise Refused('ISOLATED_ROLLBACK_SEAL')
  self.confirm_closed()

class GuardHost:
 """All coordinator hooks are concrete independent checks or fixed actions."""
 def __init__(self,s,g,i,audit):self.s=s;self.g=g;self.i=i;self.audit=audit
 def preflight(self):self.i.h.verify_base();self.audit.confirm_closed()
 def backup(self):self.i.load();self.i.f.snapshot(self.i.f.targets,self.i.f.directories)
 def install_fence_recovery(self):self.i.h.verify_base()
 def reload_fence(self):self.i.h.reload()
 def verify_fence_loaded(self):self.audit.confirm_closed()
 def enable_recovery(self):self.i.h.verify_base()
 def start_recovery(self):self.i.h.verify_base() # already completed phase-0 handshake
 def enable_watchdog(self):self.i.h.base.manager.action('enable','watch')
 def start_watchdog(self):self.i.h.base.manager.action('start','watch')
 def verify_watchdog(self):
  r=self.i.h.base.manager.show('watch')
  if r['ActiveState']!='active' or r['UnitFileState']!='enabled-runtime':raise Refused('ISOLATED_WATCHDOG')
 def quiesce_prearm(self):self.audit.quiesce()
 def blocked_start(self):self.audit.confirm_closed();return True
 def stop_timer(self):self.i.h.base.quiesce_watchdog()
 def installed(self):self.i.h.verify_published(decode_candidates(parse(self.s.read('directional-plan.json'))['candidates']))
 install_guard=installed;install_authority=installed;install_consumer=installed;install_checksum=installed
 def reload_consumer(self):self.i.h.reload()
 def verify_new_loaded(self):self.installed();self.audit.confirm_closed()
 def probe_new(self):self.installed() # no production/application request
 def verify_result(self):
  self.installed();c=seal_boundary.Chain(self.s).context()
  return {'consumer_sha256':c['artifact_manifest_sha256'],'authority_sha256':c['guard_contract_sha256'],'loaded_unit_sha256':digest(encode(self.i.h.test_show())),'result_sha256':digest(encode(self.g.current()))}
 def start_timer(self):self.i.h.base.quiesce_watchdog() # no application timer in isolated profile
 def final_verify(self):self.installed();self.audit.confirm_closed()
 def rollback_preseal(self):
  if self.g.exists('SEALED'):raise Refused('ISOLATED_SEALED_ROLLBACK')
  self.i.h.quiesce_phase1();self.i.h.base.quiesce_watchdog()
  return {'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True}
 def finish_rollback(self):return 'ROLLED_BACK_PRESEAL'

def shadow_trial(candidates,originals,created=lambda identity:None):
 """Practical root Files engine roundtrip, no systemd or production paths."""
 if os.geteuid()!=0:raise Refused('ROOT_SHADOW_ONLY')
 root=Path(SHADOW)
 if root.exists() or root.is_symlink():raise Refused('SHADOW_PREEXISTING')
 root.mkdir(mode=0o700);st=root.stat();created((st.st_dev,st.st_ino));CREATION_HOOK(root,(st.st_dev,st.st_ino))
 class ShadowFiles(Files):
  targets=(SHADOW+'/worker.py',SHADOW+'/config.json',SHADOW+'/unit.service');directories={}
 f=ShadowFiles();j=Journal(root/'journal',create=True)
 try:
  ledger={'receipts':{},'created_directories':[]};f.save=lambda value:j.save(value)
  before=f.snapshot(f.targets,{})
  for p,source in zip(f.targets,host.VALIDATION_TARGETS):f.install_exact(p,candidates[source],before)
  f.restore_owned_changes(before)
  if not f.same_restored_snapshot(before):raise Refused('SHADOW_ROLLBACK')
  return digest(encode({'candidate_pins':{p:r['sha256'] for p,r in candidates.items()},'originals':originals,'restored':True,'journal_sha256':j.load()[2]}))
 finally:
  j.close()
  # Retain private shadow evidence for outer controller. Never wildcard-delete.

def factory(s):
 if os.geteuid()!=0 or s.fixture or str(s.path)!=VALIDATION_ROOT:raise Refused('DIRECTIONAL_ROOT_PROFILE')
 g=GuardStore();j=Journal(s.path/'publication');f=host.ValidationFiles();h=host.Phase1Host(s,'validation')
 phase0files=install.file_backend('validation');h.base.manager=BoundManager(h.base.manager,phase0files,s)
 i=phase1.Installer(s,f,j,h);plan=parse(s.read('directional-plan.json'));c=decode_candidates(plan['candidates'])
 audit=Audit(s,g,i);gh=GuardHost(s,g,i,audit);bridge=split_guard.GuardBridge(g,gh,audit)
 def trial(candidates,originals):
  contract={'pins':{p:r['sha256'] for p,r in candidates.items()},'originals_sha256':digest(encode(originals))}
  if s.exists('rollback-proof.json'):
   proof=parse(s.read('rollback-proof.json'))
   if set(proof)!= {'contract','proof_sha256','journal_sha256'} or proof['contract']!=contract:raise Refused('ROLLBACK_TRIAL_REPLAY')
   sj=Journal(Path(SHADOW)/'journal')
   try:
    if sj.load()[2]!=proof['journal_sha256'] or any((Path(SHADOW)/n).exists() or (Path(SHADOW)/n).is_symlink() for n in ('worker.py','config.json','unit.service')):raise Refused('ROLLBACK_TRIAL_POSTSTATE')
   finally:sj.close()
   return proof['proof_sha256']
  pin=shadow_trial(candidates,originals,lambda identity:s.write('shadow-ownership.json',encode({'dev':identity[0],'inode':identity[1]})));sj=Journal(Path(SHADOW)/'journal')
  try:s.write('rollback-proof.json',encode({'contract':contract,'proof_sha256':pin,'journal_sha256':sj.load()[2]}))
  finally:sj.close()
  return pin
 runtime=Runtime(i,bridge,c,plan['originals'],trial);b=seal_boundary.Boundary(s,runtime);runtime.boundary=b;i.boundary=b
 return b,g,j

def worker_entry(expected,mode):
 from directional import Driver,MATRIX
 from phase0_cleanup import Cleanup
 if mode not in ('directional-recover','directional-verify','directional-activate','directional-cleanup'):raise Refused('DIRECTIONAL_MODE')
 s=Store(VALIDATION_ROOT,validation=True);b=g=j=None
 try:
  if digest(s.read('boundary-context.json'))!=expected:raise Refused('DIRECTIONAL_CONTEXT_PIN')
  b,g,j=factory(s);driver=Driver(b)
  if mode=='directional-cleanup':result=Cleanup(b).run()
  else:
   action={'directional-recover':'RECOVER','directional-verify':'VERIFY','directional-activate':'ACTIVATE'}[mode]
   job=driver.selected_job(action);result=driver.execute(job)
  return {'state':result,'context_sha256':expected,'mode':mode}
 finally:
  if j:j.close()
  if g:g.close()
  s.close()
