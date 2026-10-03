import os,sys,unittest,tempfile,shutil,hashlib,subprocess
from pathlib import Path
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_dispatcher'),str(HERE.parent/'v11_guard_recovery')]
from anchor import *
import phase0,phase1
from publication import PublicationFiles,Journal,payloads,TARGETS,DIRECTORIES
import build
B={'transaction':'v11-'+'a'*32,'origin_boot':'01234567-89ab-cdef-0123-456789abcdef','contract_sha256':'b'*64}
class Host:
 def __init__(self,s):self.s=s;self.restored=True
 def verify_base(self):self.s.base();self.s.choose()
 def confirm_closed(self):assert self.s.closed()
 def no_worker(self):pass
 def manager_before(self):return {'fixed':'before'}
 def reload(self):self.restored=False
 def verify_published(self,candidates):pass
 def quiesce_phase1(self):pass
 def restore_manager(self,before):assert before=={'fixed':'before'};self.restored=True
 def verify_restored(self,before):assert before=={'fixed':'before'} and self.restored
class Phase(unittest.TestCase):
 def setUp(self):
  self.a=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));self.a.rmdir();self.r=Path(tempfile.mkdtemp(prefix='tu1nz-fence-files-',dir='/tmp'));self.r.chmod(0o700)
  self.py=str(Path('/usr/bin/python3').resolve());self.pyhash=digest(Path(self.py).read_bytes())
  phase0.prepare(self.a,b'anchor', [b'worker'],self.py,self.pyhash,list(TARGETS),fixture=True);self.s=Store(self.a,fixture=True);self.h=Host(self.s)
  self.s.write('phase0.json',encode({'state':'PHASE0_VERIFIED','base_sha256':digest(self.s.read('base.json'))}),0o600)
  declared={self.r/n.lstrip('/') for n in DIRECTORIES};parents=set()
  for p in declared|{self.r/n.lstrip('/') for n in TARGETS}:
   for q in p.parents:
    if q==self.r:break
    if self.r in q.parents and q not in declared:parents.add(q)
  for p in sorted(parents,key=lambda p:len(p.parts)):p.mkdir(exist_ok=True);p.chmod(0o755)
  self.j=Journal(self.a/'publication',create=True);self.f=PublicationFiles(self.r,fixture=True);self.i=phase1.Installer(self.s,self.f,self.j,self.h);self.c=payloads(build.build(HERE.parent/'v11_dispatcher',B));self.before=self.f.snapshot(TARGETS,DIRECTORIES)
 def tearDown(self):self.j.close();self.s.close();shutil.rmtree(self.a);shutil.rmtree(self.r)
 def start(self):return self.i.start(B['transaction'],self.c,self.before)
 def test_prepare_idempotent(self):self.assertFalse(phase0.prepare(self.a,b'anchor',[b'worker'],self.py,self.pyhash,list(TARGETS),fixture=True)['changed'])
 def test_prepare_drift_rejected(self):
  with self.assertRaises(Refused):phase0.prepare(self.a,b'changed',[b'worker'],self.py,self.pyhash,list(TARGETS),fixture=True)
 def test_main_cannot_start_without_verified_phase0(self):
  self.s.write('phase0.json',encode({'state':'PREPARED'}),0o600,True)
  with self.assertRaisesRegex(Refused,'PHASE0_NOT_VERIFIED'):self.start()
  self.assertEqual(self.j.load()[0],None)
 def test_roundtrip_removes_main_but_preserves_anchor_slots(self):
  pins={n:digest(self.s.read(n,0o500 if n.endswith('.py') else 0o400)) for n in ('anchor.py','base.json','slot-A.py','slot-A.json')}
  self.assertEqual(self.start(),'PHASE1_PUBLISHED_FENCED');phase=parse(self.s.read('phase1.json',0o600));self.assertEqual(self.i.recover(phase),TERMINAL);self.assertEqual(self.i.verify(phase),TERMINAL)
  self.assertFalse((self.r/'usr/local/libexec/tu1nz-v11-dispatcher/installer.py').exists())
  for n,pin in pins.items():self.assertEqual(digest(self.s.read(n,0o500 if n.endswith('.py') else 0o400)),pin)
  self.assertEqual(self.i.recover(phase),TERMINAL)
 def test_original_drift_refused_before_mutation(self):
  self.before[TARGETS[0]]={'unexpected':True}
  with self.assertRaisesRegex(Refused,'ORIGINAL_DRIFT'):self.start()
  self.assertIsNone(self.j.load()[0])
 def test_unapproved_paths_rejected(self):
  self.c['/etc/shadow']=self.c[TARGETS[0]]
  with self.assertRaisesRegex(Refused,'PHASE1_SCOPE'):self.start()
 def test_duplicate_start_rejected(self):
  self.start()
  with self.assertRaisesRegex(Refused,'DUPLICATE'):self.start()
 def test_sealed_state_never_rolls_back(self):
  self.start();self.i.state['sealed']=True;self.i.persist();self.assertEqual(self.i.recover(parse(self.s.read('phase1.json',0o600))),'SECURED_STOP');self.assertTrue((self.r/TARGETS[0].lstrip('/')).exists())
 def test_worker_pins_are_immutable(self):
  with self.assertRaises(Refused):self.s.publish_slot('B',b'other')
 def test_late_publication_failure_rolls_back(self):
  self.h.verify_published=lambda c:(_ for _ in ()).throw(Refused('LATE_FAILURE'))
  self.assertEqual(self.start(),TERMINAL);self.assertTrue(self.s.closed())

def crash_child(anchor_path,file_root,operation,point):
 s=Store(anchor_path,fixture=True);j=Journal(Path(anchor_path)/'publication');f=PublicationFiles(file_root,fixture=True);h=Host(s)
 def inject(p):
  if p==point:os._exit(91)
 i=phase1.Installer(s,f,j,h,inject)
 try:
  if operation=='start':result=i.start(B['transaction'],payloads(build.build(HERE.parent/'v11_dispatcher',B)),f.snapshot(TARGETS,DIRECTORIES))
  else:result=i.recover(parse(s.read('phase1.json',0o600)))
  print(result)
 finally:j.close();s.close()
def crash_case(point,rollback):
 def test(self):
  if rollback:self.start()
  code='import sys;sys.path.insert(0,'+repr(str(HERE))+');from test_phase import crash_child;crash_child('+repr(str(self.a))+','+repr(str(self.r))+','+repr('recover' if rollback else 'start')+','+repr(point)+')'
  p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);self.assertEqual(p.returncode,91,p.stderr)
  self.assertEqual(self.i.recover(parse(self.s.read('phase1.json',0o600))),TERMINAL);self.assertEqual(self.s.read('anchor.py',0o500),b'anchor');self.assertEqual(self.s.choose()['slot'],'A')
 return test
for point in ('bound','published:'+TARGETS[0]):setattr(Phase,'test_hard_crash_'+point.replace('/','_').replace(':','_'),crash_case(point,False))
for point in ('rollback_intent','quiesced','restored','manager_restored','cleanup'):setattr(Phase,'test_hard_crash_'+point,crash_case(point,True))

if __name__=='__main__':unittest.main()
