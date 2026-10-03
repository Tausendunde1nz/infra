import os,sys,json,tempfile,unittest,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.append(str(HERE.parent/'v11_guard_recovery'))
from publication import *
import build
B={'transaction':'v11-'+'a'*32,'origin_boot':'01234567-89ab-cdef-0123-456789abcdef','contract_sha256':'b'*64}
class Manager:
 def __init__(self,root):self.p=Path(root)/'manager.json'
 def get(self):return json.loads(self.p.read_text())
 def put(self,x):
  tmp=self.p.with_suffix('.tmp');tmp.write_text(json.dumps(x));tmp.replace(self.p)
 def preflight(self,admission,originals,pins):
  if admission!={'offline':True} or self.get()!=[]:raise Refused('PREFLIGHT')
  return []
 def apply(self,phase,state):
  x=self.get()
  if x!=list(PHASES[:PHASES.index(phase)]):raise Refused('ORDER')
  self.put(x+[phase]);return sha(raw(self.get()))
 def close_fence(self):pass
 def quiesce_owned(self):pass
 def restore(self,before):self.put(before)
 def verify_restored(self,before):return self.get()==before

def child(root,operation,crash):
 r=Path(root);j=Journal(r/'rescue');m=Manager(r);f=PublicationFiles(r,fixture=True)
 def inject(point):
  if point==crash:os._exit(91)
 i=Installer(f,j,m,inject)
 try:
  if operation=='start':result=i.start(B['transaction'],payloads(build.build(HERE,B)),{'offline':True})
  else:result=i.rollback()
  print(result)
 finally:j.close()

class Publication(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='tu1nz-fence-files-',dir='/tmp');self.root=Path(self.temp.name);self.root.chmod(0o700)
  declared={self.root/n.lstrip('/') for n in DIRECTORIES};parents=set()
  for p in declared|{self.root/n.lstrip('/') for n in TARGETS}:
   for q in p.parents:
    if q==self.root:break
    if self.root in q.parents and q not in declared:parents.add(q)
  for p in sorted(parents,key=lambda p:len(p.parts)):p.mkdir(exist_ok=True);p.chmod(0o755)
  Journal(self.root/'rescue',create=True).close();Manager(self.root).put([])
 def tearDown(self):self.temp.cleanup()
 def run_child(self,operation='start',crash=''):
  code='import sys;sys.path.insert(0,'+repr(str(HERE))+');from test_publication import child;child('+repr(str(self.root))+','+repr(operation)+','+repr(crash)+')'
  return subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 def check_rollback(self):
  r=self.run_child('rollback');self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'ROLLED_BACK',r.stdout)
  r=self.run_child('rollback');self.assertIn(b'ROLLED_BACK',r.stdout)
  self.assertEqual(list(self.root.rglob('.v11-*')),[])
 def test_roundtrip(self):
  r=self.run_child();self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'PRESEAL_PUBLISHED',r.stdout);self.check_rollback()
 def test_bad_manifest(self):
  c=build.build(HERE,B);c['manifest']+=b' '
  with self.assertRaises(Refused):payloads(c)
 def test_bad_unit(self):
  c=build.build(HERE,B);c['units'][units.WORK]+=b'# foreign'
  with self.assertRaises(Refused):payloads(c)
 def test_duplicate_start(self):
  self.assertEqual(self.run_child().returncode,0);self.assertNotEqual(self.run_child().returncode,0);self.check_rollback()
 def test_lock(self):
  j=Journal(self.root/'rescue')
  try:
   with j.locked():self.assertNotEqual(self.run_child().returncode,0)
  finally:j.close()
 def test_foreign_postimage(self):
  self.assertEqual(self.run_child().returncode,0);p=self.root/TARGETS[0].lstrip('/');p.chmod(0o600);p.write_bytes(b'foreign')
  r=self.run_child('rollback');self.assertIn(b'PRESEAL_SECURED_STOP',r.stdout);self.assertEqual(p.read_bytes(),b'foreign')
 def test_journal_replacement(self):
  j=Journal(self.root/'rescue');self.root.joinpath('rescue').rename(self.root/'old');self.root.joinpath('rescue').mkdir(mode=0o700)
  try:
   with self.assertRaises(Refused):j.load()
  finally:j.close()
 def test_existing_original_restore_intent_crash(self):
  f=PublicationFiles(self.root,fixture=True,save=lambda x:None);f.create_declared_directories(DIRECTORIES)
  p=f.path(TARGETS[0]);p.write_bytes(b'original');p.chmod(0o640)
  self.assertEqual(self.run_child().returncode,0)
  r=self.run_child('rollback','receipt:INTENT');self.assertEqual(r.returncode,91,r.stderr);self.check_rollback();self.assertEqual(p.read_bytes(),b'original')

def interrupted(point,rollback=False):
 def test(self):
  if rollback:self.assertEqual(self.run_child().returncode,0)
  r=self.run_child('rollback' if rollback else 'start',point);self.assertEqual(r.returncode,91,r.stderr);self.check_rollback()
 return test
for point in ['ROOT_STARTED','BACKUP_VERIFIED','receipt:INTENT','receipt:PUBLISH_READY','receipt:VERIFIED']+[edge+':'+p for p in TARGETS for edge in ('before','after')]+[edge+':'+p for p in PHASES for edge in ('intent','action','done')]:setattr(Publication,'test_crash_'+point.replace('/','_').replace(':','_'),interrupted(point))
for point in ['rollback_intent','rollback_quiesced','rollback_files','rollback_manager','rollback_cleanup']:setattr(Publication,'test_crash_'+point,interrupted(point,True))
if __name__=='__main__':unittest.main()
