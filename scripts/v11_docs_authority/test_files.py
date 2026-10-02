import unittest,tempfile,os,hashlib,copy
from pathlib import Path
from files import Files
from adapter import TARGETS,DIRECTORIES,Adapter,ALLOWED
from manifest import Refused
class FileTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(prefix='tu1nz-docs-fixture-',dir='/tmp');self.root=Path(self.t.name);self.root.chmod(0o700);self.saved=[];self.f=Files(self.root,True,lambda x:self.saved.append(copy.deepcopy(x)))
  for n in ['/usr/local/libexec','/etc/tu1nz','/etc/systemd/system','/var/lib','/usr/local/bin']:
   p=self.root/n.lstrip('/');p.mkdir(parents=True,exist_ok=True)
  for d in self.root.rglob("*"):
   if d.is_dir():d.chmod(0o755)
  self.original=self.f.snapshot(TARGETS,DIRECTORIES)
 def tearDown(self):self.t.cleanup()
 def candidate(self,b=b'new'):return {'bytes':b,'sha256':hashlib.sha256(b).hexdigest(),'uid':0,'gid':0,'mode':0o600}
 def test_install_and_restore_absent(self):
  self.f.create_declared_directories(DIRECTORIES);self.f.install_exact(TARGETS[0],self.candidate(),self.original);self.f.verify_exact(TARGETS[0],self.candidate());self.f.restore_owned_changes(self.original);self.assertTrue(self.f.same_restored_snapshot(self.original))
 def test_restore_existing(self):
  p=self.f.path(TARGETS[-1]);p.write_bytes(b'old');p.chmod(0o600);before=self.f.snapshot(TARGETS,DIRECTORIES);self.f.install_exact(TARGETS[-1],self.candidate(),before);self.f.restore_owned_changes(before);self.assertTrue(self.f.same_restored_snapshot(before))
 def test_wrong_hash(self):self.f.create_declared_directories(DIRECTORIES);c=self.candidate();c['sha256']='0'*64;self.assertRaises(Refused,self.f.install_exact,TARGETS[0],c,self.original)
 def test_symlink(self):self.f.path(TARGETS[-1]).symlink_to('/etc/passwd');self.assertRaises(Refused,self.f.snapshot_one,TARGETS[-1])
 def test_writable_parent(self):self.f.path(TARGETS[-1]).parent.chmod(0o777);self.assertRaises(Refused,self.f.snapshot_one,TARGETS[-1])
 def test_foreign_writer(self):
  self.f.create_declared_directories(DIRECTORIES);self.f.install_exact(TARGETS[0],self.candidate(),self.original);self.f.path(TARGETS[0]).write_bytes(b'foreign');self.assertRaises(Refused,self.f.restore_owned_changes,self.original)
 def test_forbidden_path(self):self.assertRaises(Refused,self.f.path,'/etc/shadow')
 def test_nonroot_production_refused(self):self.assertRaises(Refused,Files)
 def test_no_journal_no_write(self):self.f.save=None;self.assertRaises(Refused,self.f.create_declared_directories,DIRECTORIES);self.assertFalse(self.f.path(TARGETS[0]).parent.exists())
 def test_snapshot_drift(self):p=self.f.path(TARGETS[-1]);p.write_bytes(b'foreign');p.chmod(0o600);self.assertFalse(self.f.same_snapshot(self.original))
class Journal:
 def __init__(self):self.events=[]
 def intent(self,*a,**k):self.events.append(('intent',a,k))
 def verified(self,*a):self.events.append(('verified',a))
 def terminal(self,*a):self.events.append(('terminal',a))
class RecoveryTests(unittest.TestCase):
 def test_sealed_only_stop_timer(self):
  calls=[]
  def run(a):calls.append(a);return 'ActiveState=inactive\nUnitFileState=enabled\n' if a==ALLOWED[5] else ''
  j=Journal();a=Adapter(None,j,run);self.assertEqual(a.recover({},True),'SECURED_STOP');self.assertEqual(calls,[ALLOWED[0],ALLOWED[5]])
 def test_stop_failure_refused(self):
  a=Adapter(None,Journal(),lambda a:'ActiveState=active\n');self.assertRaises(Refused,a.recover,{},True)
 def test_root_command_reject(self):
  from adapter import execute
  self.assertRaises(Refused,execute,['/bin/sh','-c','true'])
if __name__=='__main__':unittest.main()
