import hashlib,os,subprocess,tempfile,unittest
from pathlib import Path
from files import Files,TARGETS,DIRECTORIES
from state import Refused
import units
from runtime import FENCE,TIMER_DEP,CONSUMER,RECOVERY,WATCHDOG

class FileTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-fence-files-',dir='/tmp');self.root=Path(self.tmp.name);self.root.chmod(0o700);self.events=[]
  dirs={self.root/p.lstrip('/') for p in DIRECTORIES}
  parents=set()
  for p in dirs|{self.root/p.lstrip('/') for p in TARGETS}:
   for q in p.parents:
    if q==self.root:break
    if self.root in q.parents and q not in dirs:parents.add(q)
  for p in sorted(parents,key=lambda p:len(p.parts)):p.mkdir(exist_ok=True);p.chmod(0o755)
  self.f=Files(self.root,fixture=True,save=lambda v:self.events.append(str(v)));self.before=self.f.snapshot(TARGETS,DIRECTORIES)
 def tearDown(self):self.tmp.cleanup()
 def payload(self,data=b'candidate',mode=0o600):return {'bytes':data,'sha256':hashlib.sha256(data).hexdigest(),'uid':0,'gid':0,'mode':mode}
 def test_install_restore_all_targets(self):
  self.f.create_declared_directories(DIRECTORIES)
  for p in TARGETS:self.f.install_exact(p,self.payload(),self.before);self.f.verify_exact(p,self.payload())
  self.f.restore_owned_changes(self.before);self.assertTrue(self.f.same_restored_snapshot(self.before));self.assertTrue(self.events)
 def test_existing_original(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];f=self.f.path(p);f.write_bytes(b'old');f.chmod(0o640);before=self.f.snapshot(TARGETS,DIRECTORIES)
  # Directories predate this transaction for this fixture.
  self.f.created=[];self.f.install_exact(p,self.payload(),before);self.f.restore_owned_changes(before);self.assertTrue(self.f.same_restored_snapshot(before))
 def test_restore_repeated_existing(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];f=self.f.path(p);f.write_bytes(b'original');f.chmod(0o640);before=self.f.snapshot(TARGETS,DIRECTORIES);self.f.created=[]
  self.f.install_exact(p,self.payload(),before);self.f.restore_owned_changes(before);restored=self.f.snapshot_one(p);self.f.restore_owned_changes(before);self.assertEqual(self.f.snapshot_one(p),restored)
 def test_crash_after_publish_before_receipt_resumes(self):
  from unittest import mock
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];original_replace=os.replace
  def interrupted(src,dst):original_replace(src,dst);raise KeyboardInterrupt('after-rename')
  with mock.patch('files.os.replace',side_effect=interrupted):
   with self.assertRaises(KeyboardInterrupt):self.f.install_exact(p,self.payload(),self.before)
  self.assertEqual(self.f.receipts[p]['status'],'PUBLISH_READY');self.f.restore_owned_changes(self.before);self.assertTrue(self.f.same_restored_snapshot(self.before))
 def test_crashed_publish_foreign_same_bytes_refused(self):
  from unittest import mock
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];original_replace=os.replace
  def interrupted(src,dst):original_replace(src,dst);raise KeyboardInterrupt('after-rename')
  with mock.patch('files.os.replace',side_effect=interrupted):
   with self.assertRaises(KeyboardInterrupt):self.f.install_exact(p,self.payload(),self.before)
  f=self.f.path(p);other=f.with_name('foreign');other.write_bytes(b'candidate');other.chmod(0o600);other.replace(f)
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
 def test_crash_after_restore_times_resumes(self):
  from unittest import mock
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];f=self.f.path(p);f.write_bytes(b'original');f.chmod(0o640);before=self.f.snapshot(TARGETS,DIRECTORIES);self.f.created=[];self.f.install_exact(p,self.payload(),before)
  original_utime=os.utime
  def interrupted(*args,**kw):original_utime(*args,**kw);raise KeyboardInterrupt('after-utime')
  with mock.patch('files.os.utime',side_effect=interrupted):
   with self.assertRaises(KeyboardInterrupt):self.f.restore_owned_changes(before)
  self.assertEqual(self.f.receipts[p]['status'],'RESTORE_TIMES_PENDING');self.f.restore_owned_changes(before);self.assertTrue(self.f.same_restored_snapshot(before))
 def test_foreign_times_after_restore_interruption_refused(self):
  from unittest import mock
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];f=self.f.path(p);f.write_bytes(b'original');f.chmod(0o640);before=self.f.snapshot(TARGETS,DIRECTORIES);self.f.created=[];self.f.install_exact(p,self.payload(),before)
  original_utime=os.utime
  def interrupted(*args,**kw):original_utime(*args,**kw);raise KeyboardInterrupt('after-utime')
  with mock.patch('files.os.utime',side_effect=interrupted):
   with self.assertRaises(KeyboardInterrupt):self.f.restore_owned_changes(before)
  st=f.stat();os.utime(f,ns=(st.st_atime_ns,st.st_mtime_ns+10000))
  with self.assertRaises(Refused):self.f.restore_owned_changes(before)
 def test_directory_publication_crash_recovery(self):
  from unittest import mock
  import files
  original=files.rename_no_replace
  def interrupted(src,dst):original(src,dst);raise KeyboardInterrupt('directory-published')
  with mock.patch('files.rename_no_replace',side_effect=interrupted):
   with self.assertRaises(KeyboardInterrupt):self.f.create_declared_directories(DIRECTORIES)
  self.assertEqual(self.f.created[-1]['status'],'PUBLISH_READY');self.f.restore_owned_changes(self.before);self.assertTrue(self.f.same_restored_snapshot(self.before))
 def test_foreign_directory_never_replaced(self):
  from unittest import mock
  import files
  original=files.rename_no_replace;created=[]
  def intervening(src,dst):dst.mkdir();created.append((dst,dst.stat().st_ino));original(src,dst)
  with mock.patch('files.rename_no_replace',side_effect=intervening):
   with self.assertRaises(FileExistsError):self.f.create_declared_directories(DIRECTORIES)
  path,inode=created[0];self.assertEqual(path.stat().st_ino,inode)
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
 def test_wrong_hash(self):
  self.f.create_declared_directories(DIRECTORIES);v=self.payload();v['sha256']='0'*64
  with self.assertRaises(Refused):self.f.install_exact(TARGETS[0],v,self.before)
 def test_foreign_write(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];self.f.install_exact(p,self.payload(),self.before);self.f.path(p).write_bytes(b'foreign')
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
 def test_same_bytes_foreign_mode_refused(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];self.f.install_exact(p,self.payload(),self.before);self.f.path(p).chmod(0o640)
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
  self.assertEqual(self.f.path(p).stat().st_mode&0o777,0o640)
 def test_same_bytes_foreign_inode_refused(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];self.f.install_exact(p,self.payload(),self.before);f=self.f.path(p);q=f.with_name('replacement');q.write_bytes(f.read_bytes());q.chmod(0o600);q.replace(f)
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
 def test_unverified_receipt_stops(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];self.f.install_exact(p,self.payload(),self.before);self.f.receipts[p]['status']='INTENT'
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
 def test_foreign_timestamp_refused(self):
  self.f.create_declared_directories(DIRECTORIES);p=TARGETS[0];self.f.install_exact(p,self.payload(),self.before);f=self.f.path(p);st=f.stat();os.utime(f,ns=(st.st_atime_ns,st.st_mtime_ns+100000))
  with self.assertRaises(Refused):self.f.restore_owned_changes(self.before)
 def test_symlink(self):
  self.f.create_declared_directories(DIRECTORIES);self.f.path(TARGETS[0]).symlink_to('/etc/passwd')
  with self.assertRaises(Refused):self.f.snapshot_one(TARGETS[0])
 def test_hardlink(self):
  self.f.create_declared_directories(DIRECTORIES);p=self.f.path(TARGETS[0]);p.write_bytes(b'x');p.chmod(0o600);os.link(p,p.with_name('other'))
  with self.assertRaises(Refused):self.f.snapshot_one(TARGETS[0])
 def test_writable_parent(self):
  self.f.create_declared_directories(DIRECTORIES);self.f.path(TARGETS[0]).parent.chmod(0o777)
  with self.assertRaises(Refused):self.f.snapshot_one(TARGETS[0])
 def test_durable_required(self):
  f=Files(self.root,fixture=True)
  with self.assertRaises(Refused):f.create_declared_directories(DIRECTORIES)
 def test_no_arbitrary_path(self):
  with self.assertRaises(Refused):self.f.path('/etc/sudoers')
 def test_production_refuses_nonroot(self):
  with self.assertRaises(Refused):Files()

class UnitGraph(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-unitgraph-test-',dir='/tmp');self.root=Path(self.tmp.name);self.base=self.root/'etc/systemd/system';self.base.mkdir(parents=True)
  for name in ['local-fs.target','sysinit.target','basic.target','timers.target','multi-user.target','sockets.target','paths.target','shutdown.target','network-online.target','time-sync.target','time-set.target']:
   source=Path('/usr/lib/systemd/system')/name
   self.assertTrue(source.exists(),name);(self.base/name).write_bytes(source.read_bytes())
  for p in ['/usr/bin/python3','/usr/local/bin/tu1nz_delete_guard.sh']:
   f=self.root/p.lstrip('/');f.parent.mkdir(parents=True,exist_ok=True);f.write_text('#!/bin/sh\nexit 78\n');f.chmod(0o755)
  for p in [units.ROOT,units.PACKAGE,'/var/lib/tu1nz-docs-authority-v11','/usr/local/libexec/tu1nz-docs-authority-v11','/etc/tu1nz/docs-authority-v11']:(self.root/p.lstrip('/')).mkdir(parents=True,exist_ok=True)
  (self.base/'tu1nz_delete_guard.service').write_text('[Unit]\nDescription=Guard\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/tu1nz_delete_guard.sh\nTimeoutStartSec=120\n')
  (self.base/'tu1nz_delete_guard.timer').write_text('[Timer]\nOnCalendar=*-*-* 05:00:00 UTC\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
  for p,t in units.templates(b'[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B /usr/local/libexec/tu1nz-docs-authority-v11/guard.py\n').items():
   f=self.root/p.lstrip('/');f.parent.mkdir(parents=True,exist_ok=True);f.write_text(t.replace('@CONTRACT_SHA@','a'*64))
 def tearDown(self):self.tmp.cleanup()
 def verify(self):
  return subprocess.run(['systemd-analyze','--root='+str(self.root),'--man=no','verify','tu1nz_delete_guard.service','tu1nz_delete_guard.timer',RECOVERY,WATCHDOG],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
 def test_actual_systemd_graph(self):
  r=self.verify();self.assertEqual(r.returncode,0,r.stdout.decode())
 def test_cycle_rejected(self):
  p=self.base/RECOVERY;p.write_text(p.read_text().replace('After=local-fs.target','After=local-fs.target tu1nz_delete_guard.service'))
  r=self.verify();self.assertNotEqual(r.returncode,0)
 def test_missing_fixed_executable_rejected(self):
  (self.root/'usr/bin/python3').unlink();self.assertNotEqual(self.verify().returncode,0)
 def test_all_unit_start_paths_have_fence(self):
  t=units.templates(b'new');self.assertIn('ExecCondition=',t[FENCE]);self.assertIn('Requires='+RECOVERY,t[FENCE]);self.assertIn('Requires='+RECOVERY,t[TIMER_DEP]);self.assertIn('Restart=on-failure',t['/etc/systemd/system/'+WATCHDOG]);self.assertIn('WantedBy=sysinit.target',t['/etc/systemd/system/'+RECOVERY])
if __name__=='__main__':unittest.main()
