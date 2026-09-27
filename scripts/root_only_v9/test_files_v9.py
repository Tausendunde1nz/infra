"""Actual atomic file I/O in an isolated unprivileged directory.

Only UID/GID observations and chown are virtualized. No production path is
mapped or touched; an explicit fixture-only path predicate guards every write.
"""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
import files_v9 as f
from policy_v9 import Refused

class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.path=self.root/'target';self.path.write_bytes(b'original');self.path.chmod(0o600)
  real_lstat=Path.lstat;real_fstat=os.fstat
  def virtual(s):
   fields={k:getattr(s,k) for k in dir(s) if k.startswith('st_')};fields.update(st_uid=0,st_gid=0)
   return types.SimpleNamespace(**fields)
  def chain(path,*args,**kwargs):
   if Path(path)!=self.root:raise Refused('outside isolated fixture')
   if not self.root.is_dir() or stat.S_IMODE(self.root.stat().st_mode)!=0o700:raise Refused('fixture directory')
  self.patches=[patch.object(f,'authorized',lambda p:Path(p)==self.path),patch.object(f,'safe_chain',chain),
   patch.object(Path,'lstat',lambda p:virtual(real_lstat(p))),patch.object(os,'fstat',lambda fd:virtual(real_fstat(fd))),
   patch.object(os,'geteuid',lambda:0),patch.object(os,'fchown',lambda fd,uid,gid:None)]
  if not hasattr(os,'listxattr'):self.patches.append(patch.object(os,'listxattr',lambda p:[],create=True))
  for p in self.patches:p.start()
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def test_atomic_apply_and_restore(self):
  old=f.read_file(self.path);new=f.write_exact(self.path,b'candidate',old,0o644)
  self.assertNotEqual(old['ino'],new['ino']);self.assertEqual(self.path.read_bytes(),b'candidate')
  restored=f.write_exact(self.path,f.bytes_of(old),new,old['mode'],old['gid'],(old['atime_ns'],old['mtime_ns']))
  self.assertTrue(f.same_content(old,restored));self.assertEqual(restored['mtime_ns'],old['mtime_ns'])
 def test_creation_and_absent_rollback(self):
  self.path.unlink();old=f.read_file(self.path);self.assertEqual(old,{'absent':True})
  new=f.write_exact(self.path,b'candidate',old);self.assertFalse(new.get('absent'))
  self.assertEqual(f.write_exact(self.path,None,new),{'absent':True});self.assertFalse(self.path.exists())
 def test_foreign_change_refused(self):
  old=f.read_file(self.path);self.path.write_bytes(b'foreign')
  with self.assertRaises(Refused):f.write_exact(self.path,b'candidate',old)
  self.assertEqual(self.path.read_bytes(),b'foreign')
 def test_foreign_same_bytes_new_inode_refused(self):
  old=f.read_file(self.path);q=self.root/'other';q.write_bytes(b'original');q.chmod(0o600);os.replace(q,self.path)
  with self.assertRaises(Refused):f.write_exact(self.path,b'candidate',old)
 def test_replace_failure_preserves_original(self):
  old=f.read_file(self.path)
  with patch.object(os,'replace',side_effect=OSError('injected')),self.assertRaises(OSError):f.write_exact(self.path,b'candidate',old)
  self.assertEqual(self.path.read_bytes(),b'original');self.assertEqual(list(self.root.iterdir()),[self.path])
 def test_group_write_rejected(self):
  self.path.chmod(0o660)
  with self.assertRaises(Refused):f.read_file(self.path)
 def test_hardlink_rejected(self):
  os.link(self.path,self.root/'other')
  with self.assertRaises(Refused):f.read_file(self.path)
 def test_symlink_rejected(self):
  self.path.unlink();self.path.symlink_to('/etc/passwd')
  with self.assertRaises(Refused):f.read_file(self.path)
 def test_fifo_rejected_before_open(self):
  self.path.unlink();os.mkfifo(self.path,0o600)
  with self.assertRaises(Refused):f.read_file(self.path)
 def test_xattrs_rejected(self):
  with patch.object(os,'listxattr',return_value=['system.posix_acl_access']),self.assertRaises(Refused):f.read_file(self.path)
 def test_outside_fixture_denied(self):
  with self.assertRaises(Refused):f.write_exact('/etc/sudoers',b'never',{'absent':True})

if __name__=='__main__':unittest.main()
