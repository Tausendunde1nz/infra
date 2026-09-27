import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import tu1nz_quarantine_v8 as q

class QuarantineTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
  self.target=self.root/'script';self.original=b'fixture original never executed\n';self.target.write_bytes(self.original);self.target.chmod(0o700)
  self.backup=self.root/'private';self.backup.mkdir(mode=0o700)
 def make(self):
  x=q.Quarantine(self.backup,str(self.target),fixture=True,fixture_sha=q.digest(self.original));self.addCleanup(x.close);return x
 def test_apply_preserves_backup(self):
  x=self.make();x.apply();self.assertTrue(x.verify());self.assertEqual((self.backup/'original.bin').read_bytes(),self.original)
  self.assertEqual(stat.S_IMODE((self.backup/'original.bin').stat().st_mode),0o600)
 def test_guard_is_fixed_no_source(self):
  self.assertNotIn(b'.env',q.GUARD);self.assertNotIn(b'import',q.GUARD);self.assertIn(b'SystemExit(78)',q.GUARD)
 def test_idempotent(self):
  x=self.make();x.apply();inode=self.target.stat().st_ino;x.apply();self.assertEqual(self.target.stat().st_ino,inode);self.assertTrue(x.verify())
 def test_security_rollback(self):
  x=self.make();x.apply();x.rollback();self.assertEqual(self.target.read_bytes(),q.GUARD)
  self.assertFalse(json.loads((self.backup/'checkpoint.json').read_text())['automatic_restore_original'])
 def test_all_postbackup_failures_quarantine(self):
  for phase in ('AFTER_BACKUP','AFTER_INTENT','AFTER_REPLACE','AFTER_VERIFY'):
   with self.subTest(phase=phase),tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp).resolve();root.chmod(0o700);t=root/'script';t.write_bytes(self.original);t.chmod(0o700);b=root/'backup';b.mkdir(mode=0o700)
    x=q.Quarantine(b,str(t),fixture=True,fixture_sha=q.digest(self.original))
    try:
     def inject(p):
      if p==phase:raise RuntimeError('controlled failure')
     with self.assertRaises(RuntimeError):x.apply(inject)
     self.assertEqual(t.read_bytes(),q.GUARD);self.assertEqual((b/'original.bin').read_bytes(),self.original);self.assertTrue(x.verify())
    finally:x.close()
 def test_failure_before_backup_no_mutation(self):
  x=self.make()
  def inject(p):raise RuntimeError('before')
  with self.assertRaises(RuntimeError):x.apply(inject)
  self.assertEqual(self.target.read_bytes(),self.original);self.assertEqual(list(self.backup.iterdir()),[])
 def test_hash_drift(self):
  self.target.write_bytes(b'changed');x=self.make()
  with self.assertRaises(q.Refused):x.apply()
  self.assertEqual(self.target.read_bytes(),b'changed')
 def test_mode_drift(self):
  self.target.chmod(0o770);x=self.make()
  with self.assertRaises(q.Refused):x.apply()
 def test_symlink(self):
  other=self.root/'other';other.write_bytes(b'other');self.target.unlink();self.target.symlink_to(other);x=self.make()
  with self.assertRaises(OSError):x.apply()
  self.assertEqual(other.read_bytes(),b'other')
 def test_hardlink(self):
  os.link(self.target,self.root/'alias');x=self.make()
  with self.assertRaises(q.Refused):x.apply()
 def test_backup_collision(self):
  (self.backup/'original.bin').write_bytes(b'foreign');x=self.make()
  with self.assertRaises(FileExistsError):x.apply()
  self.assertEqual(self.target.read_bytes(),self.original);self.assertEqual((self.backup/'original.bin').read_bytes(),b'foreign')
 def test_foreign_target_not_overwritten_on_rollback(self):
  x=self.make();x.apply();self.target.write_bytes(b'foreign')
  with self.assertRaises(q.Refused):x.rollback()
  self.assertEqual(self.target.read_bytes(),b'foreign')
 def test_corrupt_backup_refused(self):
  x=self.make();x.apply();(self.backup/'original.bin').write_bytes(b'corrupt')
  with self.assertRaises(q.Refused):x.rollback()
  self.assertEqual(self.target.read_bytes(),q.GUARD)
 def test_checkpoint_link_refused(self):
  x=self.make();x.apply();p=self.backup/'checkpoint.json';p.unlink();p.symlink_to(self.target)
  with self.assertRaises(OSError):x.apply()
  self.assertEqual(self.target.read_bytes(),q.GUARD)
 def test_original_metadata(self):
  before=self.target.stat();x=self.make();x.apply();m=json.loads((self.backup/'metadata.json').read_text())
  self.assertEqual(m['inode'],before.st_ino);self.assertEqual(m['mode'],0o700);self.assertEqual(m['uid'],os.getuid())
 def test_no_pending_files(self):
  x=self.make();x.apply();self.assertFalse(list(self.root.glob('.pending-*')));self.assertFalse(list(self.backup.glob('.pending-*')))
 def test_no_root_entrypoint(self):
  with self.assertRaises(q.Refused):q.Quarantine(self.backup)
 def test_parent_group_write_refused(self):
  self.root.chmod(0o770)
  with self.assertRaises(q.Refused):self.make()
 def test_private_backup_mode(self):
  self.backup.chmod(0o750)
  with self.assertRaises(q.Refused):self.make()

if __name__=='__main__':unittest.main()
