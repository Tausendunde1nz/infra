import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import launcher_v10 as l

class Tests(unittest.TestCase):
 def test_pin(self):self.assertEqual(hashlib.sha256((Path(__file__).parent/'collector_v10.py').read_bytes()).hexdigest(),l.COLLECTOR_SHA256)
 def test_exact_memory_bytes(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'source';p.write_bytes(b'fixture');self.assertEqual(l.verified_bytes(p,hashlib.sha256(b'fixture').hexdigest()),b'fixture')
 def test_changed_bytes_refused(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'source';p.write_bytes(b'changed')
   with self.assertRaises(RuntimeError):l.verified_bytes(p,hashlib.sha256(b'fixture').hexdigest())
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'source';p.write_bytes(b'fixture');q=Path(t)/'link';q.symlink_to(p)
   with self.assertRaises(OSError):l.verified_bytes(q,hashlib.sha256(b'fixture').hexdigest())
 def test_nonroot_refused(self):
  with patch.object(l.os,'geteuid',return_value=1001),patch.object(l,'verified_bytes') as reader:
   with self.assertRaises(RuntimeError):l.main()
   reader.assert_not_called()
 def test_missing_B_refused(self):
  with patch.object(l.os,'geteuid',return_value=0),patch.object(l.sys,'dont_write_bytecode',False),patch.object(l,'verified_bytes') as reader:
   with self.assertRaises(RuntimeError):l.main()
   reader.assert_not_called()
 def test_arbitrary_arguments_refused(self):
  with patch.object(l.os,'geteuid',return_value=0),patch.object(l.sys,'dont_write_bytecode',True),patch.object(l.sys,'argv',['launcher','elsewhere']),patch.object(l,'verified_bytes') as reader:
   with self.assertRaises(RuntimeError):l.main()
   reader.assert_not_called()

if __name__=='__main__':unittest.main()
