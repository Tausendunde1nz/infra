import unittest
import tu1nz_privilege_sudo_candidate as m
class Tests(unittest.TestCase):
 def test_preserves_unrelated_bytes(self):
  a,b=m.REMOVALS;source=b'# comment\r\n% sudo example\n'+a+b'\n'+b+b'\n# final'
  self.assertEqual(m.remove_exact_lines(source,m.REMOVALS),b'# comment\r\n% sudo example\n# final')
 def test_missing_fails(self):
  with self.assertRaises(ValueError):m.remove_exact_lines(b'unknown',m.REMOVALS)
 def test_duplicate_fails(self):
  with self.assertRaises(ValueError):m.remove_exact_lines(b'\n'.join(m.REMOVALS*2),m.REMOVALS)
 def test_altered_argument_fails(self):
  with self.assertRaises(ValueError):m.remove_exact_lines(b'\n'.join(m.REMOVALS)+b' --unsafe',m.REMOVALS)
 def test_unknown_path_fails(self):
  with self.assertRaises(ValueError):m.prepare({'/tmp/other':b''})
 def test_hash_drift_fails(self):
  with self.assertRaises(ValueError):m.prepare({p:b'' for p in m.BASELINES})
if __name__=='__main__':unittest.main()
