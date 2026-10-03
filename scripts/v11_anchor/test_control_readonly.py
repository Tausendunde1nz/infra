import os,sys,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parent))
import control_readonly as c
class Audit(unittest.TestCase):
 def test_nonroot_cannot_collect(self):
  with self.assertRaisesRegex(RuntimeError,'ROOT_ONLY'):c.collect()
 def test_no_unlisted_or_mutating_git_operation(self):
  calls=[]
  with patch('os.geteuid',return_value=0):
   for op in (('status',),('checkout','main'),('config','core.sparseCheckout','false'),('reset','--hard'),('gc',)):
    with self.assertRaisesRegex(RuntimeError,'FIXED_SCOPE'):c.git_read(op,lambda *a,**kw:calls.append(a))
  self.assertEqual(calls,[])
 def test_index_and_optional_locks_closed(self):
  self.assertEqual(c.ENV['GIT_OPTIONAL_LOCKS'],'0');self.assertEqual(c.ENV['GIT_INDEX_FILE'],'/dev/null')
  self.assertIn('core.hooksPath=/dev/null',c.GIT);self.assertIn('core.fsmonitor=false',c.GIT)
 def test_object_output_is_typed(self):
  fake=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=b'secret-invalid-object\n')
  with patch('os.geteuid',return_value=0):
   with self.assertRaisesRegex(RuntimeError,'OBJECT_FORMAT'):c.git_read(('rev-parse','HEAD'),fake)
 def test_worktree_output_compressed(self):
  fake=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=b'worktree /private/path\nHEAD '+b'a'*40+b'\nbranch refs/heads/private\n')
  with patch('os.geteuid',return_value=0):self.assertEqual(c.git_read(('worktree','list','--porcelain'),fake),{'rc':0,'worktrees':1})
if __name__=='__main__':unittest.main()
