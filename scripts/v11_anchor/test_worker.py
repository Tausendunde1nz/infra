import unittest,tempfile,shutil,os,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
from anchor import *
import phase0,worker,build_anchor
class WorkerTests(unittest.TestCase):
 def setUp(self):
  self.p=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));self.p.rmdir();self.py=str(Path('/usr/bin/python3').resolve());self.pyhash=digest(Path(self.py).read_bytes());self.phase={'transaction':'v11-'+'a'*32,'manifest_sha256':'b'*64,'paths':['/run/phase1-test']};self.s=None
 def tearDown(self):
  if self.s:self.s.close()
  shutil.rmtree(self.p,ignore_errors=True)
 def prepare(self,source):
  phase0.prepare(self.p,b'anchor',[source],self.py,self.pyhash,self.phase['paths'],fixture=True);self.s=Store(self.p,fixture=True);return worker.Worker(self.s)
 def test_pinned_fd_process(self):
  source=b'import sys,json;assert sys.flags.isolated and sys.dont_write_bytecode;print(json.dumps({"state":"ROLLED_BACK_WITH_RECOVERY_BASE","phase1_sha256":sys.argv[2],"mode":sys.argv[1]}))\n'
  h=self.prepare(source);self.assertEqual(h.invoke(self.s.choose(),self.phase,'recover'),TERMINAL);h.no_worker()
 def test_descendant_outlives_leader_is_rejected_and_killed(self):
  source=b'import os,sys,time,json\nif os.fork()==0:\n os.close(1);os.close(2);time.sleep(10);os._exit(0)\nprint(json.dumps({"state":"ROLLED_BACK_WITH_RECOVERY_BASE","phase1_sha256":sys.argv[2],"mode":sys.argv[1]}))\n'
  h=self.prepare(source)
  with self.assertRaisesRegex(Refused,'WORKER_DESCENDANTS'):h.invoke(self.s.choose(),self.phase,'recover')
  h.no_worker()
 def test_anchor_does_not_embed_migration_modules(self):
  c=build_anchor.build(Path(__file__).parent,'validation')
  for name in ('host','phase1','publication','files','runtime','systemd_adapter'):
   self.assertNotIn(('ModuleType('+repr(name)+')').encode(),c['anchor'])
  for name in ('anchor','worker','manager','base_host'):
   self.assertIn(('ModuleType('+repr(name)+')').encode(),c['anchor'])
 def test_production_capsules_are_closed_before_store(self):
  c=build_anchor.build(Path(__file__).parent,'production')
  for key in ('anchor','worker'):
   self.assertIn(b'raise SystemExit(78) #',c[key])
  self.assertFalse(c['production_activation_ready'])
 def test_nonzero(self):
  h=self.prepare(b'raise SystemExit(7)\n')
  with self.assertRaisesRegex(Refused,'NONZERO'):h.invoke(self.s.choose(),self.phase,'recover')
 def test_oversized_output(self):
  h=self.prepare(b'print("x"*5000)\n')
  with self.assertRaisesRegex(Refused,'OUTPUT_LIMIT'):h.invoke(self.s.choose(),self.phase,'recover')
 def test_fake_terminal_rejected(self):
  h=self.prepare(b'print("{}")\n')
  with self.assertRaisesRegex(Refused,'WORKER_PROOF'):h.invoke(self.s.choose(),self.phase,'verify')
 def test_unpinned_interpreter(self):
  with self.assertRaisesRegex(Refused,'INTERPRETER_HASH'):trusted_program(self.py,'0'*64)
 def test_symlink_interpreter_rejected(self):
  if Path('/usr/bin/python3').is_symlink():
   with self.assertRaises(OSError):trusted_program('/usr/bin/python3',self.pyhash)
 def test_root_capsules_compile_and_refuse_nonroot(self):
  import subprocess
  c=build_anchor.build(Path(__file__).parent,'validation')
  for key in ('anchor','worker'):
   compile(c[key],key,'exec')
   with tempfile.TemporaryDirectory(prefix='tu1nz-anchor-capsule-',dir='/tmp') as directory:
    script=Path(directory)/(key+'.py');script.write_bytes(c[key]);script.chmod(0o600);p=subprocess.run([sys.executable,'-I','-B',str(script)],stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.assertEqual(p.returncode,78)
if __name__=='__main__':unittest.main()
