import unittest,tempfile,hashlib,os,subprocess,sys
from pathlib import Path
import protected_inputs as p
import input_bootstrap as b
class InputsTests(unittest.TestCase):
 def setUp(self):
  self.data={p.PATHS[0]:b'root ALL=(ALL:ALL) ALL\n'+b'\n'.join(p.REMOVALS)+b'\n',p.PATHS[1]:b'fake grant\n',p.PATHS[2]:b'fake second grant\n',p.PATHS[3]:b'root:!:root:\ndocker:!:admin:chatops,other\n'};self.pins={k:p.digest(self.data[k]) for k in p.PATHS[:3]}
 def test_transform(self):
  r=p.transform(self.data,self.pins);self.assertEqual(r[p.PATHS[0]],b'root ALL=(ALL:ALL) ALL\n');self.assertIsNone(r[p.PATHS[1]]);self.assertIsNone(r[p.PATHS[2]]);self.assertEqual(r[p.PATHS[3]],b'root:!:root:\ndocker:!:admin:other\n')
 def test_no_real_paths_read(self):self.assertRaises(p.Refused,p.read_fixed,'/etc/shadow')
 def test_pin_drift(self):self.data[p.PATHS[0]]+=b'x';self.assertRaises(p.Refused,p.transform,self.data,self.pins)
 def test_duplicate_group(self):self.data[p.PATHS[3]]*=2;self.assertRaises(p.Refused,p.transform,self.data,self.pins)
 def test_missing_group(self):self.data[p.PATHS[3]]=b'other:!::\n';self.assertRaises(p.Refused,p.transform,self.data,self.pins)
 def test_duplicate_member(self):self.data[p.PATHS[3]]=b'docker:!::chatops,chatops\n';self.assertRaises(p.Refused,p.transform,self.data,self.pins)
 def test_duplicate_grant(self):self.data[p.PATHS[0]]+=p.REMOVALS[0]+b'\n';self.pins[p.PATHS[0]]=p.digest(self.data[p.PATHS[0]]);self.assertRaises(p.Refused,p.transform,self.data,self.pins)
 def test_secret_not_redacted_output(self):
  secret=b'SYNTHETIC_SECRET_DO_NOT_EMIT';self.data[p.PATHS[3]]=b'docker:'+secret+b'::chatops,other\n';r=p.transform(self.data,self.pins);redacted={k:None if v is None else p.digest(v) for k,v in r.items()};self.assertNotIn(secret.decode(),str(redacted));self.assertIn(secret,r[p.PATHS[3]])
 def test_nonroot_execution_refused(self):
  r=subprocess.run([sys.executable,'-I','-B',str(Path(p.__file__))],capture_output=True);self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
 def test_bootstrap_copy_hash(self):
  with tempfile.TemporaryDirectory() as n:
   d=Path(n);d.chmod(0o700);source=d/'source';source.write_bytes(b'print(1)');stage=d/'stage';stage.mkdir(mode=0o700)
   out=b.copy_verified(str(source),stage,p.digest(source.read_bytes()),os.getuid());self.assertEqual(Path(out).read_bytes(),source.read_bytes());self.assertEqual(Path(out).stat().st_mode&0o777,0o600)
 def test_bootstrap_wrong_hash(self):
  with tempfile.TemporaryDirectory() as n:
   d=Path(n);d.chmod(0o700);source=d/'source';source.write_bytes(b'x');stage=d/'stage';stage.mkdir(mode=0o700);self.assertRaises(b.Refused,b.copy_verified,str(source),stage,'0'*64,os.getuid())
 def test_bootstrap_symlink(self):
  with tempfile.TemporaryDirectory() as n:
   d=Path(n);d.chmod(0o700);source=d/'source';source.symlink_to('/etc/passwd');stage=d/'stage';stage.mkdir(mode=0o700);self.assertRaises(OSError,b.copy_verified,str(source),stage,'0'*64,os.getuid())
if __name__=='__main__':unittest.main()

class PartialTests(unittest.TestCase):
 def test_timeout_preserves_prior(self):
  saved={};counter=[0]
  def read(path):
   counter[0]+=1
   if counter[0]==3:raise TimeoutError('SYNTHETIC_SECRET')
   return b'x',{'path':path,'sha256':p.digest(b'x')}
  r=p.collect(read,lambda n,b:saved.update({n:b}));self.assertEqual(r['status'],'INCOMPLETE');self.assertEqual(len(saved),2);self.assertNotIn('SYNTHETIC_SECRET',str(r))
 def test_interrupt_preserves_prior(self):
  saved={}
  def read(path):
   if saved:raise KeyboardInterrupt()
   return b'x',{'path':path}
  r=p.collect(read,lambda n,b:saved.update({n:b}));self.assertEqual(r['error_class'],'KeyboardInterrupt');self.assertEqual(len(saved),1)
 def test_permission_error_redacted(self):
  def read(path):raise PermissionError('private-detail')
  r=p.collect(read,lambda *a:None);self.assertEqual(r['error_class'],'PermissionError');self.assertNotIn('private-detail',str(r))
 def test_fixed_deployment_commands(self):
  import deployment as d
  for op in d.OPERATIONS:self.assertEqual(op[:3],('/usr/sbin/runuser','-u','chatops'));self.assertIn('GIT_OPTIONAL_LOCKS=0',op)
  self.assertFalse(any('/opt/tu1nz_repos/control'==x for op in d.OPERATIONS for x in op))
