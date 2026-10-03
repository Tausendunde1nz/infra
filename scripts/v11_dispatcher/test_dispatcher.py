import os,sys,subprocess,tempfile,json,unittest,hashlib
from pathlib import Path
from core import *
import build,units
HERE=Path(__file__).resolve().parent
B={'transaction':'v11-'+'a'*32,'origin_boot':'01234567-89ab-cdef-0123-456789abcdef','contract_sha256':'b'*64}
BOOT2='fedcba98-7654-3210-fedc-ba9876543210'
class Replay(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(prefix='tu1nz-dispatcher-test-',dir='/tmp');self.root=Path(self.t.name);self.root.chmod(0o700);s=Durable(self.root,fixture=True);s.initialize(B);s.close()
 def tearDown(self):self.t.cleanup()
 def run_child(self,point='',boot=None):
  code='import sys,runpy;sys.path.insert(0,'+repr(str(HERE))+');sys.argv='+repr([str(HERE/'fixture.py'),str(self.root),point,boot or B['origin_boot']])+';runpy.run_path(sys.argv[0],run_name="__main__")'
  return subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 def test_complete_and_repeat(self):
  for _ in range(3):
   p=self.run_child();self.assertEqual(p.returncode,0,p.stderr);self.assertIn(b'ROLLED_BACK',p.stdout);self.assertIn(b'PERMIT True',p.stdout)
 def test_lock_exclusion(self):
  s=Durable(self.root,fixture=True)
  try:
   with s.locked():
    p=self.run_child();self.assertNotEqual(p.returncode,0);self.assertEqual(s.read('gate.json',0o600),{'state':'CLOSED'})
  finally:s.close()
 def test_corrupt_journal_closes_previously_open_gate(self):
  self.assertEqual(self.run_child().returncode,0);p=self.root/'step-000001.json';p.chmod(0o600);p.write_bytes(b'{}');p.chmod(0o400)
  r=self.run_child();self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'PRESEAL_SECURED_STOP',r.stdout);self.assertIn(b'PERMIT False',r.stdout)
 def test_replaced_state_path(self):
  s=Durable(self.root,fixture=True);other=self.root.with_name(self.root.name+'-old');self.root.rename(other);self.root.mkdir(mode=0o700)
  try:
   with self.assertRaises(Refused):s.read('binding.json')
  finally:
   s.close();self.root.rmdir();other.rename(self.root)
 def test_foreign_transaction(self):
  self.assertEqual(self.run_child('after_intent:CLOSE').returncode,91);p=self.root/'step-000000.json';x=json.loads(p.read_bytes());x['binding']['transaction']='v11-'+'c'*32;p.chmod(0o600);p.write_bytes(raw(x));p.chmod(0o400)
  r=self.run_child();self.assertIn(b'PRESEAL_SECURED_STOP',r.stdout)

def crash(point,reboot):
 def test(self):
  a=self.run_child(point);self.assertEqual(a.returncode,91,a.stderr)
  b=self.run_child(boot=BOOT2 if reboot else None);self.assertEqual(b.returncode,0,b.stderr);self.assertIn(b'ROLLED_BACK',b.stdout);self.assertIn(b'PERMIT True',b.stdout)
  before={p.name:p.read_bytes() for p in self.root.glob('step-*')};self.assertEqual(self.run_child(boot=BOOT2 if reboot else None).returncode,0);self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.glob('step-*')})
 return test
for step in STEPS:
 for edge in ('before_intent','after_intent','before_action','after_action','after_completion'):
  for reboot in (False,True):setattr(Replay,'test_'+step+'_'+edge+str(reboot),crash(edge+':'+step,reboot))
for point in ('before_release','after_release'):
 for reboot in (False,True):setattr(Replay,'test_'+point+str(reboot),crash(point,reboot))
class Capsule(unittest.TestCase):
 def test_hashes_and_compile(self):
  b=build.build(HERE,B);self.assertEqual(sha(b['manifest']),b['manifest_sha256']);self.assertFalse(b['activation_ready']);m=parse(b['manifest'])
  self.assertEqual(len(set(m['artifacts'].values())),3)
  for name,data in b['artifacts'].items():self.assertEqual(sha(data),m['artifacts'][name]);compile(data,name,'exec')
 def test_no_author_checkout_or_shell(self):
  b=build.build(HERE,B)
  for data in b['artifacts'].values():self.assertNotIn(b'/opt/tu1nz_repos/worktrees/',data);self.assertNotIn(b'shell=True',data)
 def test_pin_injection(self):
  with self.assertRaises(ValueError):units.templates('x;touch /tmp/unsafe')
 def test_unit_graph_separates_boot_from_worker(self):
  u=units.templates('a'*64);self.assertNotIn('recover',u[units.BOOT].split('ExecStart=')[1].split('\n')[0]);self.assertNotIn('Before='+units.LEGACY_TIMER,u[units.WORK]);self.assertIn('Restart=on-failure',u[units.WORK]);self.assertIn('StartLimitIntervalSec=0',u[units.WORK]);self.assertIn('NoNewPrivileges=yes',u[units.WORK])
 def test_systemd_verify(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-dispatcher-units-') as tmp:
   d=Path(tmp);u=units.templates('a'*64)
   # Substitute only executable file locations for syntax/graph verification;
   # production paths remain separately pinned in the generated payload.
   for name,text in u.items():
    p=d/name;p.parent.mkdir(exist_ok=True);p.write_text(text.replace('/usr/bin/python3 -I -B '+units.PACKAGE+'/dispatcher.py','/usr/bin/python3').replace('/usr/bin/python3 -I -B '+units.PACKAGE+'/watchdog.py','/usr/bin/python3'))
   (d/units.GUARD).write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
   (d/units.LEGACY_TIMER).write_text('[Timer]\nOnBootSec=60\nUnit='+units.GUARD+'\n[Install]\nWantedBy=timers.target\n')
   env=dict(os.environ,SYSTEMD_UNIT_PATH=str(d)+':/usr/lib/systemd/system');p=subprocess.run(['systemd-analyze','verify',*map(str,d.glob('*.service')),*map(str,d.glob('*.timer'))],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   self.assertEqual(p.returncode,0,p.stderr.decode())
if __name__=='__main__':unittest.main()
