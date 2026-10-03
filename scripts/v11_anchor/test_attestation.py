import unittest,sys,os,tempfile,shutil,subprocess,copy,time
from pathlib import Path
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_guard_recovery'),str(HERE.parent/'v11_dispatcher')]
from anchor import *
import phase0,attestation,state as gs
BOOT_ID='01234567-89ab-cdef-0123-456789abcdef'
class Verifier:
 def confirm_closed(self):pass
 def verify_completed(self,c,state):
  if state['phase']!='COMPLETED':raise Refused('VERIFIER_NONTERMINAL')
def terminal_guard(path,transaction):
 g=gs.Store(path,fixture=True);g.initialize({'transaction':transaction,'boot':BOOT_ID,'contract_sha256':'b'*64,'deadline_ns':time.monotonic_ns()+600_000_000_000,'coordinator_pid':os.getpid(),'coordinator_start_ticks':1})
 for phase in gs.PHASES[1:]:
  proof={'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True} if phase=='SECURITY_BARRIER_SEALED' else {'consumer_sha256':'c'*64,'authority_sha256':'d'*64,'loaded_unit_sha256':'e'*64,'result_sha256':'f'*64} if phase=='NEW_CONSUMER_VERIFIED' else {'final_checks_passed':True} if phase=='COMPLETED' else {}
  g.advance(phase,proof)
 return g
def context(s):
 artifacts={'guard':'c'*64,'authority':'d'*64}
 return {'schema':1,'format':'GUARD_COMPLETION_V1','transaction':'v11-'+'a'*32,'guard_boot':BOOT_ID,'recovery_boot':BOOT_ID,'recovery_generation':0,'generation':0,'guard_version':'v11-guard-1','guard_sha256':'c'*64,'guard_contract_sha256':'b'*64,'control_commit':attestation.CONTROL,'control_tree':attestation.TREE,'infra_basis':'8fcd4aaacd6c497ff50e4964733c9e0350e3a781','activation_manifest_sha256':'1'*64,'artifacts':artifacts,'artifact_manifest_sha256':digest(encode(artifacts)),'base_sha256':digest(s.read('base.json')),'worker_pins':s.base()['workers']}
class Attestation(unittest.TestCase):
 def setUp(self):
  self.a=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));self.a.rmdir();self.gp=Path(tempfile.mkdtemp(prefix='tu1nz-fence-test-',dir='/tmp'));self.gp.chmod(0o700)
  phase0.prepare(self.a,b'anchor',[b'worker'],'/usr/bin/python3.12','a'*64,['/run/payload'],fixture=True);self.s=Store(self.a,fixture=True);self.c=context(self.s);self.g=terminal_guard(self.gp,self.c['transaction']);self.gate=attestation.Gate(self.s);self.gate.bind(self.c);self.v=Verifier()
 def tearDown(self):self.g.close();self.s.close();shutil.rmtree(self.a);shutil.rmtree(self.gp)
 def emit(self):return self.gate.publish(self.g,self.v)
 def validate(self):return self.gate.validate(self.c,BOOT_ID,0)
 def test_real_guard_chain_completion_bound(self):self.assertEqual(self.emit(),self.validate())
 def test_idempotent_producer_preserves_inodes(self):
  self.emit();old=(self.a/'attestation-000000.json').stat().st_ino;self.emit();self.assertEqual(old,(self.a/'attestation-000000.json').stat().st_ino)
 def test_missing_attestation_denies(self):
  with self.assertRaises(FileNotFoundError):self.validate()
 def test_nonterminal_guard_denies(self):
  self.g.current=lambda:{'phase':'NEW_CONSUMER_VERIFIED','sealed':True}
  with self.assertRaisesRegex(Refused,'NOT_COMPLETE'):self.emit()
 def test_wrong_transaction_denies(self):
  original=self.g.current
  self.g.current=lambda:{**original(),'binding':{**original()['binding'],'transaction':'v11-'+'b'*32}}
  with self.assertRaisesRegex(Refused,'GUARD_BINDING'):self.emit()
 def test_wrong_guard_boot_denies(self):
  original=self.g.current;self.g.current=lambda:{**original(),'binding':{**original()['binding'],'boot':'11234567-89ab-cdef-0123-456789abcdef'}}
  with self.assertRaisesRegex(Refused,'GUARD_BINDING'):self.emit()
 def test_changed_guard_artifact_denies(self):
  old=self.g.read;self.g.read=lambda n:{**old(n),'proof':{'consumer_sha256':'0'*64}} if n=='state-000005.json' else old(n)
  with self.assertRaisesRegex(gs.Refused,'GENERATION_HASH'):self.emit()
 def test_verification_failure_never_publishes(self):
  self.v.verify_completed=lambda *_:(_ for _ in ()).throw(Refused('PINNED_ARTIFACT_CHANGED'))
  with self.assertRaises(Refused):self.emit()
  self.assertFalse(self.s.exists('attestation-000000.json'))
 def test_wrong_recovery_boot_denies_after_reboot(self):
  self.emit()
  with self.assertRaisesRegex(Refused,'STALE'):self.gate.validate(self.c,'11234567-89ab-cdef-0123-456789abcdef',0)
 def test_wrong_recovery_generation_denies(self):
  self.emit()
  with self.assertRaisesRegex(Refused,'STALE'):self.gate.validate(self.c,BOOT_ID,1)
 def test_altered_manifest_denies(self):
  self.emit();c=copy.deepcopy(self.c);c['artifacts']['guard']='0'*64
  with self.assertRaisesRegex(Refused,'STALE'):self.gate.validate(c,BOOT_ID,0)
 def test_changed_version_context_denies(self):
  self.emit();c=dict(self.c,guard_version='v2')
  with self.assertRaisesRegex(Refused,'STALE'):self.gate.validate(c,BOOT_ID,0)
 def test_single_use_and_exact_resume(self):
  self.emit();r=self.gate.admit(self.c,BOOT_ID,0,'9'*64)
  with self.assertRaisesRegex(Refused,'REPLAY'):self.gate.admit(self.c,BOOT_ID,0,'9'*64)
  self.assertEqual(self.gate.admit(self.c,BOOT_ID,0,'9'*64,resume=True),r)
  with self.assertRaisesRegex(Refused,'REPLAY'):self.gate.admit(self.c,BOOT_ID,0,'8'*64,resume=True)
 def test_resume_without_consumption_denies(self):
  self.emit()
  with self.assertRaisesRegex(Refused,'NO_PRIOR'):self.gate.admit(self.c,BOOT_ID,0,'9'*64,resume=True)
 def test_commit_missing_denies(self):
  self.emit();(self.a/'attestation-commit-000000.json').unlink()
  with self.assertRaises(FileNotFoundError):self.validate()
 def test_commit_content_drift_denies(self):
  self.emit();p=self.a/'attestation-commit-000000.json';p.chmod(0o600);p.write_bytes(b'{}\n');p.chmod(0o400)
  with self.assertRaisesRegex(Refused,'NOT_SYNCED'):self.validate()
 def test_symlink_denied(self):
  self.emit();p=self.a/'attestation-000000.json';p.unlink();p.symlink_to('/etc/passwd')
  with self.assertRaises(OSError):self.validate()
 def test_hardlink_denied(self):
  self.emit();os.link(self.a/'attestation-000000.json',self.a/'copy')
  with self.assertRaises(Refused):self.validate()
 def test_mode_acl_denied(self):
  self.emit();p=self.a/'attestation-000000.json';p.chmod(0o440)
  with self.assertRaises(Refused):self.validate()
 def test_parent_swap_denied(self):
  self.emit();old=self.a.with_name(self.a.name+'-old');self.a.rename(old);self.a.mkdir(mode=0o700)
  try:
   with self.assertRaises(Refused):self.validate()
  finally:self.a.rmdir();old.rename(self.a)
 def test_parallel_guard_lock_denies(self):
  code='import sys;sys.path[:0]='+repr([str(HERE),str(HERE.parent/'v11_guard_recovery')])+';from anchor import Store;import state,attestation;s=Store('+repr(str(self.a))+',fixture=True);g=state.Store('+repr(str(self.gp))+',fixture=True);attestation.Gate(s).publish(g,object())'
  with self.g.locked():
   p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.assertNotEqual(p.returncode,0);self.assertFalse(self.s.exists('attestation-000000.json'))
 def test_fence_closed_on_producer(self):self.emit();self.assertTrue(self.s.closed())
 def test_duplicate_field_denied(self):
  self.emit();p=self.a/'attestation-000000.json';p.chmod(0o600);p.write_bytes(b'{"schema":1,"schema":2}');p.chmod(0o400)
  with self.assertRaisesRegex(Refused,'DUPLICATE'):self.validate()

def child(a,gp,point):
 s=Store(a,fixture=True,inject=lambda p:os._exit(91) if p==point else None);g=gs.Store(gp,fixture=True);attestation.Gate(s).publish(g,Verifier())
def case(point):
 def test(self):
  code='import sys;sys.path.insert(0,'+repr(str(HERE))+');from test_attestation import child;child('+repr(str(self.a))+','+repr(str(self.gp))+','+repr(point)+')'
  p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);self.assertEqual(p.returncode,91,p.stderr)
  self.s.close();self.s=Store(self.a,fixture=True);self.gate=attestation.Gate(self.s)
  # No commit, no admission. A new process producer must recheck real Guard
  # state before completing the attestation's durability handshake.
  if not self.s.exists('attestation-commit-000000.json'):
   with self.assertRaises((Refused,OSError)):self.validate()
  self.assertEqual(self.emit(),self.validate());self.assertTrue(self.s.closed())
 return test
for point in ('after_guard_complete','before_file_fsync:attestation-000000.json','after_file_fsync:attestation-000000.json','before_publish:attestation-000000.json','after_publish:attestation-000000.json','before_directory_fsync:attestation-000000.json','after_directory_fsync:attestation-000000.json','before_attest_commit','before_file_fsync:attestation-commit-000000.json','after_file_fsync:attestation-commit-000000.json','before_publish:attestation-commit-000000.json','after_publish:attestation-commit-000000.json','before_directory_fsync:attestation-commit-000000.json','after_directory_fsync:attestation-commit-000000.json'):
 setattr(Attestation,'test_crash_'+point.replace(':','_'),case(point))
if __name__=='__main__':unittest.main()
