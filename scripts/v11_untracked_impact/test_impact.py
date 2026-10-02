import hashlib,importlib.util,json,os,pathlib,py_compile,stat,struct,subprocess,sys,tempfile,unittest,signal,time
from unittest.mock import patch
import impact as i
import collector as c
import bootstrap,command
class Tests(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory();self.p=pathlib.Path(self.t.name);self.f=self.p/'file';self.f.write_bytes(b'fixture')
 def tearDown(self):self.t.cleanup()
 def test_regular_hash(self):self.assertEqual(i.inventory_one(self.p,'file')['sha256'],hashlib.sha256(b'fixture').hexdigest())
 def test_symlink_not_followed(self):
  (self.p/'link').symlink_to('/does/not/exist');r=i.inventory_one(self.p,'link');self.assertEqual(r['type'],'symlink');self.assertIsNone(r['sha256'])
 def test_symlink_credentials_redacted(self):
  (self.p/'link').symlink_to('https://synthetic:secret@example.invalid/a');self.assertNotIn('secret',json.dumps(i.inventory_one(self.p,'link')))
 def test_parent_symlink_refused(self):
  (self.p/'alias').symlink_to(self.p)
  with self.assertRaises(OSError):i.inventory_one(self.p,'alias/file')
 def test_fifo_not_opened(self):
  os.mkfifo(self.p/'pipe');self.assertEqual(i.inventory_one(self.p,'pipe')['hash_reason'],'NOT_REGULAR')
 def test_large_not_opened(self):
  with self.f.open('wb') as f:f.truncate(i.LIMIT+1)
  self.assertEqual(i.inventory_one(self.p,'file')['hash_reason'],'SIZE_LIMIT')
 def test_runtime_not_opened(self):
  self.f.rename(self.p/'job.lock');self.assertEqual(i.inventory_one(self.p,'job.lock')['hash_reason'],'POTENTIALLY_ACTIVE_RUNTIME_NOT_OPENED')
 def test_hardlink_not_opened(self):
  os.link(self.f,self.p/'link');self.assertEqual(i.inventory_one(self.p,'file')['hash_reason'],'HARDLINK_NOT_OPENED')
 def test_traversal_refused(self):
  for p in ['../file','/file','.git/config']:
   with self.assertRaises(i.Refused):i.inventory_one(self.p,p)
 def test_acl_mask(self):
  raw=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,0xffffffff) for tag,perm in [(1,7),(4,7),(16,5),(32,0)])
  self.assertEqual(next(x for x in i.acl(raw) if x['tag']=='group_obj')['effective_permissions'],5)
 def test_bad_acl(self):
  with self.assertRaises(i.Refused):i.acl(b'bad')
 def test_benign_no_gate(self):
  r=i.dimensions('PASS',[{'impact':'BENIGN'}],'EXPECTED_CHATOPS_CONTROLLED');self.assertEqual(r['overall'],'TRUSTED_CLEAN_TRACKED_WITH_BENIGN_UNTRACKED_STATE')
 def test_operational_controlled(self):
  r=i.dimensions('PASS',[{'impact':'EXECUTION_RELEVANT','controlled':True}],'EXPECTED_CHATOPS_CONTROLLED');self.assertEqual(r['overall'],'TRUSTED_TRACKED_WITH_CONTROLLED_OPERATIONAL_STATE')
 def test_unknown_contract(self):self.assertEqual(i.dimensions('PASS',[{'impact':'BENIGN'}],'UNPROVEN')['overall'],'CHECKOUT_CONTRACT_UNPROVEN')
 def test_actual_shadow_risk(self):self.assertEqual(i.dimensions('PASS',[{'impact':'SECURITY_RELEVANT','active_shadow_risk':True}],'EXPECTED_CHATOPS_CONTROLLED')['overall'],'TRUSTED_TRACKED_BUT_EXECUTION_SHADOW_RISK')
 def test_unproven_never_trusted(self):self.assertEqual(i.dimensions('UNPROVEN',[{'impact':'SECURITY_RELEVANT','active_shadow_risk':True}],'UNPROVEN')['overall'],'CHECKOUT_CONTRACT_UNPROVEN')
 def test_tracked_failure_independent(self):self.assertEqual(i.dimensions('FAIL',[{'impact':'BENIGN'}],'EXPECTED_CHATOPS_CONTROLLED')['overall'],'LOCAL_CHECKOUT_DRIFT')
 def test_writer_precedence(self):self.assertEqual(i.dimensions('PASS',[],'UNPROVEN',writers=True)['overall'],'ACTIVE_WRITER_OR_TRANSACTION')
 def test_orphan_pycache_not_standard_import(self):
  p=self.p/'untracked_fixture.py';p.write_text('value=1\n');py_compile.compile(str(p),doraise=True);p.unlink()
  code='import sys;sys.path.insert(0,sys.argv[1]);import untracked_fixture'
  r=subprocess.run([sys.executable,'-I','-B','-c',code,str(self.p)],capture_output=True);self.assertNotEqual(r.returncode,0)
 def test_reference_suppression(self):
  p=self.p/'source';p.write_text('token=synthetic-secret\n'+c.ROOT+'/emoji_map.sed\n')
  r=c.references(str(p));self.assertNotIn('synthetic-secret',json.dumps(r));self.assertTrue(r['matches'])
 def test_config_suppression(self):
  p=self.p/'cfg';p.write_text('[safe]\ndirectory = *\n[core]\nsshCommand=synthetic-secret\n')
  r=c.git_config(str(p));self.assertNotIn('synthetic-secret',json.dumps(r));self.assertEqual(r['settings'][0]['value'],'*')
 def test_partial_results_survive_error(self):
  rows=[];c.section(self.p,'one.json',lambda:{'safe':True},rows)
  def fail():raise PermissionError('synthetic-secret')
  c.section(self.p,'two.json',fail,rows);self.assertTrue((self.p/'one.json').exists());self.assertNotIn('synthetic-secret',(self.p/'two.json').read_text());self.assertEqual(rows[1]['status'],'ERROR')
 def test_timeout_record(self):
  def fail():raise c.SectionTimeout('synthetic-secret')
  rows=[];c.section(self.p,'timeout.json',fail,rows);self.assertTrue(rows[0]['timeout'])
 def test_interrupt_preserves_earlier(self):
  rows=[];c.section(self.p,'one.json',lambda:{'safe':True},rows)
  def stop():raise c.Interrupted()
  with self.assertRaises(c.Interrupted):c.section(self.p,'two.json',stop,rows)
  self.assertEqual(len(rows),1);self.assertTrue((self.p/'one.json').exists())
 def test_atomic_no_replace(self):
  c.atomic(self.p,'report.json',{'safe':True})
  with self.assertRaises(FileExistsError):c.atomic(self.p,'report.json',{'safe':False})
  self.assertTrue(json.loads((self.p/'report.json').read_bytes())['safe'])
 def test_secure_read_size(self):
  with self.assertRaises(c.Refused):c.secure_read(self.f,2)
 def test_secure_read_symlink(self):
  (self.p/'link').symlink_to(self.f)
  with self.assertRaises(OSError):c.secure_read(self.p/'link')
 def test_writer_prevents_open(self):
  with self.assertRaises(c.Refused):c.metadata_without_runtime_read('file',{'incomplete':False,'processes':[{'pid':123}]})
 def test_incomplete_view_prevents_open(self):
  with self.assertRaises(c.Refused):c.metadata_without_runtime_read('file',{'incomplete':True,'processes':[]})
 def test_scope_fixed(self):self.assertEqual(len(c.METADATA_PATHS),18);self.assertEqual(len(c.HELPERS),6)
 def test_bootstrap_hash_refused(self):
  out=self.p/'out';out.mkdir(mode=0o700)
  with self.assertRaises(bootstrap.Refused):bootstrap.copy_verified(self.f,out,'a'*64,os.getuid())
 def test_command_hash_refused(self):
  with self.assertRaises(ValueError):command.build(b'x','a'*64,'b'*64)
 def test_bootstrap_owner_refused(self):
  out=self.p/'out';out.mkdir(mode=0o700)
  with self.assertRaises(bootstrap.Refused):bootstrap.copy_verified(self.f,out,hashlib.sha256(b'fixture').hexdigest(),os.getuid()+1)
 def test_source_embedded_exact(self):self.assertTrue(pathlib.Path(c.__file__).read_text().startswith(pathlib.Path(i.__file__).read_text()))
 def test_real_alarm_timeout(self):
  old=signal.getsignal(signal.SIGALRM)
  def expire(signum,frame):raise c.SectionTimeout()
  rows=[]
  try:
   signal.signal(signal.SIGALRM,expire);signal.setitimer(signal.ITIMER_REAL,0.02)
   c.section(self.p,'alarm.json',lambda:time.sleep(0.2),rows)
  finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
  self.assertTrue(rows[0]['timeout']);self.assertEqual(c.manifest(rows)['status'],'INCOMPLETE')
 def test_manifest_interrupted_or_fatal(self):
  self.assertEqual(c.manifest([],interrupted=True)['status'],'INCOMPLETE');self.assertEqual(c.manifest([],fatal='OSError')['status'],'INCOMPLETE')
 def test_real_writer_flag_parser_with_fake_proc(self):
  proc=self.p/'proc';f=proc/'999999';(f/'fd').mkdir(parents=True);(f/'fdinfo').mkdir();(f/'cwd').symlink_to('/');(f/'fd/3').symlink_to(c.ROOT+'/emoji_map.sed');(f/'fdinfo/3').write_text('flags:\t0100001\n')
  real=pathlib.Path
  with patch.object(c.pathlib,'Path',side_effect=lambda p:proc if p=='/proc' else real(p)):r=c.writers()
  self.assertEqual(r['processes'][0]['writable_paths'],[c.ROOT+'/emoji_map.sed'])
 def test_candidate_copy_and_offline_rollback_preserve_original(self):
  before=self.f.read_bytes();out=self.p/'candidate';out.mkdir(mode=0o700)
  p=pathlib.Path(bootstrap.copy_verified(self.f,out,hashlib.sha256(before).hexdigest(),os.getuid()))
  self.assertEqual(p.read_bytes(),before);self.assertEqual(self.f.read_bytes(),before)
  # Only a newly created, hash-matching isolated candidate is removed.
  self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),hashlib.sha256(before).hexdigest());p.unlink();self.assertEqual(self.f.read_bytes(),before)
 def test_short_read_refused(self):
  with patch.object(c.os,'read',return_value=b'f'):
   with self.assertRaises(c.Refused):c.secure_read(self.f)
 def test_reference_symlink_outside_scope(self):
  p=self.p/'link';p.symlink_to(self.f)
  with self.assertRaises(c.Refused):c.references(str(p))
if __name__=='__main__':unittest.main()
