import hashlib,json,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import collector as c
import bootstrap as b
import command as command

FAKE=b'123456789:'+b'Z'*35
class ScopedTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);self.root.chmod(0o700)
 def file(self,name='input',data=b'safe'):
  p=self.root/name;p.write_bytes(data);p.chmod(0o600);return p
 def test_token_is_never_exported(self):
  data=b'BOT_TOKEN='+FAKE+b'\nPRIVATE_PAYLOAD=private-person-message\n'
  value=c.summarize(data,FAKE);serialized=c.encode(value)
  self.assertTrue(value['exposed_token_reference']);self.assertNotIn(FAKE,serialized);self.assertNotIn(b'private-person-message',serialized)
 def test_exact_reference_comparison(self):
  self.assertFalse(c.summarize(FAKE[:-1],FAKE)['exposed_token_reference']);self.assertTrue(c.summarize(FAKE,FAKE)['exposed_token_reference'])
 def test_fixed_unit_scope(self):
  with self.assertRaises(c.Refused):c.unit_command('ssh.service')
 def test_unit_env_and_command_never_export_values(self):
  u=c.SERVICES[0];data=('Id='+u+'\nActiveState=inactive\nUser=root\nGroup=root\nMainPID=0\nEnvironment=SECRET=').encode()+FAKE+b'\nExecStart=/bin/echo private-message\n'
  r=c.unit_record(u,data,FAKE);serialized=c.encode(r)
  self.assertTrue(r['Environment']['token_reference']);self.assertNotIn(FAKE,serialized);self.assertNotIn(b'private-message',serialized)
 def test_wrong_unit_rejected(self):
  with self.assertRaises(c.Refused):c.unit_record(c.SERVICES[0],b'Id=ssh.service\nActiveState=active\n',FAKE)
 def test_duplicate_properties_rejected(self):
  with self.assertRaises(c.Refused):c.unit_record(c.SERVICES[0],b'Id=x\nId=y\n',FAKE)
 def test_no_approval_or_database_scope(self):
  for p in c.FILES+c.UNIT_FILES:self.assertNotIn('ape-approval',p);self.assertNotIn('database',p)
 def test_read_metadata_and_hash(self):
  p=self.file();data,m=c.read_file(p);self.assertEqual(m['sha256'],hashlib.sha256(data).hexdigest());self.assertEqual(m['mode'],'0o600')
 def test_leaf_symlink_refused(self):
  p=self.file();q=self.root/'link';q.symlink_to(p)
  with self.assertRaises(OSError):c.read_file(q)
 def test_parent_symlink_refused(self):
  p=self.file();q=self.root/'dirlink';q.symlink_to(self.root,target_is_directory=True)
  with self.assertRaises(OSError):c.read_file(q/'input')
 def test_hardlink_refused(self):
  p=self.file();os.link(p,self.root/'other')
  with self.assertRaises(c.Refused):c.read_file(p)
 def test_fifo_refused_without_block(self):
  p=self.root/'fifo';os.mkfifo(p)
  with self.assertRaises(c.Refused):c.read_file(p)
 def test_size_bound(self):
  p=self.file(data=b'12345')
  with self.assertRaises(c.Refused):c.read_file(p,limit=4)
 def test_content_race_refused(self):
  p=self.file()
  with self.assertRaises(c.Refused):c.read_file(p,after_read=lambda:p.write_bytes(b'changed'))
 def test_rename_race_refused(self):
  p=self.file();q=self.file('replacement')
  with self.assertRaises(c.Refused):c.read_file(p,after_read=lambda:os.replace(q,p))
 def test_atomic_modes_no_overwrite(self):
  c.atomic(self.root,'safe.json',{'status':'OK'});p=self.root/'safe.json';self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
  with self.assertRaises(FileExistsError):c.atomic(self.root,'safe.json',{'status':'OTHER'})
  self.assertEqual(json.loads(p.read_bytes()),{'status':'OK'});self.assertFalse(list(self.root.glob('.safe*')))
 def test_bad_output_name_refused(self):
  with self.assertRaises(c.Refused):c.atomic(self.root,'../bad.json',{})
 def test_output_symlink_refused(self):
  q=self.root/'link';q.symlink_to(self.root,target_is_directory=True)
  with self.assertRaises(c.Refused):c.atomic(q,'safe.json',{})
 def test_existing_foreign_output_refused(self):
  p=self.file('safe.json');self.assertEqual(p.read_bytes(),b'safe')
  with self.assertRaises(FileExistsError):c.atomic(self.root,'safe.json',{})
 def collect(self,failure=None):
  raw=b'BOT_TOKEN='+FAKE+b'\n'
  def read(path):
   if path!=c.SOURCE and failure:failure()
   return raw,{'sha256':hashlib.sha256(raw).hexdigest()}
  def run(unit):return ('Id='+unit+'\nActiveState=inactive\nMainPID=0\n').encode()
  with patch.object(c,'SOURCE_SHA',hashlib.sha256(raw).hexdigest()):
   return c.collect(self.root,reader=read,runner=run,locks=lambda p:{'absent':True},transactions=lambda:[])
 def test_full_fake_run_secret_suppression_and_checksums(self):
  m=self.collect();self.assertEqual(m['status'],'COMPLETE')
  for row in m['sections']:
   data=(self.root/row['section']).read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),row['sha256']);self.assertNotIn(FAKE,data)
 def test_permission_error_is_partial_without_error_text(self):
  def fail():raise PermissionError(FAKE.decode())
  m=self.collect(fail);self.assertEqual(m['status'],'INCOMPLETE');self.assertTrue((self.root/'file-000.json').exists())
  for f in self.root.iterdir():self.assertNotIn(FAKE,f.read_bytes())
 def test_timeout_is_partial_and_preserves_earlier_result(self):
  def fail():raise TimeoutError('private message')
  m=self.collect(fail);self.assertEqual(m['status'],'INCOMPLETE');self.assertTrue((self.root/'file-000.json').exists())
 def test_interrupt_writes_partial_manifest(self):
  def fail():raise KeyboardInterrupt()
  m=self.collect(fail);self.assertEqual(m['status'],'INCOMPLETE');self.assertTrue((self.root/'file-000.json').exists());self.assertEqual(m['fatal_error_class'],'KeyboardInterrupt')
 def test_source_drift_stops_before_consumer_read(self):
  calls=[]
  def read(path):calls.append(path);return b'wrong',{}
  m=c.collect(self.root,reader=read);self.assertEqual(calls,[c.SOURCE]);self.assertEqual(m['status'],'INCOMPLETE')
 def test_root_copy_hash_is_verified_on_copy(self):
  p=self.file(data=b'print(1)\n');stage=self.root/'stage';stage.mkdir(mode=0o700)
  q=Path(b.copy_verified(str(p),stage,hashlib.sha256(p.read_bytes()).hexdigest(),os.geteuid()));self.assertEqual(q.read_bytes(),p.read_bytes());self.assertEqual(q.stat().st_mode&0o777,0o600)
 def test_root_copy_bad_hash_refuses(self):
  p=self.file();stage=self.root/'stage';stage.mkdir(mode=0o700)
  with self.assertRaises(b.Refused):b.copy_verified(str(p),stage,'0'*64,os.geteuid())
 def test_root_copy_wrong_owner_refuses(self):
  p=self.file();stage=self.root/'stage';stage.mkdir(mode=0o700)
  with self.assertRaises(b.Refused):b.copy_verified(str(p),stage,hashlib.sha256(p.read_bytes()).hexdigest(),os.geteuid()+1)
 def test_root_copy_parent_symlink_refuses(self):
  p=self.file();link=self.root/'link';link.symlink_to(self.root,target_is_directory=True);stage=self.root/'stage';stage.mkdir(mode=0o700)
  with self.assertRaises(OSError):b.copy_verified(str(link/'input'),stage,hashlib.sha256(p.read_bytes()).hexdigest(),os.geteuid())
 def test_root_copy_hardlink_refuses(self):
  p=self.file();os.link(p,self.root/'other');stage=self.root/'stage';stage.mkdir(mode=0o700)
  with self.assertRaises(b.Refused):b.copy_verified(str(p),stage,hashlib.sha256(p.read_bytes()).hexdigest(),os.geteuid())
 def test_renderer_binds_script_and_isolates_python(self):
  raw=b'pass\n';s=command.build(raw,hashlib.sha256(raw).hexdigest(),'a'*64);self.assertIn('-I -B',s);self.assertIn('sudo',s);self.assertIn('StrictHostKeyChecking=yes',s)
  with self.assertRaises(ValueError):command.build(raw,'0'*64,'a'*64)
 def test_acl_numeric_mask_only(self):
  import struct
  raw=struct.pack('<IHHIHHI',2,1,6,4294967295,16,4,4294967295)
  with patch.object(c.os,'getxattr',return_value=raw):result=c.acl(1)
  self.assertEqual(result['system.posix_acl_access'][1]['permissions'],4)
 def test_invalid_acl_refused(self):
  with patch.object(c.os,'getxattr',return_value=b'invalid'):
   with self.assertRaises(c.Refused):c.acl(1)
 def test_root_copy_directory_acl_refused(self):
  p=self.file();stage=self.root/'stage';stage.mkdir(mode=0o700)
  with patch.object(b.os,'listxattr',return_value=['system.posix_acl_default']):
   with self.assertRaises(b.Refused):b.copy_verified(str(p),stage,hashlib.sha256(p.read_bytes()).hexdigest(),os.geteuid())
 def test_new_dropin_is_unresolved_not_silently_ignored(self):
  u=c.SERVICES[0];r=c.unit_record(u,('Id='+u+'\nActiveState=inactive\nDropInPaths=/etc/systemd/system/unknown.conf\n').encode(),FAKE)
  self.assertFalse(r['scope_complete']);self.assertNotIn(b'unknown.conf',c.encode(r))
 def test_new_credential_path_is_unresolved_not_read(self):
  u=c.SERVICES[0];r=c.unit_record(u,('Id='+u+'\nActiveState=inactive\nLoadCredential=token:/etc/tu1nz/unreviewed-token\n').encode(),FAKE)
  self.assertFalse(r['scope_complete']);self.assertNotIn(b'unreviewed-token',c.encode(r))
 def test_original_change_after_copy_cannot_change_root_copy(self):
  p=self.file(data=b'original');stage=self.root/'stage';stage.mkdir(mode=0o700)
  q=Path(b.copy_verified(str(p),stage,hashlib.sha256(p.read_bytes()).hexdigest(),os.geteuid()));p.write_bytes(b'modified')
  self.assertEqual(q.read_bytes(),b'original')
 def test_systemctl_failure_never_exports_stderr(self):
  from types import SimpleNamespace
  with patch.object(c.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=FAKE,stderr=FAKE)):
   with self.assertRaises(c.Refused) as ctx:c.unit_command(c.SERVICES[0])
   self.assertNotIn(FAKE.decode(),str(ctx.exception))
 def test_program_missing_is_a_class_only_section_error(self):
  def fail():raise FileNotFoundError(FAKE.decode())
  m=self.collect(fail);self.assertEqual(m['status'],'COMPLETE')
  # Missing inputs are recorded as ABSENT; no exception message is persisted.
  for f in self.root.iterdir():self.assertNotIn(FAKE,f.read_bytes())
 def test_backup_reference_is_not_a_live_script_reference(self):
  refs=c.summarize(b'/usr/local/bin/trendwatch_post.sh.bak_2025-11-30',FAKE)['consumer_path_references']
  self.assertNotIn(c.SOURCE,refs);self.assertIn('/usr/local/bin/trendwatch_post.sh.bak_2025-11-30',refs)
if __name__=='__main__':unittest.main()
