import unittest,tempfile,os,json,uuid,stat
from pathlib import Path
from authority import *
from offline_transaction import Rehearsal,PHASES,Crash
class AuthorityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-authority-fixture-',dir='/tmp');self.root=Path(self.tmp.name);self.root.chmod(0o700);self.p=self.root/'file';self.p.write_bytes(b'trusted');self.p.chmod(0o600)
 def tearDown(self):self.tmp.cleanup()
 def read(self,**kw):return read_bound(self.p,sha(b'trusted'),os.geteuid(),os.getegid(),0o600,self.root,**kw)
 def test_bound_read(self):self.assertEqual(self.read(),b'trusted')
 def test_symlink(self):self.p.unlink();self.p.symlink_to('/etc/passwd');self.assertRaises(OSError,self.read)
 def test_parent_write(self):self.root.chmod(0o770);self.assertRaises(Refused,self.read)
 def test_hash(self):self.p.write_bytes(b'evil');self.assertRaises(Refused,self.read)
 def test_hardlink(self):os.link(self.p,self.root/'link');self.assertRaises(Refused,self.read)
 def test_wrong_owner(self):self.assertRaises(Refused,read_bound,self.p,sha(b'trusted'),os.geteuid()+1,os.getegid(),0o600,self.root)
 def test_mode(self):self.p.chmod(0o660);self.assertRaises(Refused,self.read)
 def test_replacement(self):
  def swap():
   q=self.root/'new';q.write_bytes(b'trusted');q.chmod(0o600);q.replace(self.p)
  self.assertRaises(Refused,self.read,after_open=swap)
 def test_missing(self):self.p.unlink();self.assertRaises(FileNotFoundError,self.read)
 def test_fifo(self):self.p.unlink();os.mkfifo(self.p,0o600);self.assertRaises(Refused,self.read)
 def test_large(self):self.p.write_bytes(b'x'*(LIMIT+1));self.assertRaises(Refused,self.read)
 def test_paths(self):
  for n in ['-x','/etc/passwd','../a','a/../b','./a','a//b','a/--flag','a\nfoo','a\rb','a\x00b','a\\b']:
   with self.subTest(n=n):self.assertRaises(Refused,safe_name,n)
 def test_list(self):self.assertEqual(filelist(b'a\nb/c\n'),('a','b/c'))
 def test_list_duplicate_empty(self):
  for b in [b'',b'a\na\n',b'\n',b'a']:self.assertRaises(Refused,filelist,b)
 def test_no_auto_rebaseline(self):self.assertEqual(deletion_decision(b'a\nb\n',b'a\n'),{'missing':['b'],'passed':False,'reference_update_permitted':False})
 def test_checksum(self):
  b=(('a'*64)+'  file\n').encode();self.assertTrue(compare_measurement(b,b,{'file'}))
 def test_checksum_injection(self):
  for tail in ['--status','/etc/passwd','../file','./file','file\n--help','file\r','other']:
   with self.subTest(tail=tail):self.assertRaises(Refused,checksums,(('a'*64)+'  '+tail+'\n').encode(),{'file'})
 def test_checksum_duplicate_missing_large(self):
  b=(('a'*64)+'  file\n').encode()
  for data,allow in [(b+b,{'file'}),(b,{'file','missing'}),(b'x'*(LIMIT+1),{'file'}),(b'',{'file'})]:self.assertRaises(Refused,checksums,data,allow)
 def test_git_allowlist(self):
  a=git_read_argv(['rev-parse','HEAD']);self.assertEqual(a[:4],['runuser','-u','chatops','--']);self.assertIn('GIT_OPTIONAL_LOCKS=0',a)
  for args in [['status'],['fetch'],['update-index'],['-c','x=y']]:self.assertRaises(Refused,git_read_argv,args)
 def test_historical_denied(self):
  for n in ['analysis/security_incident_2026-08-25/TU1NZ_SECURITY_S3_apply_tokens.py','scripts/encrypted_drive_backup','emoji_map.sed']:
   self.assertRaises(Refused,privileged_source,CHECKOUT+'/'+n,{})
 def test_sed_options(self):self.assertEqual(sed_argv(8,'--evil'),['/usr/bin/sed','-f','/proc/self/fd/8','--','--evil'])
 def test_contract(self):
  c=json.loads(Path(__file__).with_name('contract.json').read_text());i={'uid':1001,'gid':1001,'mode':'0600','nlink':1,'regular':True,'sha256':'a'*64,'inode':1}
  s={'head':BASE,'tree':TREE,'detached':True,'tracked_pass':True,'index_before':i.copy(),'index_after':i.copy(),'shared_gitdir':True,'origin':'Tausendunde1nz/infra'}
  self.assertEqual(validate_contract(c,s)['topology'],'MIGRATION_REQUIRED')
  s['index_after']['inode']=2;self.assertRaises(Refused,validate_contract,c,s)
 def test_old_base_rejected(self):
  c=json.loads(Path(__file__).with_name('contract.json').read_text());c['production_basis']='b78bb2a';self.assertRaises(Refused,validate_contract,c,{})

class TransactionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-authority-fixture-',dir='/tmp');self.root=Path(self.tmp.name);self.root.chmod(0o700)
  for n in PHASES:(self.root/n).write_bytes(b'old');(self.root/n).chmod(0o600)
  self.r=Rehearsal(self.root,clock=lambda:0);self.expected={n:sha(b'old') for n in PHASES};self.payload={n:('new-'+n).encode() for n in PHASES};self.pins={n:sha(b) for n,b in self.payload.items()}
 def tearDown(self):self.r.close();self.tmp.cleanup()
 def begin(self,**kw):
  args=dict(expected=self.expected,payload=self.payload,pins=self.pins,txid='v11-'+uuid.uuid4().hex,boot='boot-a',now=0,deadline=400_000_000_000,proofs={'sources_reviewed':True,'rollback_tested':True,'consumer_inventory_complete':True});args.update(kw);self.r.begin(**args)
 def test_success(self):
  self.begin()
  for n in PHASES:self.r.step(n)
  self.r.finish();self.assertEqual(self.r.watchdog('b',10**15),'COMPLETED')
 def test_preflight_no_write(self):
  self.expected[PHASES[-1]]='0'*64;self.assertRaises(Refused,self.begin);self.assertFalse((self.root/'state.json').exists())
 def test_short_window(self):self.assertRaises(Refused,self.begin,deadline=1);self.assertFalse((self.root/'state.json').exists())
 def test_concurrent(self):self.assertRaises(Refused,Rehearsal,self.root)
 def test_duplicate(self):self.begin();self.assertRaises(Refused,self.begin)
 def test_precutover_rollback(self):
  self.begin();self.r.step(PHASES[0]);self.assertEqual(self.r.recover(),'ROLLED_BACK')
  for n in PHASES:self.assertEqual((self.root/n).read_bytes(),b'old')
 def test_crash_before(self):
  self.begin();self.assertRaises(Crash,self.r.step,PHASES[0],'crash_before');self.assertEqual(self.r.watchdog('newboot',0),'ROLLED_BACK')
 def test_crash_after(self):
  self.begin();self.assertRaises(Crash,self.r.step,PHASES[0],'crash_after');self.assertEqual(self.r.watchdog('boot-a',10**15),'ROLLED_BACK')
 def test_signal(self):self.begin();self.assertRaises(Refused,self.r.step,PHASES[0],'signal');self.assertEqual(self.r.read()['status'],'ROLLED_BACK')
 def test_timeout(self):self.begin();self.assertRaises(Refused,self.r.step,PHASES[0],'timeout');self.assertEqual(self.r.read()['status'],'ROLLED_BACK')
 def test_forward_only_barrier(self):
  self.begin();self.r.step(PHASES[0]);self.r.step(PHASES[1]);self.assertRaises(Crash,self.r.step,PHASES[2],'crash_after');self.assertEqual(self.r.watchdog('newboot',0),'SECURED_STOP');self.assertNotEqual((self.root/PHASES[2]).read_bytes(),b'old');self.assertEqual(self.r.recover(),'SECURED_STOP')
 def test_foreign_writer_rollback_refused(self):
  self.begin();self.assertRaises(Crash,self.r.step,PHASES[0],'crash_after');(self.root/PHASES[0]).write_bytes(b'foreign');self.assertRaises(Refused,self.r.recover)
 def test_phase_order(self):self.begin();self.assertRaises(Refused,self.r.step,PHASES[1])
 def test_incomplete(self):self.begin();self.assertRaises(Refused,self.r.finish)
if __name__=='__main__':unittest.main()

class IntegrationTests(unittest.TestCase):
 def test_program_sealed(self):
  b=b's/a/b/g\n';fd=sealed_program(b,sha(b))
  try:self.assertRaises(OSError,os.write,fd,b'evil');self.assertEqual(os.read(fd,100),b)
  finally:os.close(fd)
 def test_program_hash(self):self.assertRaises(Refused,sealed_program,b'evil','0'*64)
 def test_actual_map_review(self):
  b=Path(__file__).with_name('emoji_map.sed').read_bytes()
  self.assertEqual(sha(b),'eece58840199bb578c97994246d990c9ef842ced06d29c579e5cc42064d6655b')
  for line in b.decode().splitlines():self.assertRegex(line,r'^s/[^/]+/\[[A-Z]+\]/g$')
 def test_existing_component_pins(self):
  d=Path(__file__).parent;j=json.loads((d/'integration.json').read_text())
  for folder,items in j['components'].items():
   for n,h in items.items():self.assertEqual(sha((d.parent/folder/n).read_bytes()),h)
  self.assertEqual(len(j['ten_paths']),10);self.assertFalse(j['production_activation_ready'])
 def test_posix_acl_rejected(self):
  import struct
  with tempfile.TemporaryDirectory(prefix='tu1nz-authority-fixture-',dir='/tmp') as name:
   p=Path(name);p.chmod(0o700);f=p/'f';f.write_bytes(b'x');f.chmod(0o600)
   entries=[(1,6,0xffffffff),(2,4,os.getuid()+1),(4,0,0xffffffff),(16,0,0xffffffff),(32,0,0xffffffff)]
   os.setxattr(f,'system.posix_acl_access',struct.pack('<I',2)+b''.join(struct.pack('<HHI',*x) for x in entries))
   self.assertRaises(Refused,read_bound,f,sha(b'x'),os.getuid(),os.getgid(),0o600,p)

class LegacyTests(unittest.TestCase):
 def test_known_root_only(self):
  b=('a'*64+'  /opt/tu1nz_repos/docs/file\n').encode();out=canonicalize_legacy_checksums(b,sha(b));self.assertEqual(checksums(out,{'file'}),{'file':'a'*64})
 def test_reject_other_root(self):
  b=('a'*64+'  /etc/file\n').encode();self.assertRaises(Refused,canonicalize_legacy_checksums,b,sha(b))
 def test_reject_traversal(self):
  b=('a'*64+'  /opt/tu1nz_repos/docs/../file\n').encode();self.assertRaises(Refused,canonicalize_legacy_checksums,b,sha(b))
 def test_reject_unpinned(self):self.assertRaises(Refused,canonicalize_legacy_checksums,b'x','0'*64)

class DeadlineTests(unittest.TestCase):
 setUp=TransactionTests.setUp
 tearDown=TransactionTests.tearDown
 begin=TransactionTests.begin
 def test_expired_before_mutation(self):
  self.begin();self.r.clock=lambda:500_000_000_000;self.assertRaises(Refused,self.r.step,PHASES[0]);self.assertEqual(self.r.read()['status'],'ROLLED_BACK')
