import unittest,tempfile,os,json,hashlib,copy,stat
from pathlib import Path
import manifest as m
import guard,production

def row(path='file',data=b'content',mode='100644'):
 return (path,mode,hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),data)
def src(rows=None):return m.source('Tausendunde1nz/docs','1'*40,'2'*40,rows or [row()],'2026-10-02T00:00:00Z')
def approved(rows=None):return m.approve(src(rows),{'schema':1,'kind':'GENERATED_MANIFEST','entries':[]})
class ManifestTests(unittest.TestCase):
 def test_reproducible(self):self.assertEqual(m.canonical(approved()),m.canonical(approved()))
 def test_parse(self):
  b=m.canonical(approved());self.assertEqual(m.parse(b,m.digest(b),'1'*40,'2'*40),approved())
 def test_corrupt_hash(self):self.assertRaises(m.Refused,m.parse,b'{}','0'*64,'1'*40,'2'*40)
 def test_empty(self):self.assertRaises(m.Refused,m.parse,b'',m.digest(b''),'1'*40,'2'*40)
 def test_big(self):b=b'x'*(m.MAX_BYTES+1);self.assertRaises(m.Refused,m.parse,b,m.digest(b),'1'*40,'2'*40)
 def test_duplicate(self):self.assertRaises(m.Refused,src,[row(),row()])
 def test_symlink_tree(self):self.assertRaises(m.Refused,src,[row(mode='120000')])
 def test_bad_git_blob(self):x=list(row());x[2]='0'*40;self.assertRaises(m.Refused,src,[tuple(x)])
 def test_paths(self):
  for path in ['/a','../a','a/../b','a//b','./a','-x','a/-x','a\nb','a\x00b','a\\b']:
   with self.subTest(path=path):self.assertRaises(m.Refused,src,[row(path)])
 def test_no_automatic_generated(self):self.assertRaises(m.Refused,m.approve,src(),{'schema':1,'kind':'GENERATED_MANIFEST','entries':[{}]})
 def test_no_automatic_enrollment(self):
  a=approved();a['entries'].append({'path':'extra','type':'regular','git_mode':'100644','git_blob':'a'*40,'sha256':'b'*64});a['entries'].sort(key=lambda x:x['path']);self.assertRaises(m.Refused,m.validate,a)
 def test_no_untrusted_commit(self):
  b=m.canonical(approved());self.assertRaises(m.Refused,m.parse,b,m.digest(b),'3'*40,'2'*40)
 def test_timestamp_not_authority(self):self.assertFalse(approved()['metadata']['timestamp_is_trust_anchor'])
 def test_duplicate_json(self):
  b=b'{"schema":1,"schema":1}';self.assertRaises(m.Refused,m.parse,b,m.digest(b),'1'*40,'2'*40)

class GuardTests(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory(prefix='tu1nz-docs-test-');self.root=Path(self.t.name);self.f=self.root/'file';self.f.write_bytes(b'content');self.a=approved()
 def tearDown(self):self.t.cleanup()
 def result(self):return guard.observe(self.root,self.a)
 def test_good(self):self.assertTrue(self.result()['passed'])
 def test_missing(self):self.f.unlink();self.assertEqual(self.result()['entries'][0]['status'],'MISSING')
 def test_content_change(self):self.f.write_bytes(b'changed');self.assertEqual(self.result()['entries'][0]['status'],'CONTENT_MISMATCH')
 def test_alarm_no_update(self):
  b=m.canonical(self.a);self.f.unlink();self.assertFalse(self.result()['passed']);self.assertEqual(m.canonical(self.a),b)
 def test_extra_separate(self):(self.root/'extra').write_bytes(b'x');r=self.result();self.assertTrue(r['passed']);self.assertEqual(r['additional_paths'],['extra'])
 def test_symlink(self):self.f.unlink();self.f.symlink_to('/etc/passwd');self.assertEqual(self.result()['entries'][0]['status'],'UNSAFE_OR_UNREADABLE')
 def test_hardlink(self):os.link(self.f,self.root/'link');self.assertFalse(self.result()['passed'])
 def test_fifo(self):self.f.unlink();os.mkfifo(self.f);self.assertFalse(self.result()['passed'])
 def test_device(self):
  # Read-only real /dev/null, no mknod or privileged operation.
  fd=os.open('/dev',os.O_RDONLY|os.O_DIRECTORY)
  try:self.assertRaises(m.Refused,guard.measure,fd,'null')
  finally:os.close(fd)
 def test_parent_symlink(self):
  self.f.unlink();(self.root/'dir').symlink_to('/tmp');self.a=approved([row('dir/file')]);self.assertFalse(self.result()['passed'])
 def test_replacement(self):
  fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  def swap():p=self.root/'new';p.write_bytes(b'content');p.replace(self.f)
  try:self.assertRaises(m.Refused,guard.measure,fd,'file',swap)
  finally:os.close(fd)
 def test_directory_replacement(self):
  d=self.root/'d';d.mkdir();(d/'f').write_bytes(b'content');fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  def swap():d.rename(self.root/'old');d.mkdir();(d/'f').write_bytes(b'content')
  try:self.assertRaises(m.Refused,guard.measure,fd,'d/f',swap)
  finally:os.close(fd)
 def test_limit(self):
  with self.f.open('wb') as f:f.truncate(guard.MAX_FILE+1)
  self.assertFalse(self.result()['passed'])
 def test_report_reject_writable(self):self.assertRaises(m.Refused,guard.publish_report,self.root,{'passed':True},os.getuid())

class ProductionTests(unittest.TestCase):
 def test_compile_candidates(self):
  for p,r in production.payloads(Path(__file__).parent).items():
   if p.endswith('.py') or p.endswith('checksum_verify'):compile(r['bytes'],p,'exec')
 def test_service_sandbox(self):
  b=production.service_dropin();self.assertIn(b'PrivateNetwork=yes',b);self.assertIn(b'ProtectSystem=strict',b);self.assertIn(b'TimeoutStartSec=120',b);self.assertNotIn(b'/bin/bash',b)
 def test_no_root_checkout_write(self):self.assertNotIn(production.DOCS.encode(),next(l for l in production.service_dropin().splitlines() if l.startswith(b'ReadWritePaths=')))
 def test_status_only(self):s=production.status_reader();self.assertNotIn(b'sha256sum',s);self.assertIn(b'ExecMainStatus',s);self.assertIn(b'O_NOFOLLOW',s)
if __name__=='__main__':unittest.main()

class RootPathTests(unittest.TestCase):
 def test_root_parent_symlink(self):
  with tempfile.TemporaryDirectory() as n:
   p=Path(n);(p/'real').mkdir();(p/'real'/'docs').mkdir();(p/'link').symlink_to(p/'real');self.assertRaises(OSError,guard.observe,p/'link'/'docs',approved())
 def test_wrong_root_identity(self):
  with tempfile.TemporaryDirectory() as n:self.assertRaises(m.Refused,guard.observe,n,approved(),(0,0,0,0,0o755))
