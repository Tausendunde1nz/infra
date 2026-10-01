import hashlib,json,os,tempfile,unittest
from pathlib import Path
import doc_publish as p
import doc_worker as w
class DocumentsTests(unittest.TestCase):
 def fixture(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);d=Path(t.name);d.chmod(0o700)
  data={'document.html':b'<!doctype html><html>fixture</html>','document.pdf':b'%PDF-1.4\nfixture\n%%EOF'}
  for n,b in data.items():(d/n).write_bytes(b);(d/n).chmod(0o600)
  (d/'manifest.json').write_text(json.dumps({'source_sha256':'a'*64,'sha256':{n:hashlib.sha256(b).hexdigest() for n,b in data.items()}}));(d/'manifest.json').chmod(0o600)
  return d,data
 def test_valid_data_only(self):
  d,data=self.fixture();self.assertEqual(p.validate(d,'a'*64,os.geteuid()),data)
 def test_changed_source(self):
  d,_=self.fixture()
  with self.assertRaises(p.Refused):p.validate(d,'b'*64,os.geteuid())
 def test_changed_pdf(self):
  d,_=self.fixture();(d/'document.pdf').write_bytes(b'OTHER')
  with self.assertRaises(p.Refused):p.validate(d,'a'*64,os.geteuid())
 def test_symlink(self):
  d,_=self.fixture();(d/'document.pdf').unlink();(d/'document.pdf').symlink_to(d/'document.html')
  with self.assertRaises(OSError):p.validate(d,'a'*64,os.geteuid())
 def test_unknown_filename(self):
  d,_=self.fixture();fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaises(p.Refused):p.read_file(fd,'../../etc/shadow',os.geteuid(),1000)
  finally:os.close(fd)
 def test_atomic_modes_and_exclusive(self):
  d,_=self.fixture();fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
  try:
   p.atomic(fd,'result',b'one',0o600,replace=False)
   with self.assertRaises(FileExistsError):p.atomic(fd,'result',b'two',replace=False)
   self.assertEqual((d/'result').read_bytes(),b'one');self.assertEqual((d/'result').stat().st_mode&0o777,0o600)
  finally:os.close(fd)
 def test_atomic_replacement(self):
  d,_=self.fixture();fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
  try:p.atomic(fd,'test',b'one');p.atomic(fd,'test',b'two');self.assertEqual((d/'test').read_bytes(),b'two')
  finally:os.close(fd)
 def test_directory_permissions(self):
  d,_=self.fixture();d.chmod(0o777)
  with self.assertRaises(p.Refused):p.validate(d,'a'*64,os.geteuid())
 def test_foreign_owner(self):
  d,_=self.fixture()
  with self.assertRaises(p.Refused):p.validate(d,'a'*64,os.geteuid()+1)
 def test_worker_symlink(self):
  d,_=self.fixture();(d/'link').symlink_to(d/'document.pdf')
  with self.assertRaises(OSError):w.read_regular(d/'link',os.geteuid(),1000)
class PublisherRollbackTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.d=Path(self.t.name);self.fd=os.open(self.d,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,self.fd)
  self.names={'System_Dokumentation.html':b'new html','System_Dokumentation_latest.pdf':b'new pdf'}
  self.before={n:b'old '+n.encode() for n in self.names}
  for n,b in self.before.items():p.atomic(self.fd,n,b)
  self.ids={n:p.identity(self.fd,n) for n in self.names}
 def test_success(self):
  p.publish_pair(self.fd,self.names,self.before,self.ids)
  for n,b in self.names.items():self.assertEqual((self.d/n).read_bytes(),b)
 def test_failure_before_second_write_restores_first(self):
  def writer(fd,n,b):
   if n.endswith('.pdf'):raise OSError('fixture')
   p.atomic(fd,n,b)
  with self.assertRaises(OSError):p.publish_pair(self.fd,self.names,self.before,self.ids,writer)
  for n,b in self.before.items():self.assertEqual((self.d/n).read_bytes(),b)
 def test_failure_after_replace_restores_both(self):
  def writer(fd,n,b):
   p.atomic(fd,n,b)
   if n.endswith('.pdf'):raise OSError('directory fsync fixture')
  with self.assertRaises(OSError):p.publish_pair(self.fd,self.names,self.before,self.ids,writer)
  for n,b in self.before.items():self.assertEqual((self.d/n).read_bytes(),b)
 def test_refused_second_does_not_skip_first_rollback(self):
  def writer(fd,n,b):
   p.atomic(fd,n,b)
   if n.endswith('.html'):p.atomic(fd,'System_Dokumentation_latest.pdf',b'foreign')
  with self.assertRaisesRegex(p.Refused,'DESTINATION_DRIFT'):p.publish_pair(self.fd,self.names,self.before,self.ids,writer)
  self.assertEqual((self.d/'System_Dokumentation.html').read_bytes(),self.before['System_Dokumentation.html'])
  self.assertEqual((self.d/'System_Dokumentation_latest.pdf').read_bytes(),b'foreign')
 def test_foreign_first_write_not_overwritten_by_rollback(self):
  def writer(fd,n,b):
   if n.endswith('.pdf'):
    p.atomic(fd,'System_Dokumentation.html',b'foreign');raise OSError('fixture')
   p.atomic(fd,n,b)
  with self.assertRaisesRegex(p.Refused,'ROLLBACK_CONFLICT'):p.publish_pair(self.fd,self.names,self.before,self.ids,writer)
  self.assertEqual((self.d/'System_Dokumentation.html').read_bytes(),b'foreign')
 def test_prior_absence_restored(self):
  n='System_Dokumentation.html';(self.d/n).unlink();self.before[n]=None;self.ids[n]=None
  def writer(fd,n,b):
   if n.endswith('.pdf'):raise OSError('fixture')
   p.atomic(fd,n,b)
  with self.assertRaises(OSError):p.publish_pair(self.fd,self.names,self.before,self.ids,writer)
  self.assertFalse((self.d/'System_Dokumentation.html').exists())
 def test_interrupt_restores(self):
  def writer(fd,n,b):
   if n.endswith('.pdf'):raise KeyboardInterrupt()
   p.atomic(fd,n,b)
  with self.assertRaises(KeyboardInterrupt):p.publish_pair(self.fd,self.names,self.before,self.ids,writer)
  for n,b in self.before.items():self.assertEqual((self.d/n).read_bytes(),b)
 def test_group_writable_input_refused(self):
  n='System_Dokumentation.html';(self.d/n).chmod(0o664)
  with self.assertRaises(p.Refused):p.read_file(self.fd,n,os.geteuid(),1000)
if __name__=='__main__':unittest.main()
