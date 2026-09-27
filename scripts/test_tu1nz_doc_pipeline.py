#!/usr/bin/python3
import importlib.util,pathlib,tempfile,subprocess,json,hashlib,shutil,os,unittest
spec=importlib.util.spec_from_file_location('pipeline',pathlib.Path(__file__).with_name('tu1nz_doc_pipeline.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
FIXTURE=pathlib.Path(os.environ['TU1NZ_PDF_TEST_FIXTURE'])
BASE=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22/pipeline-offline-tests')
def git(repo,*a):return subprocess.check_output(['git','-C',str(repo),*a],stderr=subprocess.PIPE).decode().strip()
class PipelineTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=BASE,prefix='case-');self.root=pathlib.Path(self.tmp.name)
  self.stage=self.root/'stage';shutil.copytree(FIXTURE,self.stage)
  self.m=json.loads((self.stage/'manifest.json').read_text());self.sha=self.m['pdf_sha256']
 def tearDown(self):self.tmp.cleanup()
 def repository(self):
  remote=self.root/'remote.git';subprocess.run(['git','init','--bare','-q',str(remote)],check=True)
  repo=self.root/'repo';repo.mkdir();git(repo,'init','-q','-b','main');git(repo,'config','user.email','fixture@example.invalid');git(repo,'config','user.name','Fixture')
  (repo/'README').write_text('fixture\n');git(repo,'add','README');git(repo,'commit','-qm','fixture');git(repo,'remote','add','origin',str(remote));git(repo,'push','-qu','origin','main')
  return repo,str(remote)
 def test_valid_pdf(self):self.assertEqual(p.validate(self.stage)[0]['pdf_sha256'],self.sha)
 def test_invalid_pdf(self):
  f=self.stage/self.m['filename'];f.write_bytes(b'not a PDF');self.m['pdf_sha256']=p.digest(f);(self.stage/'manifest.json').write_text(json.dumps(self.m))
  with self.assertRaisesRegex(ValueError,'signature'):p.validate(self.stage)
 def test_empty_and_secret(self):
  for value in ['', 'token=SIMULATED_NOT_REAL_SECRET']:
   self.m['data']['server']=value;(self.stage/'manifest.json').write_text(json.dumps(self.m))
   with self.assertRaises(ValueError):p.publish(self.stage,self.sha)
 def test_dirty_files_not_staged(self):
  repo,remote=self.repository()
  for path in ['untracked','README']:
   f=repo/path;old=f.read_bytes() if f.exists() else None;f.write_text('foreign work')
   with self.assertRaisesRegex(ValueError,'Dirty'):p.publish(self.stage,self.sha,repo,remote)
   self.assertEqual(git(repo,'diff','--cached','--name-only'),'')
   if old is None:f.unlink()
   else:f.write_bytes(old)
 def test_remote_missing_or_wrong(self):
  repo,remote=self.repository()
  with self.assertRaisesRegex(ValueError,'remote'):p.publish(self.stage,self.sha,repo,'incorrect')
  git(repo,'remote','remove','origin')
  with self.assertRaises(subprocess.CalledProcessError):p.publish(self.stage,self.sha,repo,remote)
 def test_push_and_repeat(self):
  repo,remote=self.repository();result=p.publish(self.stage,self.sha,repo,remote)
  self.assertTrue(result.startswith('PUSHED '));head=git(repo,'rev-parse','HEAD')
  self.assertEqual(p.publish(self.stage,self.sha,repo,remote),'UNCHANGED');self.assertEqual(git(repo,'rev-parse','HEAD'),head)
 def test_push_failure(self):
  repo,remote=self.repository();hook=pathlib.Path(remote)/'hooks/pre-receive';hook.write_text('#!/bin/sh\nexit 1\n');hook.chmod(0o700)
  old=git(repo,'ls-remote','origin','refs/heads/main')
  with self.assertRaises(subprocess.CalledProcessError):p.publish(self.stage,self.sha,repo,remote)
  self.assertEqual(git(repo,'ls-remote','origin','refs/heads/main'),old)
  self.assertNotEqual(git(repo,'rev-parse','HEAD'),old.split()[0])
 def test_reviewed_hash_required(self):
  with self.assertRaisesRegex(ValueError,'reviewed'):p.publish(self.stage,'wrong')
 def test_stage_no_git(self):
  repo,remote=self.repository();head=git(repo,'rev-parse','HEAD');oldrun=p.run
  def guard(*args,**kw):
   if args[0]=='git':raise AssertionError('Stage called Git')
   return oldrun(*args,**kw)
  p.run=guard
  try:folder=p.stage(self.root/'staged',self.m['data']);p.validate(folder)
  finally:p.run=oldrun
  self.assertEqual(git(repo,'rev-parse','HEAD'),head);self.assertEqual(git(repo,'status','--porcelain'),'')
  self.assertEqual(git(repo,'ls-remote','origin','refs/heads/main').split()[0],head)
 def test_transaction_restore_exact(self):
  spec=importlib.util.spec_from_file_location('transaction',pathlib.Path(__file__).with_name('tu1nz_doc_pipeline_transaction.py'))
  tx=importlib.util.module_from_spec(spec);spec.loader.exec_module(tx)
  out=self.root/'transaction';out.mkdir()
  original=b'original configuration\n';candidate=b'new configuration\n'
  existing=self.root/'existing';existing.write_bytes(candidate)
  added=self.root/'added';added.write_bytes(candidate)
  (out/'original').write_bytes(original)
  entries=[{'path':str(existing),'changed':True,'existed':True,'candidate_sha':tx.sha(candidate),'sha':tx.sha(original),'backup':'original','mode':0o640,'uid':os.getuid(),'gid':os.getgid()}, {'path':str(added),'changed':True,'existed':False,'candidate_sha':tx.sha(candidate)}]
  (out/'manifest.json').write_text(json.dumps(entries))
  calls=[]
  def fake_run(*args):
   calls.append(args)
   if args==('systemctl','daemon-reload'):return b''
   if args[0:3]==('systemctl','show','tu1nz-doc.service'):return b'/opt/tu1nz_repos/docs_repo\n'
   raise AssertionError('Unexpected privileged action')
  tx.run=fake_run;tx.restore(out)
  self.assertEqual(existing.read_bytes(),original);self.assertEqual(existing.stat().st_mode&0o777,0o640)
  self.assertFalse(added.exists());self.assertTrue((out/'ROLLED_BACK.json').exists())

if __name__=='__main__':unittest.main(verbosity=2)
