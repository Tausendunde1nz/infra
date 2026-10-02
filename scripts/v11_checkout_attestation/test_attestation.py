import hashlib,json,os,pathlib,subprocess,tempfile,unittest
from unittest.mock import patch
import collector as c
import bootstrap,command
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.tmp.name);self.repo=self.base/'repo';self.repo.mkdir();self.out=self.base/'out';self.out.mkdir(mode=0o700)
  self.env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',HOME=str(self.base))
  self.git('init','-q');self.git('config','user.name','Fixture');self.git('config','user.email','fixture@example.invalid')
  (self.repo/'file').write_bytes(b'fixture\n');self.git('add','file');self.git('commit','-qm','fixture')
  self.commit=self.git('rev-parse','HEAD').strip();self.tree=self.git('rev-parse','HEAD^{tree}').strip();self.git('checkout','--detach','-q');self.git('remote','add','origin',c.ORIGINS[0])
 def tearDown(self):self.tmp.cleanup()
 def git(self,*a):return subprocess.check_output(['/usr/bin/git',*a],cwd=self.repo,env=self.env,stderr=subprocess.DEVNULL,text=True)
 def runcheck(self,scan=lambda root:{'processes':[],'incomplete':False}):return c.attest(self.repo,self.out,self.commit,self.tree,self.commit,processes=scan)
 def test_clean_content_does_not_prove_contract(self):
  r=self.runcheck();self.assertEqual(r['status'],'TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN');self.assertFalse(r['proof']['drift']);self.assertTrue(r['expected_commit_content_verified'])
 def test_worktree_drift(self):
  (self.repo/'file').write_text('changed');self.assertEqual(self.runcheck()['status'],'LOCAL_CHECKOUT_DRIFT')
 def test_staged_drift(self):
  (self.repo/'file').write_text('changed');self.git('add','file');r=self.runcheck();self.assertTrue(any(x['reason']=='INDEX_TREE_MISMATCH' for x in r['proof']['drift']))
 def test_untracked_even_ignored(self):
  (self.repo/'.git/info/exclude').write_text('private\n');(self.repo/'private').write_text('synthetic-secret');r=self.runcheck();self.assertEqual(r['untracked'],['private']);self.assertNotIn('synthetic-secret',json.dumps(r))
 def test_different_origin_requires_contract_review(self):
  self.git('remote','set-url','origin','git@github.com-infra:Tausendunde1nz/infra.git');r=self.runcheck();self.assertEqual(r['status'],'TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN');self.assertFalse(r['remote']['origin_matches_reference_repository'])
 def test_origin_secret_redacted(self):
  self.git('remote','set-url','origin','https://synthetic-secret@example.invalid/repo');self.assertNotIn('synthetic-secret',json.dumps(self.runcheck()))
 def test_lock(self):
  (self.repo/'.git/index.lock').write_bytes(b'');self.assertEqual(self.runcheck()['status'],'ACTIVE_WRITER_OR_TRANSACTION')
 def test_writer(self):self.assertEqual(self.runcheck(lambda root:{'processes':[{'pid':99999}],'incomplete':False})['status'],'ACTIVE_WRITER_OR_TRANSACTION')
 def test_incomplete_process_view(self):self.assertEqual(self.runcheck(lambda root:{'processes':[],'incomplete':True})['status'],'TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN')
 def test_index_unchanged(self):
  p=self.repo/'.git/index';b=p.read_bytes();s=c.identity(p.stat());self.runcheck();self.assertEqual(b,p.read_bytes());self.assertEqual(s,c.identity(p.stat()))
 def test_symbolic_branch_rejected(self):
  self.git('checkout','-qb','fixture');self.assertEqual(self.runcheck()['status'],'LOCAL_CHECKOUT_DRIFT')
 def test_index_symlink(self):
  p=self.repo/'.git/index';p.rename(self.base/'index');p.symlink_to(self.base/'index')
  with self.assertRaises(c.Refused):self.runcheck()
 def test_index_hardlink(self):
  os.link(self.repo/'.git/index',self.base/'index')
  with self.assertRaises(c.Refused):self.runcheck()
 def test_worktree_symlink_drift(self):
  p=self.repo/'file';p.unlink();p.symlink_to('/etc/passwd');self.assertEqual(self.runcheck()['status'],'LOCAL_CHECKOUT_DRIFT')
 def test_alternates_refused(self):
  (self.repo/'.git/objects/info/alternates').write_text('/elsewhere')
  with self.assertRaises(c.Refused):self.runcheck()
 def test_untrusted_hooks_filters_never_executed(self):
  marker=self.base/'executed';bad=self.base/'bad';bad.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');bad.chmod(0o755)
  self.git('config','core.fsmonitor',str(bad));self.git('config','diff.test.textconv',str(bad));self.git('config','core.hooksPath',str(self.base));self.git('config','filter.test.clean',str(bad));r=self.runcheck()
  self.assertFalse(marker.exists());self.assertFalse(r['remote']['source_config_executed']);self.assertEqual(len(r['remote']['external_features']),4)
 def test_include_not_followed(self):
  inc=self.base/'inc';inc.write_text('[remote "origin"]\nurl=https://synthetic-secret@invalid\n');self.git('config','include.path',str(inc));r=self.runcheck();self.assertTrue(r['remote']['origin_matches_reference_repository']);self.assertNotIn('synthetic-secret',json.dumps(r))
 def test_object_hash_rejects_forged_response(self):
  g=c.SafeGit(self.repo,self.out,(self.repo/'.git/index').read_bytes(),(self.repo/'.git/HEAD').read_bytes())
  with patch.object(g,'run',return_value=(0,b'forged')):
   with self.assertRaises(c.Refused):g.object('commit',self.commit)
 def test_mutating_git_verb_forbidden(self):
  g=c.SafeGit(self.repo,self.out,(self.repo/'.git/index').read_bytes(),(self.repo/'.git/HEAD').read_bytes())
  for verb in ['fetch','checkout','reset','clean','update-index','maintenance']:
   with self.assertRaises(c.Refused):g.run([verb])
 def test_concurrent_worktree_change(self):
  calls=[0]
  def scan(root):
   calls[0]+=1
   if calls[0]==2:(root/'file').write_text('late change')
   return {'processes':[],'incomplete':False}
  self.assertTrue(any(x['reason']=='CONCURRENT_WORKTREE_CHANGE' for x in self.runcheck(scan)['proof']['drift']))
 def test_classification_requires_contract_and_protection(self):
  p=dict(writers=[],locks=[],drift=[],complete=True,root_controlled=True,contract_confirmed=True);self.assertEqual(c.classify(p),'TRUSTED_CLEAN_ROOT_CONTROLLED_CHECKOUT')
  for k in ['complete','root_controlled','contract_confirmed']:
   q=dict(p);q[k]=False;self.assertEqual(c.classify(q),'TRUSTED_COMMIT_BUT_LOCAL_STATE_UNPROVEN')
 def test_bootstrap_copied_bytes_bound(self):
  src=self.base/'source';src.write_bytes(b'fixture');os.chmod(self.out,0o700)
  target=bootstrap.copy_verified(src,self.out,c.sha(b'fixture'),os.getuid());self.assertEqual(pathlib.Path(target).read_bytes(),b'fixture');self.assertEqual(pathlib.Path(target).stat().st_mode&0o777,0o600)
 def test_bootstrap_hash_refused(self):
  src=self.base/'source';src.write_bytes(b'fixture')
  with self.assertRaises(bootstrap.Refused):bootstrap.copy_verified(src,self.out,'a'*64,os.getuid())
 def test_bootstrap_link_refused(self):
  src=self.base/'source';src.symlink_to(self.repo/'file')
  with self.assertRaises(OSError):bootstrap.copy_verified(src,self.out,'a'*64,os.getuid())
 def test_command_binding(self):
  with self.assertRaises(ValueError):command.build(b'wrong','a'*64,'b'*64)
 def test_publication_no_overwrite(self):
  c.publish(self.out,'report.json',{'safe':True})
  with self.assertRaises(FileExistsError):c.publish(self.out,'report.json',{'safe':False})
  self.assertTrue(json.loads((self.out/'report.json').read_bytes())['safe'])
class AdditionalTests(Tests):
 # Only extra cases; inherited fixture setup, not duplicate inherited test execution.
 def test_parent_symlink_read_refused(self):
  alias=self.base/'alias';alias.symlink_to(self.repo,target_is_directory=True)
  with self.assertRaises(OSError):c.read_stable(alias/'file')
 def test_file_size_refused(self):
  with self.assertRaises(c.Refused):c.read_stable(self.repo/'file',2)
 def test_atomic_report_mode(self):
  c.publish(self.out,'safe.json',{'safe':True});self.assertEqual((self.out/'safe.json').stat().st_mode&0o777,0o600)
 def test_bootstrap_wrong_source_owner(self):
  src=self.base/'source';src.write_bytes(b'fixture')
  with self.assertRaises(bootstrap.Refused):bootstrap.copy_verified(src,self.out,c.sha(b'fixture'),os.getuid()+1)
 def test_bootstrap_directory_acl_refused(self):
  with patch.object(bootstrap.os,'listxattr',return_value=['system.posix_acl_access']):
   with self.assertRaises(bootstrap.Refused):bootstrap.trusted_dir(self.out,os.getuid())
 def test_bootstrap_content_race_refused(self):
  src=self.base/'source';src.write_bytes(b'fixture');original=bootstrap.os.fstat;calls=[0]
  def change(fd):
   st=original(fd)
   if st.st_ino==src.stat().st_ino:
    calls[0]+=1
    if calls[0]==3:src.write_bytes(b'changed')
   return original(fd)
  with patch.object(bootstrap.os,'fstat',side_effect=change):
   with self.assertRaises(bootstrap.Refused):bootstrap.copy_verified(src,self.out,c.sha(b'fixture'),os.getuid())
 def test_git_timeout_preserves_original_index(self):
  original=(self.repo/'.git/index').read_bytes();g=c.SafeGit(self.repo,self.out,original,(self.repo/'.git/HEAD').read_bytes())
  with patch.object(c.subprocess,'run',side_effect=subprocess.TimeoutExpired('git',30)):
   with self.assertRaises(subprocess.TimeoutExpired):g.run(['ls-files','--stage','-z'])
  self.assertEqual((self.repo/'.git/index').read_bytes(),original)
 def test_metadata_tree_no_silent_permission_skip(self):
  with self.assertRaises(c.Refused):c.walk_error(PermissionError('synthetic-secret'))
 def test_tracked_symlink_literal_hash(self):
  (self.repo/'link').symlink_to('file');self.git('add','link');self.git('commit','-qm','link');self.commit=self.git('rev-parse','HEAD').strip();self.tree=self.git('rev-parse','HEAD^{tree}').strip();r=self.runcheck();self.assertFalse(r['proof']['drift'])
# Keep the additional fixture subclass from repeating the original 26 tests.
for _name in list(Tests.__dict__):
 if _name.startswith('test_') and _name not in AdditionalTests.__dict__:setattr(AdditionalTests,_name,None)
if __name__=='__main__':unittest.main()
