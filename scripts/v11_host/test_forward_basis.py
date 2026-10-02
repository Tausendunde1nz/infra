import copy,hashlib,unittest
import forward_basis as f
class Forward(unittest.TestCase):
 def setUp(self):
  self.old='a'*40;self.new='b'*40;self.raw=b'reviewed delta';blob=hashlib.sha1(b'blob '+str(len(self.raw)).encode()+b'\0'+self.raw).hexdigest()
  self.api={'repository':f.REPO,'ref':f.REF,'commit':self.new,'tree':'c'*40,'merge_base':self.old,'ahead':11,'behind':0,'commit_verified':True,'files':[{'path':'governance/example.md','blob':blob,'status':'modified'}]}
  self.blobs={'governance/example.md':self.raw};self.tests={'governance/example.md':{'passed':True,'sha256':'d'*64}}
  index={'uid':1001,'gid':1001,'mode':0o600,'regular':True,'nlink':1,'sha256':'f'*64}
  self.o={'tracked_match':True,'writer_scan_complete':True,'active_writer':False,'index_before':index,'index_after':dict(index),'head':self.new,'tree':'c'*40}
 def adopt(self):return f.adopt(self.old,self.api,self.blobs,self.o,self.tests)
 def test_forward(self):self.assertEqual(self.adopt()['head'],self.new)
 def test_behind(self):
  self.api['behind']=1
  with self.assertRaises(f.Refused):self.adopt()
 def test_side_branch(self):
  self.api['merge_base']='f'*40
  with self.assertRaises(f.Refused):self.adopt()
 def test_repo_spoof(self):
  self.api['repository']='other/control'
  with self.assertRaises(f.Refused):self.adopt()
 def test_unsigned_head(self):
  self.api['commit_verified']=False
  with self.assertRaises(f.Refused):self.adopt()
 def test_blob_drift(self):
  self.blobs['governance/example.md']+=b'bad'
  with self.assertRaises(f.Refused):self.adopt()
 def test_missing_delta_test(self):
  self.tests={}
  with self.assertRaises(f.Refused):self.adopt()
 def test_failed_delta_test(self):
  self.tests['governance/example.md']['passed']=False
  with self.assertRaises(f.Refused):self.adopt()
 def test_active_writer(self):
  self.o['active_writer']=True
  with self.assertRaises(f.Refused):self.adopt()
 def test_incomplete_writer_scan(self):
  self.o['writer_scan_complete']=False
  with self.assertRaises(f.Refused):self.adopt()
 def test_index_drift(self):
  self.o['index_after']['sha256']='0'*64
  with self.assertRaises(f.Refused):self.adopt()
 def test_deletion_scope(self):
  self.api['files'][0]['status']='removed';self.blobs['governance/example.md']=None
  with self.assertRaises(f.Refused):self.adopt()
 def frozen(self):
  basis=self.adopt();deployment={'path':f.TARGET,'head':self.new,'tree':'c'*40,'dedicated_gitdir':True,'alternates':False,'tracked_match':True,'index_verified':True,'active_writer':False,'payloads_verified':True}
  return f.freeze(basis,deployment,{'control/main':self.new,'infra/control-main':'e'*40},1,'12345678-1234-1234-1234-123456789abc','tu1nz-privileged-v11-'+'a'*32)
 def test_freeze(self):
  x=self.frozen();self.assertTrue(f.validate_frozen(x,x['payload']['refs'],x['payload']['boot'],2))
 def test_changed_authoring_ref_invalidates_only_manifest(self):
  basis=self.adopt();saved=copy.deepcopy(basis);x=self.frozen();refs=dict(x['payload']['refs']);refs['infra/control-main']='0'*40
  with self.assertRaises(f.Refused):f.validate_frozen(x,refs,x['payload']['boot'],2)
  self.assertEqual(basis,saved)
 def test_expired_freeze(self):
  x=self.frozen()
  with self.assertRaises(f.Refused):f.validate_frozen(x,x['payload']['refs'],x['payload']['boot'],300_000_000_002)
 def test_reboot_invalidates(self):
  x=self.frozen()
  with self.assertRaises(f.Refused):f.validate_frozen(x,x['payload']['refs'],'different',2)
 def test_tamper(self):
  x=self.frozen();x['payload']['head']='0'*40
  with self.assertRaises(f.Refused):f.validate_frozen(x,x['payload']['refs'],x['payload']['boot'],2)
if __name__=='__main__':unittest.main()
