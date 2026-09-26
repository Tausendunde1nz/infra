import unittest,json,copy,tempfile,pathlib,time,os
from unittest.mock import patch
import tu1nz_policy_watchdog as w
class FakeAPI:
 def __init__(self,current=None):
  self.current=current or {'raw':b'{"grants":[]}', 'json':b'{"grants":[]}','etag':'"one"'};self.writes=[];self.token=None;self.credentials=None;self.uncertain=False
 def snapshot(self):return copy.deepcopy(self.current)
 def validate(self,raw):pass
 def set(self,raw,etag):
  if etag!=self.current['etag']:raise w.SafeError('conflict')
  self.writes.append(raw);self.current={'raw':raw,'json':w.canonical(raw),'etag':'"two"'}
  if self.uncertain:raise w.SafeError('lost response')
class Tests(unittest.TestCase):
 def test_restore(self):
  original=FakeAPI().snapshot();a=FakeAPI({'raw':b'{"grants":[1]}','json':b'{"grants":[1]}','etag':'"x"'})
  self.assertTrue(w.restore(a,original,a.current['json'])['verified']);self.assertEqual(a.writes,[original['raw']])
 def test_real_test_must_write(self):
  a=FakeAPI();o=a.snapshot();w.restore(a,o,o['json'],force=True);self.assertEqual(len(a.writes),1)
 def test_concurrent_policy_not_overwritten(self):
  a=FakeAPI({'raw':b'{"grants":[9]}','json':b'{"grants":[9]}','etag':'"x"'})
  with self.assertRaises(w.SafeError):w.restore(a,FakeAPI().snapshot(),b'{"grants":[1]}')
  self.assertEqual(a.writes,[])
 def test_uncertain_post_reconciled(self):
  a=FakeAPI();a.uncertain=True;self.assertTrue(w.restore(a,a.snapshot(),a.current['json'],force=True)['verified'])
 def test_semantic_equivalence(self):
  a=FakeAPI().snapshot();b=copy.deepcopy(a);b['raw']=b'{ "grants": [] }';self.assertTrue(w.same(a,b))
 def test_guard(self):
  a=w.API({'id':'DUMMY','secret':'DUMMY'})
  with self.assertRaises(w.SafeError):a.set(b'{}',None)
 def test_no_redirect(self):
  with self.assertRaises(w.SafeError):w.NoRedirect().redirect_request(None,None,None,None,None,None)
 def test_validation_200_error_rejected(self):
  a=w.API({'id':'DUMMY','secret':'DUMMY'});a.call=lambda *x,**k:(b'{"message":"test(s) failed"}',{},200)
  with self.assertRaises(w.SafeError):a.validate(b'{}')
 def test_validation_empty_and_object(self):
  a=w.API({'id':'DUMMY','secret':'DUMMY'})
  for body in [b'',b'{}']:
   a.call=lambda *x,**k:(body,{},200);a.validate(b'{}')
 def test_scope_expansion_rejected(self):
  a=w.API({'id':'DUMMY','secret':'DUMMY'});a.wire=lambda *x,**k:(b'{"access_token":"DUMMY","token_type":"Bearer","expires_in":3600,"scope":"all"}',{},200)
  with self.assertRaises(w.SafeError):a.auth()
 def test_marker(self):
  from test_monotonic_observer import fixture
  manifest,activation,observation,report,marker=fixture()
  check=lambda m=marker,mf=manifest,r=report,cur={'json':b'{}'},clock=112_000_000_000:w.valid_completion(m,mf,r,cur,clock,activation,observation)
  self.assertTrue(check())
  for name,value in [('transaction','x'),('candidate_sha256','x'),('report_sha256','x')]:self.assertFalse(check(m=dict(marker,**{name:value})))
  self.assertFalse(check(clock=121_000_000_000));self.assertFalse(check(cur={'json':b'{"x":1}'}))
  for key in w.REQUIRED:
   bad=json.loads(report);bad['checks'][key]=False;r=json.dumps(bad).encode();self.assertFalse(check(m=dict(marker,report_sha256=w.sha(r)),r=r))
  self.assertFalse(check(mf=dict(manifest,stage='accept')))
 def test_private_and_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'file';w.write_new(p,b'ok');self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertEqual(w.read_private(p),b'ok')
   link=pathlib.Path(d)/'link';link.symlink_to(p)
   with self.assertRaises(OSError):w.read_private(link)
   p.chmod(0o644)
   with self.assertRaises(w.SafeError):w.read_private(p)
 def test_watchdog_timeout_real_control_flow(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'txn';a=FakeAPI();w.run_transaction(p,None,5,'selftest',api=a)
   self.assertTrue((p/'ARMED.json').exists());self.assertTrue((p/'ROLLED_BACK.json').exists());self.assertFalse((p/'FAILED.json').exists());self.assertEqual(len(a.writes),1)
 def test_endpoint_restriction(self):
  a=w.API({'id':'DUMMY','secret':'DUMMY'})
  with self.assertRaises(w.SafeError):a.wire('/tailnet/-/keys')
if __name__=='__main__':unittest.main()
