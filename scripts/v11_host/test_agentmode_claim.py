import copy,json,os,tempfile,unittest
from pathlib import Path
from unittest import mock
import agentmode_claim as a

class ClaimTests(unittest.TestCase):
 def setUp(self):
  self.boot='12345678-1234-1234-1234-123456789abc';self.inv='b'*32;self.pid=345
  self.files={a.PROGRAM:b'fixed-prologue',a.OBSERVER:b'fixed-observer',a.UNIT:b'fixed-unit'}
  self.intent={'schema':1,'transaction':'tu1nz-privileged-v11-'+'a'*32,'boot':self.boot,'deadline_ns':10**12,'source_sha256':a.sha(self.files[a.OBSERVER]),'program_sha256':a.sha(self.files[a.PROGRAM]),'base_unit_sha256':a.sha(self.files[a.UNIT]),'dropin_template':'fixed @INTENT_SHA@','head':a.HEAD,'status':'START_INTENT'}
  self.pin=a.sha(a.encode(self.intent));self.files[a.DROPIN]=self.intent['dropin_template'].replace('@INTENT_SHA@',self.pin).encode()
  self.unit={'Id':'tu1nz_agentmode.service','InvocationID':self.inv,'ControlPID':str(self.pid),'NeedDaemonReload':'no','DropInPaths':a.DROPIN,'User':'chatops','Group':'chatops'}
 def check(self,**kw):
  args=dict(intent=self.intent,pin=self.pin,boot=self.boot,now=1,invocation=self.inv,pid=self.pid,cgroup='0::/system.slice/tu1nz_agentmode.service',unit=self.unit,files=self.files);args.update(kw);return a.validate(**args)
 def test_bound_claim(self):self.assertEqual(self.check()['status'],'START_CLAIMED')
 def test_boot_change(self):
  with self.assertRaises(a.Refused):self.check(boot='different')
 def test_deadline(self):
  with self.assertRaises(a.Refused):self.check(now=10**12-300_000_000_000)
 def test_unknown_keys(self):
  self.intent['other']=True
  with self.assertRaises(a.Refused):self.check()
 def test_foreign_control_pid(self):
  self.unit['ControlPID']='123'
  with self.assertRaises(a.Refused):self.check()
 def test_foreign_invocation(self):
  self.unit['InvocationID']='c'*32
  with self.assertRaises(a.Refused):self.check()
 def test_wrong_cgroup(self):
  with self.assertRaises(a.Refused):self.check(cgroup='0::/user.slice/session.scope')
 def test_unit_not_reloaded(self):
  self.unit['NeedDaemonReload']='yes'
  with self.assertRaises(a.Refused):self.check()
 def test_extra_dropin(self):
  self.unit['DropInPaths']+=' /etc/foreign.conf'
  with self.assertRaises(a.Refused):self.check()
 def test_unprivileged_entrypoint(self):self.assertEqual(a.main(),78)
 def test_duplicate_json(self):
  with self.assertRaises(a.Refused):json.loads('{"x":1,"x":2}',object_pairs_hook=a.pairs)
 def test_claim_atomic_no_overwrite(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-claim-test-',dir='/tmp') as d:
   fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
   try:
    value=self.check();a.publish(fd,value);p=Path(d)/'claim.json';old=p.read_bytes();self.assertEqual(p.stat().st_mode&0o777,0o400);self.assertEqual(p.stat().st_nlink,1)
    with self.assertRaises(FileExistsError):a.publish(fd,{**value,'invocation':'d'*32})
    self.assertEqual(p.read_bytes(),old);self.assertEqual([x.name for x in Path(d).iterdir()],['claim.json'])
   finally:os.close(fd)
 def test_existing_symlink_no_overwrite(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-claim-test-',dir='/tmp') as d:
   p=Path(d)/'claim.json';p.symlink_to('/etc/passwd');fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
   try:
    with self.assertRaises(FileExistsError):a.publish(fd,self.check())
    self.assertTrue(p.is_symlink())
   finally:os.close(fd)
 def test_fsync_failure_prevents_main_admission(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-claim-test-',dir='/tmp') as d:
   fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
   try:
    with mock.patch.object(a.os,'fsync',side_effect=OSError('injected')):
     with self.assertRaises(OSError):a.publish(fd,self.check())
    self.assertFalse((Path(d)/'claim.json').exists())
   finally:os.close(fd)
for path in (a.PROGRAM,a.OBSERVER,a.UNIT,a.DROPIN):
 def test(self,path=path):
  self.files[path]+=b'changed'
  with self.assertRaises(a.Refused):self.check()
 setattr(ClaimTests,'test_modified_'+Path(path).name.replace('.','_'),test)
if __name__=='__main__':unittest.main()
