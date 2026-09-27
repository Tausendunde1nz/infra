import tempfile
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from tu1nz_campaign_journal_v7 import *

class Fake:
    def __init__(self):self.state={n:{'enabled':True,'data':'exact','endpoint':['ip','alias']} for n in STEPS};self.fail=None
    def snapshot(self,n):return json.loads(json.dumps(self.state[n]))
    def apply(self,n):
        self.state[n]['data']='changed'
        if self.fail==n:raise RuntimeError('injected')
    def validate(self,n,b,a):return True
    def restore(self,n,b,quarantine):self.state[n]=dict(b,**({'enabled':False} if quarantine else {}))
    def verify_restore(self,n,b,quarantine):return self.state[n]==dict(b,**({'enabled':False} if quarantine else {}))
    def final_validation(self):return True

class JournalTests(unittest.TestCase):
    def setUp(self):
        if not hasattr(os,'listxattr'):
            shim=patch.object(os,'listxattr',return_value=[],create=True);shim.start();self.addCleanup(shim.stop)
        self.tmp=tempfile.TemporaryDirectory();os.chmod(self.tmp.name,0o700);self.j=Journal(self.tmp.name)
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def test_each_phase_failure(self):
        for failed in STEPS:
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as p:
                os.chmod(p,0o700);j=Journal(p);a=Fake();a.fail=failed
                try:
                    for n in STEPS:
                        if n==failed:
                            before=a.snapshot(n)
                            with self.assertRaises(RuntimeError):j.step(n,a,before)
                            self.assertEqual(j.read()['status'],'STOPPED')
                            self.assertEqual(a.state[n]['data'],'exact')
                            self.assertEqual(a.state[n]['enabled'],n not in SECURITY_TRIGGERS)
                            break
                        j.step(n,a,a.snapshot(n))
                finally:j.close()
    def test_durable_intent_recovery(self):
        a=Fake();b=a.snapshot('preflight');self.j.write(dict(version=7,status='INTENT',steps=[dict(name='preflight',status='INTENT',before=b)]))
        a.apply('preflight');self.j.close();self.j=Journal(self.tmp.name)
        self.j.rollback_current(a);self.assertEqual(a.state['preflight'],b)
    def test_lock_rejects_parallel(self):
        with self.assertRaises(BlockingIOError):Journal(self.tmp.name)
    def test_drift(self):
        with self.assertRaises(Closed):self.j.step('preflight',Fake(),{})
        self.assertEqual(self.j.read()['status'],'NEW')
    def test_complete(self):
        a=Fake()
        for n in STEPS:self.j.step(n,a,a.snapshot(n))
        self.j.finish(a);self.assertEqual(self.j.read()['status'],'COMPLETE')
    def test_no_early_completion(self):
        with self.assertRaises(Closed):self.j.finish(Fake())
    def test_checksum(self):
        self.j.write(dict(version=7,status='NEW',steps=[]));p=Path(self.tmp.name)/'checkpoint.json';x=json.loads(p.read_text());x['payload']['status']='COMPLETE';p.write_text(json.dumps(x))
        with self.assertRaises(Closed):self.j.read()
    def test_symlink(self):
        (Path(self.tmp.name)/'checkpoint.json').symlink_to('/dev/null')
        with self.assertRaises(OSError):self.j.read()
        with self.assertRaises(Closed):self.j.write({})
    def test_permissions(self):
        self.j.write({});self.assertEqual((Path(self.tmp.name)/'checkpoint.json').stat().st_mode&0o777,0o600)
    def test_rollback_failure_persists(self):
        a=Fake();self.j.step('preflight',a,a.snapshot('preflight'))
        a.verify_restore=lambda *args,**kwargs:False
        with self.assertRaises(Closed):self.j.rollback_current(a)
        self.assertEqual(self.j.read()['status'],'ROLLBACK_FAILED')
