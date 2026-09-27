import unittest
import sys
import tu1nz_codex_broker_v7 as b

class BrokerTests(unittest.TestCase):
    def test_only_fixed_ops(self):
        for args in ([],['shell'],['status','extra'],['docker','run'],['/etc/shadow']):
            with self.assertRaises(ValueError):b.parse(args)
        for op in b.OPS:self.assertEqual(b.parse([op]),op)
    def test_bounded_success(self):self.assertEqual(b.run_bounded([sys.executable,'-I','-c','print("ok")']),b'ok\n')
    def test_bounded_stderr(self):
        with self.assertRaises(ValueError):b.run_bounded([sys.executable,'-I','-c','import sys;sys.stderr.write("secret")'])
    def test_bounded_size(self):
        with self.assertRaises(ValueError):b.run_bounded([sys.executable,'-I','-c','print("x"*10000)'],limit=100)
    def test_bounded_timeout(self):
        with self.assertRaises(ValueError):b.run_bounded([sys.executable,'-I','-c','import time;time.sleep(5)'],timeout=0.05)
    def test_bounded_rc(self):
        with self.assertRaises(ValueError):b.run_bounded([sys.executable,'-I','-c','raise SystemExit(2)'])
    def test_no_wildcards(self):
        text=b.sudoers();self.assertNotIn('*',text);self.assertNotIn('NOPASSWD: ALL',text)
    def test_env_not_returned(self):
        import json
        rows=[dict(Name='/'+n,State=dict(Status='running'),RestartCount=0,Config=dict(Env=['TOKEN=SECRET'])) for n in b.CONTAINERS]
        self.assertNotIn('SECRET',json.dumps(b.sanitize('containers',json.dumps(rows).encode())))
