import unittest
import shlex
from unittest.mock import patch
import tu1nz_root_trust_v51_launcher as m

class Tests(unittest.TestCase):
    def test_inert_fixed_destination(self):
        with patch('subprocess.call',side_effect=AssertionError('must not execute')):
            r=m.build(b'pass\n','a'*40)
        self.assertIn('chatops@100.121.130.51',r['argv']);self.assertIn('StrictHostKeyChecking=yes',r['argv'])
        self.assertNotIn('shell_line',r)
    def test_bad_commit(self):
        with self.assertRaises(ValueError):m.build(b'pass','bad;command')
    def test_invalid_source(self):
        with self.assertRaises(SyntaxError):m.build(b'invalid python syntax','a'*40)
    def test_remote_and_root_bindings(self):
        r=m.build(b'pass\n','a'*40);remote=shlex.split(r['argv'][-1])[-1]
        calls=[]
        class FakePath:
            def __init__(self,*_):pass
            def __truediv__(self,_):return self
            def read_bytes(self):return b'pass\n'
        with patch('subprocess.check_output',return_value='a'*40),patch('pathlib.Path',FakePath),patch('subprocess.call',side_effect=lambda a:calls.append(a) or 0):
            with self.assertRaises(SystemExit):exec(remote,{})
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][:6],['/usr/bin/sudo','--','/usr/bin/python3','-I','-S','-c'])
        exec(calls[0][-1],{})
    def test_changed_source_never_sudo(self):
        r=m.build(b'pass\n','a'*40);remote=shlex.split(r['argv'][-1])[-1]
        class FakePath:
            def __init__(self,*_):pass
            def __truediv__(self,_):return self
            def read_bytes(self):return b'changed'
        with patch('subprocess.check_output',return_value='a'*40),patch('pathlib.Path',FakePath),patch('subprocess.call') as call:
            with self.assertRaises(AssertionError):exec(remote,{})
        call.assert_not_called()

if __name__=='__main__':unittest.main()
