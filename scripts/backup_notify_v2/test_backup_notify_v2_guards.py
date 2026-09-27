from pathlib import Path
import hashlib
import io
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
import reader_runtime as r

class SourceGuardTests(unittest.TestCase):
    def exercise(self,*,expected=None,uid=0,mode=0o100600,drift=False,links=1):
        path=Path('/private-fixture/archive/source.bin');data=b'fixture only'
        fields=dict(st_dev=1,st_ino=2,st_mode=mode,st_uid=uid,st_gid=0,st_nlink=links,st_size=len(data),st_mtime_ns=1,st_ctime_ns=1)
        f=SimpleNamespace(**fields);end=SimpleNamespace(**dict(fields,st_mtime_ns=2)) if drift else f
        directory=SimpleNamespace(st_mode=0o40700,st_uid=0)
        class Stream(io.BytesIO):
            def fileno(self):return 42
        with patch.object(r.Path,'lstat',lambda p:f if p==path else directory),patch.object(r.os,'listxattr',return_value=[],create=True),patch.object(r.os,'open',return_value=42) as op,patch.object(r.os,'fdopen',return_value=Stream(data)),patch.object(r.os,'fstat',side_effect=[f,end]):
            result=r.guarded(path,expected or hashlib.sha256(data).hexdigest());self.assertEqual(op.call_count,1);self.assertEqual(op.call_args.args[0],path);return result
    def test_exact_path(self):self.assertEqual(self.exercise(),b'fixture only')
    def test_source_hash_mismatch(self):
        with self.assertRaises(ValueError):self.exercise(expected='0'*64)
    def test_symlink(self):
        with self.assertRaises(ValueError):self.exercise(mode=0o120600)
    def test_wrong_owner(self):
        with self.assertRaises(ValueError):self.exercise(uid=1001)
    def test_public_source(self):
        with self.assertRaises(ValueError):self.exercise(mode=0o100644)
    def test_hardlink(self):
        with self.assertRaises(ValueError):self.exercise(links=2)
    def test_source_drift(self):
        with self.assertRaises(ValueError):self.exercise(drift=True)
    def test_only_fixed_systemctl_operation(self):
        with patch.object(r,'guarded',return_value=b''),patch.object(r.subprocess,'run') as run:
            run.return_value=SimpleNamespace(returncode=0,stdout=b'User=root\nActiveState=active\n',stderr=b'')
            value=r.unit_state('example.service',{'systemctl_sha256':'a'*64})
            self.assertEqual(value['User'],'root');self.assertEqual(run.call_args.args[0][:2],['/usr/bin/systemctl','show'])
    def test_option_injection(self):
        with self.assertRaises(ValueError):r.unit_state('--now',{})
