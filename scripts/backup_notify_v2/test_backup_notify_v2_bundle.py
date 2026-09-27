from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
import build_reader_v2 as build
import tu1nz_backup_notify_launcher_v2 as launcher

class BundleTests(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(build.build(),(BASE/'tu1nz_backup_notify_reader_v2.py').read_bytes())
    def test_hash_binding(self):
        b=(BASE/'tu1nz_backup_notify_reader_v2.py').read_bytes()
        self.assertEqual(hashlib.sha256(b).hexdigest(),launcher.READER_SHA)
        command=launcher.remote_command(b)
        self.assertIn(launcher.READER_SHA,command);self.assertIn('sudo',command)
        self.assertLess(len(command),120000)
    def test_changed_reader(self):
        with self.assertRaises(ValueError):launcher.remote_command(b'wrong')
    def test_vendor_manifest(self):
        m=json.loads((BASE/'PARSER_MANIFEST.json').read_text())
        for n,h in m['files'].items():self.assertEqual(hashlib.sha256((BASE/n).read_bytes()).hexdigest(),h)
    def test_no_env_candidate(self):
        b=json.loads((BASE/'CALLER_BINDINGS.json').read_text())
        self.assertEqual(b['source_sha256'],'878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311')
        self.assertTrue(all('/.env' not in row['path'] and not row['path'].endswith('.env') for row in b['callers']))
    def test_memory_bundle_fixture_linux(self):
        if not hasattr(os,'memfd_create'):
            # This is an explicit platform rejection, not simulated proof of Linux loading.
            self.assertEqual(sys.platform,'darwin');return
        code="""import importlib.util,os
spec=importlib.util.spec_from_file_location('fixture',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fd,p,e,r,b=m.load_bundle()
assert e.analyse(b'printf fixture\\n',p)['status']=='PARSED_COMPLETE'
os.close(fd)
""".replace('PATH',repr(str(BASE/'tu1nz_backup_notify_reader_v2.py')))
        r=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr.decode());self.assertFalse(r.stdout)
