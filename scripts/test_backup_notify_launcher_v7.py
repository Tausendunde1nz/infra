import pathlib
import shlex
import unittest
from unittest.mock import patch
import tu1nz_backup_notify_launcher_v7 as l

class LauncherTests(unittest.TestCase):
    def test_hash_bound(self):
        b=pathlib.Path(__file__).with_name('tu1nz_backup_notify_semantic_v7.py').read_bytes()
        cmd=l.argv(b)
        self.assertEqual(cmd[-2],'chatops@100.121.130.51')
        remote=shlex.split(cmd[-1]);self.assertEqual(remote[:4],['sudo','/usr/bin/python3','-I','-c'])
        self.assertIn(l.READER_SHA,remote[4]);self.assertNotIn('shell=True',remote[4])
    def test_modified_reader_denied(self):
        with self.assertRaises(ValueError):l.remote_command(b'print("wrong")')
    def test_no_argument_expansion(self):
        with patch.object(l.sys,'argv',['launcher','extra']):self.assertEqual(l.main(),77)
    def test_readonly_reader_source(self):
        import ast
        source=pathlib.Path(__file__).with_name('tu1nz_backup_notify_semantic_v7.py').read_text()
        tree=ast.parse(source)
        imports=[n.names[0].name for n in ast.walk(tree) if isinstance(n,ast.Import)]
        self.assertNotIn('subprocess',imports)
        self.assertNotIn('O_WRONLY',source);self.assertNotIn('O_CREAT',source)
