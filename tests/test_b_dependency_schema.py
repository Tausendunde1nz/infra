"""Public synthetic recipe tests; no private Application SQL or Host data."""
from contextlib import redirect_stdout, nullcontext
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('dependency_recipe', Path(__file__).resolve().parents[1] /
                                             'scripts/tu1nz_b_dependency_schema.py')
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)


class Recipe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='b-recipe-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root/'migrations').mkdir()
        self.raw = b'-- synthetic line 1\n-- synthetic line 2\nSELECT 1;\n'
        (self.root/'migrations/synthetic.sql').write_bytes(self.raw)
        self.sources = {'synthetic.sql': d.b.sha(self.raw)}

    def test_exact_bytes_and_selected_ranges(self):
        with patch.object(d, 'SOURCES', self.sources), patch.object(d, 'RANGES', (('synt',3,3),)):
            sql,receipt=d.recipe(self.root)
        self.assertEqual(sql,b'BEGIN;\nSELECT 1;\n\nCOMMIT;\n')
        self.assertEqual(receipt['sql_sha256'],d.b.sha(sql))
        self.assertFalse(receipt['host_admission'])
        self.assertFalse(receipt['s11_activation'])

    def test_missing_changed_or_linked_source_fails_closed(self):
        for mode in ('missing','changed','symlink'):
            path=self.root/'migrations/synthetic.sql'
            if path.exists() or path.is_symlink():path.unlink()  # Own temporary synthetic fixture only.
            if mode=='changed':path.write_bytes(b'SELECT 2;')
            if mode=='symlink':path.symlink_to(self.root/'not-a-source')
            with self.subTest(mode=mode),patch.object(d,'SOURCES',self.sources),self.assertRaises((d.b.Denied,OSError)):
                d.recipe(self.root)

    def test_source_binding_contains_only_the_minimal_dependency_files(self):
        self.assertEqual({n[:4] for n in d.SOURCES},{'0031','0032','0033','0035'})
        self.assertNotIn(('0033',211,319),d.RANGES)  # No transition entrypoint.
        self.assertEqual(set(d.BASE_SOURCES) & set(d.SOURCES),set())

    def test_cli_never_echoes_private_source_on_failure(self):
        output=io.StringIO()
        with redirect_stdout(output):code=d.main(['--source',str(self.root),'--output',str(self.root/'out.sql')])
        self.assertEqual(code,2)
        self.assertNotIn('SELECT',output.getvalue())

    def test_create_only_private_output_and_replay_denial(self):
        self.root.chmod(0o700)
        dest=self.root/'private.sql';out=io.StringIO()
        with patch.object(d,'SOURCES',self.sources),patch.object(d,'RANGES',(('synt',3,3),)), \
                patch.object(d.sys,'platform','linux'), \
                (nullcontext() if hasattr(d.os,'listxattr') else patch.object(d.os,'listxattr',return_value=[],create=True)),redirect_stdout(out):
            self.assertEqual(d.main(['--source',str(self.root),'--output',str(dest)]),0)
            self.assertEqual(d.main(['--source',str(self.root),'--output',str(dest)]),2)
        self.assertEqual(dest.stat().st_mode & 0o777,0o600)
        self.assertNotIn('SELECT',out.getvalue())

    def test_shared_directory_cannot_receive_private_sql(self):
        self.root.chmod(0o755)
        with patch.object(d,'SOURCES',self.sources),patch.object(d,'RANGES',(('synt',3,3),)), \
                patch.object(d.sys,'platform','linux'), \
                (nullcontext() if hasattr(d.os,'listxattr') else patch.object(d.os,'listxattr',return_value=[],create=True)),redirect_stdout(io.StringIO()):
            self.assertEqual(d.main(['--source',str(self.root),'--output',str(self.root/'private.sql')]),2)
        self.assertFalse((self.root/'private.sql').exists())
