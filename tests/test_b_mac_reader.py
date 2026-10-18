"""Synthetic admission regressions; no Host, real credentials or Mac dependency."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('b_mac_reader', ROOT/'scripts/tu1nz_b_mac_reader.py')
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)
CATALOG = (ROOT/'manifests/b-data-writer-handoff-r1.json').read_bytes()


class ReaderAdmission(unittest.TestCase):
    def values(self):
        return {'user': reader.ROLE, 'dbname': reader.DATABASE, 'host': '127.0.0.1',
                'port': '5432', 'password': 'SYNTHETIC-not-a-credential'}

    def observation(self):
        return [dict(kind='identity', database=reader.DATABASE, role=reader.ROLE,
                     session_role=reader.ROLE, version='170011', port=5432,
                     address='127.0.0.1', transaction_read_only='on', ssl=True,
                     postmaster_start='2026-08-27T19:59:20.500309+00:00'),
                dict(kind='role', superuser=False, bypass_rls=False, create_role=False,
                     create_db=False, replication=False, schema_usage=True, snapshot_execute=True)] + [
                dict(kind='relation', name=n, exists=True, relation_kind='r', select=True,
                     all_columns_select=True, rls=False, force_rls=False)
                for n in json.loads(CATALOG)['tables']]

    def test_existing_exact_role(self):
        self.assertEqual(reader.validate_dsn(self.values()), 'SYNTHETIC-not-a-credential')

    def test_wrong_identity_no_password_in_error(self):
        for key, value in (('user', 'postgres'), ('dbname', 'other'), ('host', 'example.invalid'), ('port', '9999')):
            with self.subTest(key=key):
                values = self.values(); values[key] = value
                with self.assertRaises(reader.Denied) as caught:
                    reader.validate_dsn(values)
                self.assertNotIn(values['password'], str(caught.exception))

    def test_indirection_and_extra_options_denied(self):
        for key in ('service', 'passfile', 'options', 'hostaddr', 'sslkey', 'target_session_attrs'):
            values = self.values(); values[key] = 'synthetic'
            with self.subTest(key=key), self.assertRaises(reader.Denied):
                reader.validate_dsn(values)

    def test_stronger_original_tls_not_downgraded(self):
        for value in ('verify-full', 'verify-ca'):
            values = self.values(); values['sslmode'] = value
            with self.assertRaises(reader.Denied): reader.validate_dsn(values)

    def test_required_other_auth_denied(self):
        values = self.values(); values['gssencmode'] = 'require'
        with self.assertRaises(reader.Denied): reader.validate_dsn(values)

    def test_password_line_injection_denied(self):
        for value in ('', 'synthetic\nextra', 'synthetic\r', 'synthetic\0'):
            values = self.values(); values['password'] = value
            with self.assertRaises(reader.Denied): reader.validate_dsn(values)
            with self.assertRaises(reader.Denied): reader.passfile_bytes(value)

    def test_passfile_escape(self):
        raw = reader.passfile_bytes('SYNTHETIC:back\\slash')
        self.assertTrue(raw.endswith(b'SYNTHETIC\\:back\\\\slash\n'))
        self.assertEqual(raw.count(b'\n'), 1)

    def test_clean_environment_no_password_or_inheritance(self):
        env = reader.clean_environment(Path('/private/tmp/synthetic/pgpass'), Path('/synthetic'), Path('/private/tmp/synthetic'))
        self.assertNotIn('PGPASSWORD', env)
        self.assertNotIn('HOME', env)
        self.assertFalse(any(k.startswith('DYLD_') for k in env))
        self.assertEqual(env['PGCHANNELBINDING'], 'require')
        self.assertEqual(env['PGSSLMODE'], 'require')
        self.assertIn('default_transaction_read_only=on', env['PGOPTIONS'])

    def test_metadata_is_not_export_or_snapshot_claim(self):
        sql = reader.metadata_sql(CATALOG).decode()
        self.assertIn('REPEATABLE READ READ ONLY', sql)
        self.assertNotIn('SELECT pg_export_snapshot()', sql)
        self.assertNotIn('COPY ', sql)
        self.assertNotIn('pg_authid', sql)
        self.assertEqual(sql.count("('commercial_s11_runtime_control')"), 2)

    def test_catalog_tamper_denied(self):
        with self.assertRaises(reader.Denied): reader.metadata_sql(CATALOG+b' ')

    def test_valid_metadata(self):
        reader.validate_observation(self.observation(), CATALOG)

    def test_source_or_invocation_change_denied(self):
        for key, value in (('database', 'wrong'), ('role', 'postgres'), ('session_role', 'postgres'),
                           ('port', 9999), ('version', '160000'), ('address', '192.0.2.1'),
                           ('postmaster_start', '2026-10-18T00:00:00+00:00')):
            data = self.observation(); data[0][key] = value
            with self.subTest(key=key), self.assertRaises(reader.Denied):
                reader.validate_observation(data, CATALOG)

    def test_writable_or_cleartext_connection_denied(self):
        for key, value in (('ssl', False), ('transaction_read_only', 'off')):
            data = self.observation(); data[0][key] = value
            with self.assertRaises(reader.Denied): reader.validate_observation(data, CATALOG)

    def test_elevated_role_denied(self):
        for key in ('superuser', 'bypass_rls', 'create_role', 'create_db', 'replication'):
            data = self.observation(); data[1][key] = True
            with self.subTest(key=key), self.assertRaises(reader.Denied):
                reader.validate_observation(data, CATALOG)

    def test_rights_and_rls_denied(self):
        for key, value in (('rls', True), ('force_rls', True), ('select', False),
                           ('all_columns_select', False), ('exists', False), ('relation_kind', 'p')):
            data = self.observation(); data[2][key] = value
            with self.subTest(key=key), self.assertRaises(reader.Denied):
                reader.validate_observation(data, CATALOG)

    def test_missing_or_duplicate_relation_denied(self):
        for data in (self.observation()[:-1], self.observation()+[copy.deepcopy(self.observation()[-1])]):
            with self.assertRaises(reader.Denied): reader.validate_observation(data, CATALOG)

    def test_missing_snapshot_or_sequence_rights_denied(self):
        data = self.observation(); data[1]['snapshot_execute'] = False
        with self.assertRaises(reader.Denied): reader.validate_observation(data, CATALOG)
        data = self.observation()+[dict(kind='sequence', name='synthetic_seq', select=False)]
        with self.assertRaises(reader.Denied): reader.validate_observation(data, CATALOG)

    def test_cleanup_only_owned_new_passfile(self):
        directory = Path(tempfile.mkdtemp(prefix='tu1nz-b-synthetic-passfile-'))
        path = directory/'pgpass'; reader.private_write(path, b'SYNTHETIC\n')
        info = path.lstat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        reader.remove_owned_passfile(path, (info.st_dev, info.st_ino, info.st_uid))
        self.assertFalse(path.exists())

    def test_replacement_not_deleted(self):
        directory = Path(tempfile.mkdtemp(prefix='tu1nz-b-synthetic-replacement-'))
        path = directory/'pgpass'; reader.private_write(path, b'SYNTHETIC\n')
        info = path.lstat()
        with self.assertRaises(reader.Denied):
            reader.remove_owned_passfile(path, (info.st_dev, info.st_ino+1, info.st_uid))
        self.assertTrue(path.exists())  # No-delete: retain unowned/replaced fixture.

    def test_remote_reader_fixed_source_no_changes(self):
        self.assertIn("'/etc/tu1nz/adult-commercial-s7-database.dsn'", reader.REMOTE_READ)
        self.assertIn('os.O_RDONLY|os.O_NOFOLLOW', reader.REMOTE_READ)
        self.assertNotIn('chmod', reader.REMOTE_READ)
        self.assertNotIn('chown', reader.REMOTE_READ)
        self.assertNotIn('/run/credentials', reader.REMOTE_READ)
        self.assertNotIn('subprocess', reader.REMOTE_READ)


if __name__ == '__main__': unittest.main()
