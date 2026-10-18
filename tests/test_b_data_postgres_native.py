"""Actual PostgreSQL, synthetic private cluster, Unix sockets only, no Host data.

Run as an unprivileged user with PostgreSQL16 bin tools. This is NOT a proof of
Host writer freedom or of the real application's schema/data quality.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

from tests.test_b_data_handoff import b, CATALOG, chosen, encoded


@unittest.skipUnless(sys.platform.startswith('linux'), 'Native PostgreSQL proof requires Linux, not Host acceptance')
class NativePostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise RuntimeError('UNPRIVILEGED_SYNTHETIC_TEST_REQUIRED')
        cls.bin = Path(os.environ.get('TU1NZ_B_PG_BIN', '/usr/lib/postgresql/16/bin'))
        if not all((cls.bin / n).is_file() for n in ('initdb', 'pg_ctl', 'psql', 'pg_dump', 'pg_restore')):
            raise RuntimeError('NATIVE_POSTGRES_TOOLS_REQUIRED_NO_SKIP')
        cls.tmp = tempfile.TemporaryDirectory(prefix='tu1nz-b-pg-synthetic-')
        cls.root = Path(cls.tmp.name)
        cls.env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
        cls.env.update({'PGHOST': str(cls.root), 'PGPORT': '6543', 'PGUSER': 'b_admin',
                        'PGDATABASE': 'postgres', 'PGCONNECT_TIMEOUT': '5'})
        cls.command('initdb', '-D', str(cls.root / 'cluster'), '--username=b_admin',
                    '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8')
        cls.command('pg_ctl', '-D', str(cls.root / 'cluster'), '-l', str(cls.root / 'server.log'),
                    '-o', '-k ' + str(cls.root) + " -p 6543 -c listen_addresses=''", '-w', 'start')
        cls.service = cls.root / 'service.conf'
        cls.service.write_text('[tu1nz_b_export]\nhost=' + str(cls.root) +
                               '\nport=6543\nuser=b_admin\ndbname=tu1nz_adult_commercial_s3\n')
        cls.service.chmod(0o600)
        cls.env['PGSERVICEFILE'] = str(cls.service)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.command('pg_ctl', '-D', str(cls.root / 'cluster'), '-m', 'fast', '-w', 'stop')
        finally:
            cls.tmp.cleanup()

    @classmethod
    def command(cls, name, *args, input=None, env=None, check=True):
        result = subprocess.run([str(cls.bin / name), *args], input=input, capture_output=True,
                                env=env or cls.env, timeout=30)
        if check and result.returncode:
            raise AssertionError(name + ' failed with synthetic inputs: ' + result.stderr.decode(errors='replace'))
        return result

    @classmethod
    def sql(cls, text, db='postgres', **kwargs):
        return cls.command('psql', '-X', '-qAt', '--set=ON_ERROR_STOP=1', '--dbname', db,
                           input=text.encode(), **kwargs)

    def setUp(self):
        # Drop ONLY databases of this newly owned synthetic cluster, never Host.
        for name in ('tu1nz_adult_commercial_s3', 'restored'):
            self.sql('DROP DATABASE IF EXISTS ' + name + '; CREATE DATABASE ' + name + ';')
        for db in ('tu1nz_adult_commercial_s3', 'restored'):
            statements = ['CREATE TABLE ' + n + '(id int PRIMARY KEY, value text NOT NULL);'
                          for n in CATALOG['tables']]
            for child, parents in CATALOG['foreign_keys'].items():
                statements.extend('ALTER TABLE ' + child + ' ADD FOREIGN KEY(id) REFERENCES ' + p + '(id);'
                                  for p in parents)
            self.sql('\n'.join(statements), db)
        self.sql('BEGIN;' + ''.join("INSERT INTO " + n + " VALUES (1,'SYNTHETIC');"
                                    for n in CATALOG['tables']) + 'COMMIT;', 'tu1nz_adult_commercial_s3')

    def snapshot(self):
        keeper = subprocess.Popen([str(self.bin / 'psql'), '-X', '-qAt', '--set=ON_ERROR_STOP=1',
                                   '--dbname=tu1nz_adult_commercial_s3'], env=self.env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.close_snapshot, keeper)
        keeper.stdin.write(b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n')
        keeper.stdin.flush()
        self.assertTrue(select.select([keeper.stdout], [], [], 10)[0], 'snapshot bounded wait')
        token = keeper.stdout.readline().decode().strip()
        self.assertRegex(token, r'^[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+$')
        return keeper, token

    @staticmethod
    def close_snapshot(keeper):
        if keeper.poll() is None:
            keeper.stdin.write(b'ROLLBACK;\n'); keeper.stdin.close()
            keeper.wait(timeout=10)
        for stream in (keeper.stdin, keeper.stdout, keeper.stderr):
            if not stream.closed: stream.close()

    def dump(self, token, **kwargs):
        selected = b.selection(encoded(chosen()), CATALOG)
        argv = b.dump_argv(selected, token)
        return self.command(argv[0], *argv[1:], **kwargs)

    def restore(self, raw, check=True):
        return self.command('pg_restore', '--dbname=restored', '--data-only', '--no-owner',
                            '--no-privileges', '--exit-on-error', '--single-transaction',
                            input=raw, check=check)

    def assert_rows(self, count):
        actual = self.sql(b.counts_sql(chosen()), 'restored').stdout.decode().splitlines()
        self.assertEqual(len(actual), 33)
        self.assertTrue(all(line.rsplit('|', 1)[1] == str(count) for line in actual))

    def test_mvcc_snapshot_with_concurrent_committed_writer(self):
        _, token = self.snapshot()
        self.sql('BEGIN;' + ''.join("INSERT INTO " + n + " VALUES(2,'LATER_SYNTHETIC');"
                                    for n in CATALOG['tables']) + 'COMMIT;', 'tu1nz_adult_commercial_s3')
        raw = self.dump(token).stdout
        self.assertEqual(self.sql('SELECT count(*) FROM commercial_s7_waitlist;',
                                  'tu1nz_adult_commercial_s3').stdout.strip(), b'2')
        self.restore(raw)
        self.assert_rows(1)

    def test_final_fixture_snapshot_and_content_roundtrip(self):
        _, token = self.snapshot()
        self.restore(self.dump(token).stdout)
        self.assert_rows(1)
        for name in CATALOG['tables']:
            query = 'COPY (SELECT * FROM ' + name + ' ORDER BY id) TO STDOUT;'
            self.assertEqual(self.sql(query, 'tu1nz_adult_commercial_s3').stdout,
                             self.sql(query, 'restored').stdout)
        # There is exactly one controlled fixture writer and it is idle here.
        # This does NOT establish an all-writer or filesystem fence on a Host.

    def test_lost_snapshot_no_retry(self):
        keeper, token = self.snapshot()
        self.close_snapshot(keeper)
        self.assertNotEqual(self.dump(token, check=False).returncode, 0)

    def test_partial_dump_and_schema_mismatch_deny_restore(self):
        _, token = self.snapshot()
        raw = self.dump(token).stdout
        self.assertNotEqual(self.restore(raw[:100], check=False).returncode, 0)
        self.sql('ALTER TABLE commercial_s7_waitlist RENAME COLUMN value TO other;', 'restored')
        self.assertNotEqual(self.restore(raw, check=False).returncode, 0)
        self.assertEqual(self.sql('SELECT count(*) FROM commercial_s7_waitlist;', 'restored').stdout.strip(), b'0')

    def test_seeded_target_is_not_silently_cleaned_or_upserted(self):
        self.sql("INSERT INTO commercial_s7_waitlist VALUES(1,'PREEXISTING_SYNTHETIC');", 'restored')
        _, token = self.snapshot()
        self.assertNotEqual(self.restore(self.dump(token).stdout, check=False).returncode, 0)
        self.assertEqual(self.sql('SELECT value FROM commercial_s7_waitlist;', 'restored').stdout.strip(),
                         b'PREEXISTING_SYNTHETIC')

    def test_equal_counts_do_not_prove_equal_content(self):
        _, token = self.snapshot()
        self.restore(self.dump(token).stdout)
        self.sql("UPDATE commercial_s7_waitlist SET value='DIFFERENT_SYNTHETIC' WHERE id=1;", 'restored')
        self.assert_rows(1)
        query = 'COPY (SELECT * FROM commercial_s7_waitlist ORDER BY id) TO STDOUT;'
        self.assertNotEqual(b.sha(self.sql(query, 'tu1nz_adult_commercial_s3').stdout),
                            b.sha(self.sql(query, 'restored').stdout))

    def test_progressed_insert_guard_predata_data_postdata(self):
        # Synthetic reproduction of the bound0030 INSERT invariant, not an
        # execution/import of private application Source or real polling data.
        table = 'commercial_s10_2d_bot_polling_state'
        self.sql('ALTER TABLE ' + table + ' ADD COLUMN revision int NOT NULL DEFAULT 0;'
                 'ALTER TABLE ' + table + ' ADD COLUMN created_at int NOT NULL DEFAULT 0;'
                 'ALTER TABLE ' + table + ' ADD COLUMN updated_at int NOT NULL DEFAULT 0;'
                 'UPDATE ' + table + ' SET revision=7, updated_at=8;'
                 "CREATE FUNCTION synthetic_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                 "IF NEW.revision<>0 OR NEW.updated_at<>NEW.created_at THEN RAISE EXCEPTION 'SYNTHETIC_INSERT_GUARD'; "
                 "END IF; RETURN NEW; END $$;"
                 'CREATE TRIGGER synthetic_insert_guard BEFORE INSERT ON ' + table +
                 ' FOR EACH ROW EXECUTE FUNCTION synthetic_guard();', 'tu1nz_adult_commercial_s3')
        pre = self.command('pg_dump', '--dbname=tu1nz_adult_commercial_s3', '--schema-only',
                           '--section=pre-data', '--no-owner', '--no-privileges').stdout
        post = self.command('pg_dump', '--dbname=tu1nz_adult_commercial_s3', '--schema-only',
                            '--section=post-data', '--no-owner', '--no-privileges').stdout
        _, token = self.snapshot()
        data = self.dump(token).stdout
        self.sql('CREATE DATABASE staged;')
        try:
            self.command('psql', '-X', '--set=ON_ERROR_STOP=1', '--single-transaction',
                         '--dbname=staged', input=pre)
            self.command('pg_restore', '--dbname=staged', '--data-only', '--no-owner',
                         '--no-privileges', '--single-transaction', '--exit-on-error', input=data)
            self.command('psql', '-X', '--set=ON_ERROR_STOP=1', '--single-transaction',
                         '--dbname=staged', input=post)
            self.assertEqual(self.sql('SELECT revision,updated_at,created_at FROM ' + table + ';',
                                      'staged').stdout.strip(), b'7|8|0')
            denied = self.sql('INSERT INTO ' + table +
                              " VALUES(2,'SYNTHETIC',7,0,8);", 'staged', check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn(b'SYNTHETIC_INSERT_GUARD', denied.stderr)
        finally:
            # Only this newly created isolated test database, not Host data.
            self.sql('DROP DATABASE staged;')

    def test_insufficient_role_and_rls_are_not_empty_success(self):
        self.sql("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='b_reader') "
                 "THEN CREATE ROLE b_reader LOGIN; END IF; END $$;")
        self.sql('GRANT USAGE ON SCHEMA public TO b_reader;'
                 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO b_reader;'
                 'ALTER TABLE commercial_s7_waitlist ENABLE ROW LEVEL SECURITY;', 'tu1nz_adult_commercial_s3')
        _, token = self.snapshot()
        env = {**self.env, 'PGUSER': 'b_reader'}
        # Explicit PGSERVICE fields take precedence over PGUSER; a private
        # synthetic service file binds the limited role for this one request.
        service = self.root / 'reader.conf'
        service.write_text(self.service.read_text().replace('user=b_admin', 'user=b_reader'))
        service.chmod(0o600); env['PGSERVICEFILE'] = str(service)
        self.assertNotEqual(self.dump(token, env=env, check=False).returncode, 0)
        self.sql('ALTER TABLE commercial_s7_waitlist DISABLE ROW LEVEL SECURITY;'
                 'REVOKE SELECT ON commercial_s7_waitlist FROM b_reader;', 'tu1nz_adult_commercial_s3')
        self.assertNotEqual(self.dump(token, env=env, check=False).returncode, 0)

    def test_closing_one_role_does_not_close_an_additional_writer(self):
        connections = {}
        for role in ('b_closed', 'b_extra'):
            self.sql("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='" + role + "') "
                     "THEN CREATE ROLE " + role + " LOGIN; END IF; END $$; ALTER ROLE " + role + " LOGIN;")
            self.sql('GRANT USAGE ON SCHEMA public TO ' + role + ';'
                     'GRANT INSERT ON commercial_s7_waitlist TO ' + role + ';', 'tu1nz_adult_commercial_s3')
            service = self.root / (role + '.conf')
            service.write_text(self.service.read_text().replace('user=b_admin', 'user=' + role))
            service.chmod(0o600)
            # Select the service explicitly, not only its file. Plain dbname
            # + PGUSER also works, but never assume which role was selected.
            connections[role] = {**self.env, 'PGUSER': role, 'PGSERVICE': 'tu1nz_b_export',
                                 'PGSERVICEFILE': str(service)}
            self.assertEqual(self.sql('SELECT session_user,current_user;', 'tu1nz_adult_commercial_s3',
                                      env=connections[role]).stdout.strip(), (role + '|' + role).encode())
        self.sql('ALTER ROLE b_closed NOLOGIN;')
        closed = self.sql("INSERT INTO commercial_s7_waitlist VALUES(3,'CLOSED_SYNTHETIC');",
                          'tu1nz_adult_commercial_s3', env=connections['b_closed'], check=False)
        self.assertNotEqual(closed.returncode, 0)
        self.assertIn(b'not permitted to log in', closed.stderr)
        env = connections['b_extra']
        self.sql("INSERT INTO commercial_s7_waitlist VALUES(2,'EXTRA_SYNTHETIC');",
                 'tu1nz_adult_commercial_s3', env=env)
        self.assertEqual(self.sql('SELECT count(*) FROM commercial_s7_waitlist;',
                                  'tu1nz_adult_commercial_s3').stdout.strip(), b'2')
        self.sql('REVOKE INSERT ON commercial_s7_waitlist FROM b_extra;', 'tu1nz_adult_commercial_s3')
        denied = self.sql("INSERT INTO commercial_s7_waitlist VALUES(3,'DENIED_SYNTHETIC');",
                          'tu1nz_adult_commercial_s3', env=env, check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn(b'permission denied for table commercial_s7_waitlist', denied.stderr)
        self.assertEqual(self.sql('SELECT count(*) FROM commercial_s7_waitlist;',
                                  'tu1nz_adult_commercial_s3').stdout.strip(), b'2')

    def test_actual_metadata_intake_is_read_only_on_synthetic_database(self):
        intake = Path(__file__).resolve().parents[1] / 'scripts/tu1nz_b_data_inventory.sql'
        self.sql("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='b_column') "
                 "THEN CREATE ROLE b_column LOGIN; END IF; END $$;")
        self.sql('GRANT UPDATE(value) ON commercial_s7_waitlist TO b_column;',
                 'tu1nz_adult_commercial_s3')
        before = self.sql(b.counts_sql(chosen()), 'tu1nz_adult_commercial_s3').stdout
        output = self.command('psql', '-X', '--set=ON_ERROR_STOP=1', '--dbname=tu1nz_adult_commercial_s3',
                              '--file', str(intake)).stdout
        self.assertIn(b'b_column', output)
        self.assertEqual(before, self.sql(b.counts_sql(chosen()), 'tu1nz_adult_commercial_s3').stdout)


if __name__ == '__main__': unittest.main()
