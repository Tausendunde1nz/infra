"""Explicit local synthetic Mac fixture; no production address/data/credentials.

Not a persistent service: one owned native PG17 process, private fixture and
loopback35432 only; always stop it. Retain test data under No-Delete.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(_number, _frame):
        raise InterruptedError('SIGNAL')
    signal.signal(signal.SIGTERM, interrupted)
    assert not args.output.exists()
    os.umask(0o077)
    base = args.client_root/'Contents/Versions/17'
    for name in ('initdb', 'pg_ctl', 'postgres'):
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R',
                        '=anchor apple generic and certificate leaf[subject.OU] = "ZF84SJ5A3G"',
                        str(base/'bin'/name)], check=True, capture_output=True)
    fixture = Path(tempfile.mkdtemp(prefix='tu1nz-b-mac-fixture-', dir='/private/tmp'))
    pgdata, sockdir = fixture/'pgdata', fixture/'socket'
    sockdir.mkdir(mode=0o700)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 35432))
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null',
           'PGHOST': str(sockdir), 'PGPORT': '35432', 'PGUSER': 'b_fixture_owner',
           'PGDATABASE': 'postgres', 'PGSERVICEFILE': '/dev/null', 'PGPASSFILE': '/dev/null'}
    cases, owner = [], None
    started = False
    passfile = passfile_identity = None

    def call(name, options, sql=None, settings=None, expect=0):
        command = ['/usr/bin/arch', '-arm64', str(base/'bin'/name), *options]
        result = subprocess.run(command, input=sql, capture_output=True, env=settings or env, timeout=15)
        if expect == 0:
            assert result.returncode == 0, name+'_FAILED_'+hashlib.sha256(result.stderr).hexdigest()
        else:
            assert result.returncode != 0, name+'_UNEXPECTED_SUCCESS'
        return result

    def query(sql, settings=None, expect=0):
        return call('psql', ['-X', '-qAt', '--no-password', '--set=ON_ERROR_STOP=1', '--file=-'], sql.encode(), settings, expect)

    try:
        call('initdb', ['-D', str(pgdata), '--username=b_fixture_owner', '--auth-local=trust', '--auth-host=scram-sha-256', '--no-instructions'])
        cert = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-days', '1', '-keyout', str(pgdata/'server.key'), '-out', str(pgdata/'server.crt')], capture_output=True, timeout=15)
        assert cert.returncode == 0
        os.chmod(pgdata/'server.key', 0o600)
        started = True
        call('pg_ctl', ['-D', str(pgdata), '-l', str(fixture/'server.log'), '-o',
                       "-c listen_addresses=127.0.0.1 -p 35432 -c unix_socket_directories="+str(sockdir)+" -c ssl=on -c autovacuum=off -c shared_buffers=16MB -c max_connections=10", '-w', '-t', '10', 'start'])
        query("CREATE ROLE b_fixture_reader LOGIN PASSWORD 'SYNTHETIC-only-for-local-test'; CREATE DATABASE b_fixture_source; CREATE DATABASE b_fixture_restore;")
        env['PGDATABASE'] = 'b_fixture_source'
        query('CREATE TABLE b_parent(id integer PRIMARY KEY, payload text NOT NULL); CREATE TABLE b_child(id integer PRIMARY KEY, parent integer REFERENCES b_parent(id)); INSERT INTO b_parent VALUES(1,\'SYNTHETIC\'); INSERT INTO b_child VALUES(1,1); GRANT SELECT ON b_parent,b_child TO b_fixture_reader;')
        passfile = fixture/'pgpass'
        passfile.write_bytes(b'127.0.0.1:35432:b_fixture_source:b_fixture_reader:SYNTHETIC-only-for-local-test\n')
        os.chmod(passfile, 0o600)
        passfile_info = passfile.lstat()
        passfile_identity = (passfile_info.st_dev, passfile_info.st_ino)
        reader_env = dict(env, PGHOST='127.0.0.1', PGUSER='b_fixture_reader', PGPASSFILE=str(passfile),
                          PGSSLMODE='require', PGCHANNELBINDING='require', PGGSSENCMODE='disable',
                          PGSSLROOTCERT=str(fixture/'absent-root.crt'), PGSSLCERT=str(fixture/'absent-client.crt'),
                          PGSSLKEY=str(fixture/'absent-client.key'), PGOPTIONS='-c default_transaction_read_only=on')
        check = query("BEGIN READ ONLY; SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT current_setting('transaction_read_only'); COMMIT;", reader_env)
        assert check.stdout.splitlines() == [b't', b'on']
        cases.append('native_scram_plus_tls_readonly')
        owner = subprocess.Popen(['/usr/bin/arch', '-arm64', str(base/'bin/psql'), '-X', '-qAt', '--no-password', '--set=ON_ERROR_STOP=1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=reader_env)
        owner.stdin.write(b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n')
        owner.stdin.flush()
        assert select.select([owner.stdout], [], [], 5)[0], 'SNAPSHOT_NOT_READY'
        token = owner.stdout.readline().decode().strip()
        assert token and all(c in '0123456789ABCDEF-' for c in token), 'BAD_SNAPSHOT'
        query("INSERT INTO b_parent VALUES(2,'SYNTHETIC-later');")
        dump = fixture/'snapshot.dump'
        dump_args = ['--format=custom', '--data-only', '--no-owner', '--no-privileges', '--strict-names', '--lock-wait-timeout=5000', '--table=public.b_parent', '--table=public.b_child']
        call('pg_dump', [*dump_args, '--snapshot='+token, '--file='+str(dump)], settings=reader_env)
        snapshot_count = query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '"+token+"'; SELECT count(*) FROM b_parent; COMMIT;", reader_env)
        assert snapshot_count.stdout.strip() == b'1'
        assert query('SELECT count(*) FROM b_parent;', reader_env).stdout.strip() == b'2'
        cases.append('held_snapshot_excludes_concurrent_insert')
        restore_env = dict(env, PGDATABASE='b_fixture_restore')
        query('CREATE TABLE b_parent(id integer PRIMARY KEY, payload text NOT NULL); CREATE TABLE b_child(id integer PRIMARY KEY, parent integer);', restore_env)
        call('pg_restore', ['--exit-on-error', '--no-owner', '--no-privileges', '--dbname=b_fixture_restore', str(dump)], settings=restore_env)
        query('ALTER TABLE b_child ADD FOREIGN KEY(parent) REFERENCES b_parent(id);', restore_env)
        assert query('SELECT (SELECT count(*) FROM b_parent),(SELECT count(*) FROM b_child);', restore_env).stdout.strip() == b'1|1'
        cases.append('native_pre_data_post_restore_and_fk')
        call('pg_dump', [*dump_args, '--snapshot=INVALID-SYNTHETIC', '--file='+str(fixture/'invalid-snapshot.partial')], settings=reader_env, expect=1)
        cases.append('invalid_snapshot_denied')
        owner.stdin.write(b'ROLLBACK;\n\\q\n'); owner.stdin.flush()
        owner.communicate(timeout=5)
        assert owner.returncode == 0
        query('ALTER TABLE b_parent ENABLE ROW LEVEL SECURITY;')
        call('pg_dump', [*dump_args, '--file='+str(fixture/'rls.partial')], settings=reader_env, expect=1)
        cases.append('rls_not_silently_filtered')
        query('ALTER TABLE b_parent DISABLE ROW LEVEL SECURITY; REVOKE SELECT ON b_child FROM b_fixture_reader;')
        call('pg_dump', [*dump_args, '--file='+str(fixture/'rights.partial')], settings=reader_env, expect=1)
        cases.append('missing_select_denied')
    finally:
        if owner is not None and owner.poll() is None:
            owner.terminate(); owner.wait(timeout=5)
        if started and (pgdata/'postmaster.pid').exists():
            stopped = subprocess.run(['/usr/bin/arch', '-arm64', str(base/'bin/pg_ctl'), '-D', str(pgdata), '-m', 'fast', '-w', '-t', '10', 'stop'], capture_output=True, timeout=15, env=env)
            assert stopped.returncode == 0, 'OWN_TEST_SERVER_NOT_STOPPED'
        if passfile is not None and passfile_identity is not None:
            current = passfile.lstat()
            assert (current.st_dev, current.st_ino) == passfile_identity, 'TEST_PASSFILE_REPLACED'
            passfile.unlink()  # Only this new temporary synthetic credential.
    report = {'result': 'PASS', 'cases': cases, 'case_count': len(cases), 'fixture': str(fixture),
              'native_architecture': 'arm64', 'retained_synthetic_data_no_delete': True,
              'temporary_service_stopped': True, 'private_production_input': False,
              'not_real_restore_acceptance': True}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((json.dumps(report, indent=2)+'\n').encode()); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'result': 'PASS', 'cases': len(cases), 'own_test_server': 'STOPPED'}))


if __name__ == '__main__': main()
