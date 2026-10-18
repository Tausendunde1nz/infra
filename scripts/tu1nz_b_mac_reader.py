#!/usr/bin/env python3
"""Fixed B admission metadata reader, never a productive data exporter.

Import/help are inert. The once-only CLI needs a secure local TTY, authentic
Mac client closure and explicit --read-only-check. Passwords use private pipes
and exactly one temporary0600 passfile; neither raw DSN nor stderr is logged.
"""
from __future__ import annotations

import argparse
import ast
import ctypes
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import warnings

DATABASE = 'tu1nz_adult_commercial_s3'
ROLE = 'tu1nz_adult_commercial_s3_runtime'
HOST = 'chatops@100.121.130.51'
CATALOG_SHA = '8e5d57c4c45af3402da6328289ba511aa9a9fad9cafe109249d31d9cf7f27877'
TRANSPORT_SHA = '23ebabba5e0ff08cf1d20e3267d8afcbe02c27c04c83332a75d9698a3b3a5a2b'
TEAM = 'ZF84SJ5A3G'
MEMBERS = {
    'Contents/Versions/17/bin/psql', 'Contents/Versions/17/bin/pg_dump',
    'Contents/Versions/17/bin/pg_restore', 'Contents/Versions/17/lib/libpq.5.dylib',
    'Contents/Versions/17/lib/libcrypto.3.dylib', 'Contents/Versions/17/lib/libssl.3.dylib',
    'Contents/Versions/17/lib/liblz4.1.10.0.dylib',
    'Contents/Versions/17/lib/libzstd.1.5.7.dylib',
}

# The only privileged source operation. No SQL, DSO loading, credential search,
# remote staging or writes. The private SSH stdout pipe is NOT a tool/log output.
REMOTE_READ = r'''
import hashlib,os,pathlib,stat,sys
try:
 if os.geteuid()!=0: raise ValueError()
 if hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()!='a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae': raise ValueError()
 fd=os.open('/etc/tu1nz/adult-commercial-s7-database.dsn',os.O_RDONLY|os.O_NOFOLLOW)
 a=os.fstat(fd)
 if not stat.S_ISREG(a.st_mode) or (a.st_uid,a.st_gid,stat.S_IMODE(a.st_mode))!=(0,0,0o600) or not 0<a.st_size<=16384: raise ValueError()
 data=os.read(fd,16385); z=os.fstat(fd);os.close(fd)
 if len(data)!=a.st_size or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns): raise ValueError()
 sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
except BaseException:
 sys.stderr.write('SOURCE_CREDENTIAL_READ_DENIED\n');sys.exit(71)
'''


class Denied(ValueError):
    """Only fixed codes, never the failing value or subprocess stderr."""


def need(value, code):
    if not value:
        raise Denied(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def verify_client(root, manifest_path, expected_sha):
    need(sys.platform == 'darwin' and os.uname().machine == 'arm64', 'NATIVE_ARM64_MAC_REQUIRED')
    need(Path(sys.prefix) == Path('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9'),
         'ADMITTED_APPLE_PYTHON_REQUIRED')
    raw = manifest_path.read_bytes()
    need(sha(raw) == expected_sha, 'CLIENT_MANIFEST_CHANGED')
    manifest = json.loads(raw)
    need(set(manifest['members']) == MEMBERS and manifest['signer_team'] == TEAM,
         'CLIENT_CLOSURE_CHANGED')
    root = root.resolve()
    for name, member in manifest['members'].items():
        path = (root / name).resolve()
        need(path.is_relative_to(root) and sha(path.read_bytes()) == member['sha256'],
             'CLIENT_BYTES_CHANGED')
        p = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R',
                            '=anchor apple generic and certificate leaf[subject.OU] = "'+TEAM+'"',
                            str(path)], capture_output=True, timeout=10)
        need(p.returncode == 0, 'CLIENT_SIGNATURE_FAILED')
    for command in (['/usr/bin/codesign', '--verify', '--deep', '--strict', str(root)],
                    ['/usr/sbin/spctl', '--assess', '--type', 'execute', str(root)],
                    ['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=anchor apple',
                     '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework']):
        need(subprocess.run(command, capture_output=True, timeout=30).returncode == 0,
             'PLATFORM_OR_APP_SIGNATURE_FAILED')
    return manifest


def parse_dsn(raw, library):
    """Use the authenticated client library's grammar; no connect/default expansion."""
    need(0 < len(raw) <= 16384 and b'\0' not in raw, 'DSN_SIZE_OR_NUL')
    class Option(ctypes.Structure):
        _fields_ = [(name, ctypes.c_char_p) for name in
                    ('keyword', 'envvar', 'compiled', 'val', 'label', 'dispchar')] + [('dispsize', ctypes.c_int)]
    lib = ctypes.CDLL(str(library))
    lib.PQconninfoParse.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.PQconninfoParse.restype = ctypes.POINTER(Option)
    lib.PQconninfoFree.argtypes = [ctypes.POINTER(Option)]
    lib.PQfreemem.argtypes = [ctypes.c_void_p]
    error = ctypes.c_void_p()
    options = lib.PQconninfoParse(raw.strip(), ctypes.byref(error))
    try:
        need(bool(options), 'DSN_PARSE_FAILED')
        values, index = {}, 0
        while options[index].keyword:
            item = options[index]
            if item.val is not None:
                values[item.keyword.decode('ascii')] = item.val.decode('utf-8')
            index += 1
        return values
    finally:
        if options:
            lib.PQconninfoFree(options)
        if error.value:
            lib.PQfreemem(error)


def validate_dsn(values):
    allowed = {'user', 'password', 'dbname', 'host', 'port', 'sslmode',
               'connect_timeout', 'application_name', 'channel_binding', 'gssencmode'}
    need(set(values) <= allowed, 'DSN_UNAPPROVED_OPTIONS')
    need(values.get('user') == ROLE, 'DSN_UNEXPECTED_ROLE')
    need(values.get('dbname') == DATABASE, 'DSN_UNEXPECTED_DATABASE')
    need(values.get('host', '') in ('', 'localhost', '127.0.0.1', '/var/run/postgresql'),
         'DSN_UNEXPECTED_SERVICE')
    need(values.get('port', '5432') == '5432', 'DSN_UNEXPECTED_PORT')
    need(values.get('sslmode', 'prefer') in ('disable', 'allow', 'prefer', 'require'),
         'DSN_STRONGER_TLS_BINDING_REQUIRES_SCOPE')
    need(values.get('gssencmode', 'prefer') in ('disable', 'prefer'), 'DSN_REQUIRES_OTHER_AUTH')
    need(values.get('channel_binding', 'prefer') in ('disable', 'prefer', 'require'),
         'DSN_CHANNEL_BINDING_INVALID')
    password = values.get('password', '')
    need(password and not any(c in password for c in '\r\n\0'), 'DSN_PASSWORD_UNUSABLE')
    return password


def passfile_bytes(password):
    need(password and not any(c in password for c in '\r\n\0'), 'PASSWORD_UNUSABLE')
    escaped = password.replace('\\', '\\\\').replace(':', '\\:')
    return ('127.0.0.1:15432:'+DATABASE+':'+ROLE+':'+escaped+'\n').encode('utf-8')


def clean_environment(passfile, base, private_dir):
    # Keep the user's HOME unchanged; explicit absent TLS files prevent reading
    # ~/.postgresql defaults. No PGPASSWORD, inherited PG/DYLD, shell or user RC.
    return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
            'PGPASSFILE': str(passfile), 'PGSERVICEFILE': '/dev/null',
            'PGSSLMODE': 'require', 'PGCHANNELBINDING': 'require',
            'PGGSSENCMODE': 'disable', 'PGCONNECT_TIMEOUT': '5',
            'PGSSLROOTCERT': str(private_dir/'absent-ca.crt'),
            'PGSSLCERT': str(private_dir/'absent-client.crt'),
            'PGSSLKEY': str(private_dir/'absent-client.key'),
            'PGSSLCRL': str(private_dir/'absent-crl'),
            'PGSSLCRLDIR': str(private_dir/'absent-crldir'),
            'PGOPTIONS': '-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=2000',
            'OPENSSL_CONF': '/dev/null', 'OPENSSL_MODULES': str(base/'lib/ossl-modules')}


def metadata_sql(catalog):
    need(sha(catalog) == CATALOG_SHA, 'CATALOG_CHANGED')
    names = json.loads(catalog)['tables']
    need(len(names) == 34 and all(re.fullmatch('commercial_[a-z0-9_]+', n) for n in names), 'CATALOG_INVALID')
    values = ','.join("('%s')" % n for n in names)
    return (r"""\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='2s'; SET LOCAL TimeZone='UTC';
SELECT json_build_object('kind','identity','database',current_database(),'role',current_user,
 'session_role',session_user,'version',current_setting('server_version_num'),
 'address',inet_server_addr(),'port',inet_server_port(),
 'postmaster_start',pg_postmaster_start_time(),'transaction_read_only',current_setting('transaction_read_only'),
 'ssl',(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()));
SELECT json_build_object('kind','role','superuser',rolsuper,'bypass_rls',rolbypassrls,
 'create_role',rolcreaterole,'create_db',rolcreatedb,'replication',rolreplication,
 'schema_usage',has_schema_privilege(oid,'public','USAGE'),
 'snapshot_execute',has_function_privilege(oid,'pg_catalog.pg_export_snapshot()','EXECUTE'))
FROM pg_roles WHERE rolname=current_user;
WITH selected(name) AS (VALUES __VALUES__)
SELECT json_build_object('kind','relation','name',s.name,'exists',c.oid IS NOT NULL,
 'relation_kind',c.relkind,'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity,
 'select',has_table_privilege(current_user,c.oid,'SELECT'),
 'all_columns_select',(SELECT bool_and(has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT'))
 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped))
FROM selected s LEFT JOIN pg_namespace n ON n.nspname='public'
LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=s.name ORDER BY s.name;
WITH selected(name) AS (VALUES __VALUES__)
SELECT json_build_object('kind','sequence','name',q.relname,'select',has_sequence_privilege(current_user,q.oid,'SELECT'))
FROM selected s JOIN pg_namespace n ON n.nspname='public'
JOIN pg_class t ON t.relnamespace=n.oid AND t.relname=s.name
JOIN pg_depend d ON d.refclassid='pg_class'::regclass AND d.refobjid=t.oid
 AND d.classid='pg_class'::regclass AND d.deptype IN ('a','i')
JOIN pg_class q ON q.oid=d.objid AND q.relkind='S' ORDER BY q.relname;
COMMIT;
""".replace('__VALUES__', values)).encode()


def validate_observation(data, catalog):
    identity = [r for r in data if r.get('kind') == 'identity']
    roles = [r for r in data if r.get('kind') == 'role']
    need(len(identity) == len(roles) == 1, 'IDENTITY_INCOMPLETE')
    row = identity[0]
    need((row['database'], row['role'], row['session_role'], row['version'], row['port']) ==
         (DATABASE, ROLE, ROLE, '170011', 5432), 'WRONG_SOURCE_IDENTITY')
    need(row['address'] in ('127.0.0.1', '::1') and row['transaction_read_only'] == 'on' and row['ssl'] is True,
         'CONNECTION_NOT_EXPECTED_READONLY_TLS')
    need(datetime.fromisoformat(row['postmaster_start']) == datetime.fromisoformat('2026-08-27T19:59:20.500309+00:00'),
         'POSTMASTER_IDENTITY_CHANGED')
    role = roles[0]
    need(not any(role[k] for k in ('superuser', 'bypass_rls', 'create_role', 'create_db', 'replication')),
         'PRIVILEGED_ROLE_DENIED')
    need(role['schema_usage'] and role['snapshot_execute'], 'READER_ACCESS_MISSING')
    rows = [r for r in data if r.get('kind') == 'relation']
    need(len(rows) == 34 and {r['name'] for r in rows} == set(json.loads(catalog)['tables']),
         'RELATION_COVERAGE_CHANGED')
    need(all(r['exists'] and r['relation_kind'] == 'r' and r['select'] and r['all_columns_select']
             and not r['rls'] and not r['force_rls'] for r in rows), 'EXPORT_RIGHTS_OR_RLS_DENIED')
    need(all(r['select'] for r in data if r.get('kind') == 'sequence'), 'SEQUENCE_ACCESS_DENIED')


def transport(path):
    raw = path.read_bytes()
    need(sha(raw) == TRANSPORT_SHA, 'TRANSPORT_CHANGED')
    constants = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(raw).body
                 if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                 and n.targets[0].id in ('HOST', 'SSH_OPTIONS')}
    need(constants['HOST'] == HOST, 'WRONG_SSH_HOST')
    return constants['SSH_OPTIONS']


def ssh(options, *extra):
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T',
            *[v for o in options for v in ('-o', o)], *extra, HOST]


def stop_owned(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)


def remove_owned_passfile(path, identity):
    if path is None:
        return
    current = os.lstat(path)
    need((current.st_dev, current.st_ino, current.st_uid) == identity
         and stat.S_ISREG(current.st_mode), 'PASSFILE_REPLACED_NO_DELETE')
    os.unlink(path)  # Explicit user exception: ONLY this newly created file.
    need(not os.path.lexists(path), 'PASSFILE_CLEANUP_FAILED')


def run(args):
    need(args.read_only_check and sys.stdin.isatty(), 'SECURE_LOCAL_TTY_REQUIRED')
    need(not args.output.exists(), 'ONCE_ONLY_OUTPUT_EXISTS')
    # A create-only durable event file blocks accidental retry after interruption.
    event_path = args.output.with_suffix('.intent.jsonl')
    event_fd = os.open(event_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    def event(name, **fields):
        raw = (json.dumps({'utc': datetime.now(timezone.utc).isoformat(), 'event': name, **fields})+'\n').encode()
        os.write(event_fd, raw)
        os.fsync(event_fd)
    event('START', helper_sha256=sha(Path(__file__).read_bytes()), manifest_sha256=args.client_manifest_sha256)
    result = {'schema': 'TU1NZ_B_MAC_READER_CHECK_V1', 'status': 'HOLD', 'productive_rows_or_export': False}
    tunnel = source = None
    passfile = identity = None
    secret = raw_dsn = password = None
    try:
        verify_client(args.client_root, args.client_manifest, args.client_manifest_sha256)
        options = transport(args.transport)
        catalog = args.catalog.read_bytes()
        sql = metadata_sql(catalog)
        event('SOURCE_BOUND', catalog_sha256=sha(catalog), sql_sha256=sha(sql), remote_reader_sha256=sha(REMOTE_READ.encode()))
        vpn = json.loads(subprocess.check_output(['/opt/homebrew/bin/tailscale', 'status', '--json'], stderr=subprocess.DEVNULL, timeout=8))
        need(vpn['BackendState'] == 'Running' and any(p.get('Online') and '100.121.130.51' in p.get('TailscaleIPs', []) for p in vpn.get('Peer', {}).values()), 'VPN_NOT_CONFIRMED')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 15432))
        warnings.simplefilter('error', getpass.GetPassWarning)
        secret = getpass.getpass('chatops sudo — nur lokal verdeckt, genau vorhandene DB-DSN: ').encode()
        need(secret and not any(c in secret for c in (b'\n', b'\r')), 'LOCAL_AUTH_INPUT_INVALID')
        remote = 'LC_ALL=C '+shlex.join(['/usr/bin/sudo', '-S', '-k', '-p', '', '--', '/usr/bin/timeout', '--kill-after=3s', '10s', '/usr/bin/python3', '-I', '-B', '-S', '-c', REMOTE_READ])
        source = subprocess.Popen(ssh(options)+[remote], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        source.stdin.write(secret+b'\n')
        source.stdin.flush()
        secret = None
        raw_dsn, _ = source.communicate(timeout=25)
        need(source.returncode == 0, 'SOURCE_CREDENTIAL_READ_FAILED')
        values = parse_dsn(raw_dsn, args.client_root/'Contents/Versions/17/lib/libpq.5.dylib')
        actual_role = values.get('user', '')
        result['observed_dsn_role'] = actual_role if re.fullmatch('[a-z_][a-z0-9_]{0,62}', actual_role, re.I) else 'UNCLASSIFIED_IDENTIFIER'
        password = validate_dsn(values)
        event('DSN_EXPECTED_IDENTITY', database=DATABASE, role=ROLE)
        raw_dsn = values = None
        private_dir = Path(tempfile.mkdtemp(prefix='tu1nz-b-reader-', dir='/private/tmp'))
        need(private_dir.resolve().parent == Path('/private/tmp') and stat.S_IMODE(private_dir.stat().st_mode) == 0o700,
             'PRIVATE_NONSYNC_DIRECTORY_REQUIRED')
        passfile = private_dir/'pgpass'
        credential_fd = os.open(passfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        st = os.fstat(credential_fd)
        identity = (st.st_dev, st.st_ino, st.st_uid)
        event('TEMP_PASSFILE_CREATED', path=str(passfile), dev=st.st_dev, ino=st.st_ino, uid=st.st_uid)
        with os.fdopen(credential_fd, 'wb') as credential_stream:
            credential_stream.write(passfile_bytes(password))
            credential_stream.flush()
            os.fsync(credential_stream.fileno())
        password = None
        forwarded = tuple('ClearAllForwardings=no' if o == 'ClearAllForwardings=yes' else o for o in options)
        tunnel = subprocess.Popen(ssh(forwarded, '-v', '-N', '-o', 'ExitOnForwardFailure=yes', '-L', '127.0.0.1:15432:127.0.0.1:5432'), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        event('TUNNEL_STARTED', pid=tunnel.pid)
        deadline, debug = time.monotonic()+15, b''
        while b'Local forwarding listening on 127.0.0.1 port 15432.' not in debug:
            need(time.monotonic() < deadline and tunnel.poll() is None, 'TUNNEL_NOT_READY')
            if select.select([tunnel.stderr], [], [], 0.25)[0]:
                part = os.read(tunnel.stderr.fileno(), 16384)
                need(bool(part), 'TUNNEL_CLOSED')
                debug += part
        base = args.client_root/'Contents/Versions/17'
        command = ['/usr/bin/arch', '-arm64', str(base/'bin/psql'), '-X', '--no-password', '--quiet', '--tuples-only', '--no-align', '--set=ON_ERROR_STOP=1', '--set=VERBOSITY=sqlstate', '--host=127.0.0.1', '--port=15432', '--username='+ROLE, '--dbname='+DATABASE, '--file=-']
        p = subprocess.run(command, input=sql, capture_output=True, timeout=25, env=clean_environment(passfile, base, private_dir))
        need(p.returncode == 0, 'READER_LOGIN_OR_METADATA_FAILED')
        data = [json.loads(line) for line in p.stdout.decode().splitlines()]
        validate_observation(data, catalog)
        result.update(status='READER_METADATA_PASS_NOT_EXPORT_ADMISSION', observations=data,
                      database=DATABASE, role=ROLE, client_manifest_sha256=args.client_manifest_sha256)
        event('READER_METADATA_PASS')
    except Denied as exc:
        result['failure_code'] = str(exc)
    except BaseException as exc:
        result['failure_code'] = 'UNEXPECTED_'+type(exc).__name__
    finally:
        secret = raw_dsn = password = None
        for child in (source, tunnel):
            try:
                stop_owned(child)
            except BaseException:
                result.update(status='HOLD', process_cleanup_code='OWN_PROCESS_CLEANUP_FAILED')
        result['own_processes_ended'] = all(p is None or p.poll() is not None for p in (source, tunnel))
        if not result['own_processes_ended']:
            result['status'] = 'HOLD'
        try:
            remove_owned_passfile(passfile, identity)
            result['temporary_passfile_removed_or_not_created'] = True
        except BaseException:
            result.update(status='HOLD', cleanup_code='PASSFILE_CLEANUP_REQUIRES_OWNER', temporary_passfile_removed_or_not_created=False)
        if tunnel is not None:
            probe = subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP:15432', '-sTCP:LISTEN'], capture_output=True, timeout=5)
            result['listener_absent_after'] = probe.returncode == 1 and not probe.stdout
            if not result['listener_absent_after']:
                result['status'] = 'HOLD'
        event('FINISH', status=result['status'], own_processes_ended=result['own_processes_ended'], temporary_passfile_removed_or_not_created=result['temporary_passfile_removed_or_not_created'])
        os.close(event_fd)
        private_write(args.output, (json.dumps(result, indent=2)+'\n').encode())
    print(json.dumps({k: result[k] for k in ('status', 'failure_code', 'cleanup_code') if k in result}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-only-check', action='store_true')
    for name in ('client-root', 'client-manifest', 'transport', 'catalog', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--client-manifest-sha256', required=True)
    args = parser.parse_args()
    def interrupted(_number, _frame):
        raise InterruptedError('SIGNAL')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run(args)
    except BaseException as exc:
        # No traceback/subprocess error object/DSN may leave this CLI.
        print(json.dumps({'status': 'HOLD', 'failure_code': 'CLI_'+type(exc).__name__}))
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
