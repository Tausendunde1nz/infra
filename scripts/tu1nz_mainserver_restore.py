"""Finite Rev4 S7 restore primitives; import performs no access or effect.

The two-table logical backup is data, never executable Host SQL. Schema comes
only from the pinned private application Git objects. This module contains no
application DDL, credentials, network transport, production restore or retry.
Its local PostgreSQL child listens only in an owned private Unix directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

COMMIT = '93555d8a141caf8ace33522f9340d30bfc47d2bb'
TREE = '1e8a644115127818f394b6f9d24f31826e04ecba'
MIGRATIONS = {
    'migrations/0001_m1_core.sql': '89138dd33d3c8e21184a097813261f7cc7c3c27b385913b5de29df585004b271',
    'migrations/0021_commercial_s7_public_soft_launch.sql': 'a71350ae6d9ce544558ced38b0b032b28ac9885d0e3b4b9855e4c2db88d8b021'}
TABLES = ('commercial_s7_waitlist', 'commercial_s7_analytics_events')
FUNCTIONS = ('tu1nz_reject_append_only_mutation', 'tu1nz_s7_waitlist_binding_only')
RUNTIME_ROLE = 'tu1nz_adult_commercial_s3_runtime'
TEAM = 'ZF84SJ5A3G'
TOOLS = ('initdb', 'postgres', 'psql', 'pg_dump', 'pg_restore')
MAX_DATA = 128*1024*1024
MAX_CATALOG = 512*1024
MAX_ROWS = 1000000


class Denied(RuntimeError):
    """Fixed codes only; no SQL, private row, path or subprocess output."""


def need(value, code):
    if not value:raise Denied(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def private_read(path, limit):
    path = Path(path)
    need(path.resolve(strict=True) == path, 'PRIVATE_CANONICAL_PATH')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= limit, 'PRIVATE_INPUT_PROFILE')
        raw = os.pread(fd, s.st_size+1, 0)
        fields = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == s.st_size and all(tuple(getattr(v,k) for k in fields) ==
             tuple(getattr(s,k) for k in fields) for v in (os.fstat(fd),path.lstat())), 'PRIVATE_INPUT_CHANGED')
        return raw
    finally:os.close(fd)


def private_create(path, raw):
    path = Path(path)
    need(path.parent.resolve(strict=True) == path.parent and type(raw) is bytes, 'PRIVATE_OUTPUT_PARENT')
    p = path.parent.stat()
    need(p.st_uid == os.geteuid() and stat.S_IMODE(p.st_mode) == 0o700, 'PRIVATE_OUTPUT_DIRECTORY')
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw);handle.flush();os.fsync(handle.fileno())
    parent = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
    need(private_read(path, max(len(raw),1)) == raw, 'PRIVATE_OUTPUT_READBACK')


def bounded_process(argv, *, env, deadline, data=None, limit=MAX_CATALOG):
    """No shell; bounded stdout/stderr and only this owned child can be killed."""
    need(time.monotonic() < deadline and limit > 0, 'PROCESS_DEADLINE')
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, close_fds=True)
    selector = selectors.DefaultSelector(); out = bytearray(); err = bytearray(); offset = 0
    payload = memoryview(data or b'')
    try:
        for stream,name in ((child.stdout,'out'),(child.stderr,'err')):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        if payload:
            os.set_blocking(child.stdin.fileno(),False)
            selector.register(child.stdin,selectors.EVENT_WRITE,'in')
        else:child.stdin.close()
        while selector.get_map():
            need(time.monotonic() < deadline, 'PROCESS_DEADLINE')
            for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                if key.data == 'in':
                    offset += os.write(key.fileobj.fileno(),payload[offset:offset+65536])
                    if offset == len(payload):selector.unregister(key.fileobj);key.fileobj.close()
                    continue
                raw = os.read(key.fileobj.fileno(),65536)
                if not raw:selector.unregister(key.fileobj);continue
                target = out if key.data == 'out' else err;target.extend(raw)
                need(len(target) <= (limit if key.data == 'out' else 65536), 'PROCESS_OUTPUT_BOUND')
        status = child.wait(timeout=max(.001,deadline-time.monotonic()))
        return status,bytes(out),bytes(err)
    finally:
        selector.close();payload.release()
        if child.poll() is None:child.kill();child.wait(timeout=5)
        for stream in (child.stdin,child.stdout,child.stderr):
            if not stream.closed:stream.close()


def trusted_schema(application):
    """Extract known finite ranges from authenticated immutable Git objects.

    Neither the checkout's worktree nor a Host pg_dump schema is executed.
    Exact input hashes protect the delimiters; no general SQL parser is used.
    """
    prefix = ['/usr/bin/git','--no-optional-locks','--no-replace-objects','-c','core.fsmonitor=false',
              '-c','core.hooksPath=/dev/null','-C',str(application)]
    env = {'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
    def read(*args):
        code,out,_ = bounded_process([*prefix,*args],env=env,deadline=time.monotonic()+10)
        need(code == 0,'APPLICATION_GIT_READ');return out
    need(read('remote','get-url','origin').decode().strip() in (
        'https://github.com/Tausendunde1nz/adult-publishing-core.git',
        'https://github.com/Tausendunde1nz/adult-publishing-core',
        'git@github.com:Tausendunde1nz/adult-publishing-core.git') and
        read('rev-parse',COMMIT+'^{tree}').decode().strip() == TREE,'APPLICATION_ORIGIN')
    bodies = {p:read('show',COMMIT+':'+p) for p in MIGRATIONS}
    need(all(sha(bodies[p]) == expected for p,expected in MIGRATIONS.items()),'APPLICATION_MIGRATION_BYTES')
    core,s7 = bodies.values()
    append_only = core.split(b'CREATE FUNCTION tu1nz_guard_media_asset_identity()',1)[0]
    tables = s7.split(b'CREATE TABLE commercial_s7_content_templates',1)[0]
    need(append_only.startswith(b'BEGIN;\n\n') and tables.startswith(b'BEGIN;\n\n') and
         append_only.count(b'CREATE FUNCTION ') == 1 and tables.count(b'CREATE TABLE ') == 2 and
         tables.count(b'CREATE FUNCTION ') == 1,'APPLICATION_FINITE_DDL_BOUNDARY')
    ddl = b'BEGIN;\nSET LOCAL search_path=public,pg_catalog;\n'+append_only[8:]+tables[8:]+b'\nCOMMIT;\n'
    grant = re.findall(rb"EXECUTE 'GRANT SELECT, INSERT ON ([a-z0-9_, ]+) TO "+RUNTIME_ROLE.encode()+rb"';",s7)
    update = re.findall(rb"EXECUTE '(GRANT UPDATE \([a-z0-9_, ]+\) ON commercial_s7_waitlist TO "+
                        RUNTIME_ROLE.encode()+rb")';",s7)
    need(len(grant) == len(update) == 1 and set(TABLES) <=
         set(grant[0].decode().split(', ')),'APPLICATION_FINITE_GRANTS')
    grants = (('GRANT SELECT, INSERT ON '+', '.join('public.'+n for n in TABLES)+' TO '+RUNTIME_ROLE+';\n').encode()+
              update[0].replace(b' ON commercial_s7_waitlist ',b' ON public.commercial_s7_waitlist ')+b';\n')
    return ddl,grants,{'application_commit':COMMIT,'application_tree':TREE,'migration_sha256':MIGRATIONS,
                       'ddl_sha256':sha(ddl),'grants_sha256':sha(grants),
                       'tables':list(TABLES),'functions':list(FUNCTIONS)}


def catalog_sql():
    """Only two relations and their direct structural dependencies; no rows.

    Query under a read-only snapshot with search_path=pg_catalog. Definitions
    are digests to compare to the trusted local schema, not executable SQL.
    Unsupported sequences/custom types/defaults/rules/partitions/extensions
    remain explicit; no widening to a whole database or to other applications.
    """
    values = ','.join("('%s')" % n for n in TABLES)
    selected = "WITH wanted(name) AS (VALUES "+values+"), rel AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN wanted w ON w.name=c.relname WHERE n.nspname='public') "
    h = lambda expression:"encode(sha256(convert_to("+expression+",'UTF8')),'hex')"
    queries = [
        selected+"SELECT json_build_object('kind','relation','table',c.relname,'relation_kind',c.relkind,'persistence',c.relpersistence,'partition',c.relispartition,'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity,'replica_identity',c.relreplident,'options',c.reloptions,'tablespace_default',c.reltablespace=0,'owner',pg_get_userbyid(c.relowner),'acl',c.relacl::text) FROM rel c ORDER BY c.relname;",
        selected+"SELECT json_build_object('kind','column','table',c.relname,'position',a.attnum,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'type_schema',n.nspname,'type_kind',t.typtype,'not_null',a.attnotnull,'generated',a.attgenerated,'identity',a.attidentity,'collation',co.collname,'acl',a.attacl::text,'default_sha256',CASE WHEN d.oid IS NULL THEN NULL ELSE "+h('pg_get_expr(d.adbin,d.adrelid)')+" END) FROM rel c JOIN pg_attribute a ON a.attrelid=c.oid JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace n ON n.oid=t.typnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum LEFT JOIN pg_collation co ON co.oid=a.attcollation WHERE a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum;",
        selected+"SELECT json_build_object('kind','constraint','table',c.relname,'name',k.conname,'type',k.contype,'validated',k.convalidated,'deferrable',k.condeferrable,'deferred',k.condeferred,'target_schema',n.nspname,'target',r.relname,'definition_sha256',"+h('pg_get_constraintdef(k.oid)')+") FROM rel c JOIN pg_constraint k ON k.conrelid=c.oid LEFT JOIN pg_class r ON r.oid=k.confrelid LEFT JOIN pg_namespace n ON n.oid=r.relnamespace ORDER BY c.relname,k.conname;",
        selected+"SELECT json_build_object('kind','index','table',c.relname,'name',x.relname,'valid',i.indisvalid,'ready',i.indisready,'definition_sha256',"+h('pg_get_indexdef(i.indexrelid)')+") FROM rel c JOIN pg_index i ON i.indrelid=c.oid JOIN pg_class x ON x.oid=i.indexrelid ORDER BY c.relname,x.relname;",
        selected+"SELECT json_build_object('kind','trigger','table',c.relname,'name',t.tgname,'enabled',t.tgenabled,'function_schema',n.nspname,'function',p.proname,'definition_sha256',"+h('pg_get_triggerdef(t.oid)')+") FROM rel c JOIN pg_trigger t ON t.tgrelid=c.oid JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace WHERE NOT t.tgisinternal ORDER BY c.relname,t.tgname;",
        selected+"SELECT DISTINCT jsonb_build_object('kind','function','name',p.proname,'schema',n.nspname,'arguments',pg_get_function_identity_arguments(p.oid),'language',l.lanname,'security_definer',p.prosecdef,'settings',p.proconfig,'owner',pg_get_userbyid(p.proowner),'acl',p.proacl::text,'definition_sha256',"+h('pg_get_functiondef(p.oid)')+") FROM rel c JOIN pg_trigger t ON t.tgrelid=c.oid JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE NOT t.tgisinternal;",
        selected+"SELECT json_build_object('kind','sequence','table',c.relname,'name',q.relname) FROM rel c JOIN pg_depend d ON d.refclassid='pg_class'::regclass AND d.refobjid=c.oid AND d.classid='pg_class'::regclass AND d.deptype IN('a','i') JOIN pg_class q ON q.oid=d.objid WHERE q.relkind='S';",
        selected+"SELECT json_build_object('kind','inheritance','table',c.relname) FROM rel c JOIN pg_inherits i ON i.inhrelid=c.oid OR i.inhparent=c.oid;",
        selected+"SELECT json_build_object('kind','rule','table',c.relname,'name',r.rulename) FROM rel c JOIN pg_rewrite r ON r.ev_class=c.oid;",
        selected+"SELECT json_build_object('kind','incoming_fk','table',c.relname,'from_schema',n.nspname,'from_table',r.relname) FROM rel c JOIN pg_constraint k ON k.confrelid=c.oid JOIN pg_class r ON r.oid=k.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE k.contype='f' AND k.conrelid NOT IN(SELECT oid FROM rel);",
        selected+"SELECT json_build_object('kind','extension','table',c.relname,'name',e.extname) FROM rel c JOIN pg_depend d ON d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e' JOIN pg_extension e ON e.oid=d.refobjid;",
    ]
    return ('\n'.join(queries)+'\n').encode()


def catalog_transaction():
    return (b"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog; "
            b"SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='2s';\n"+
            catalog_sql()+b'ROLLBACK;\n')


def rights_sql():
    """Exact two-object rights, plus memberships/elevated flags of S7's role.

    No passwords/authid, role configuration values or unrelated table grants.
    This records actual effective rights; the caller compares to source-derived
    grants in the isolated restore. Unexpected current principals stay unknown.
    """
    values = ','.join("('%s')" % n for n in TABLES)
    selected = "WITH wanted(name) AS (VALUES "+values+"), rel AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN wanted w ON w.name=c.relname WHERE n.nspname='public') "
    role = "'"+RUNTIME_ROLE+"'"
    privilege = lambda fn,object,n:fn+'('+role+','+object+",'"+n+"')"
    pairs = ','.join("'"+n.lower()+"',"+privilege('has_table_privilege','c.oid',n)
                     for n in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'))
    columns = ','.join("'"+n.lower()+"',"+privilege('has_column_privilege','c.oid,a.attnum',n)
                       for n in ('SELECT','INSERT','UPDATE','REFERENCES'))
    queries = [
        "SELECT json_build_object('kind','runtime_role','name',rolname,'superuser',rolsuper,'create_db',rolcreatedb,'create_role',rolcreaterole,'replication',rolreplication,'bypass_rls',rolbypassrls,'inherit',rolinherit) FROM pg_roles WHERE rolname="+role+';',
        "SELECT json_build_object('kind','schema_rights','schema','public','usage',has_schema_privilege("+role+",'public','USAGE'),'create',has_schema_privilege("+role+",'public','CREATE'));",
        "SELECT json_build_object('kind','runtime_membership','name',rolname) FROM pg_roles WHERE rolname<>"+role+" AND pg_has_role("+role+",oid,'MEMBER') ORDER BY rolname;",
        selected+"SELECT json_build_object('kind','table_rights','table',c.relname,"+pairs+") FROM rel c ORDER BY c.relname;",
        selected+"SELECT json_build_object('kind','column_rights','table',c.relname,'column',a.attname,"+columns+") FROM rel c JOIN pg_attribute a ON a.attrelid=c.oid WHERE a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum;",
        selected+"SELECT json_build_object('kind','table_grant','table',c.relname,'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable) FROM rel c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) x;",
        selected+"SELECT json_build_object('kind','column_grant','table',c.relname,'column',a.attname,'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable) FROM rel c JOIN pg_attribute a ON a.attrelid=c.oid CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE a.attnum>0 AND NOT a.attisdropped;",
        selected+"SELECT DISTINCT jsonb_build_object('kind','function_grant','function',p.proname,'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable) FROM rel c JOIN pg_trigger t ON t.tgrelid=c.oid JOIN pg_proc p ON p.oid=t.tgfoid CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x WHERE NOT t.tgisinternal;",
    ]
    return ('\n'.join(queries)+'\n').encode()


def rights_transaction():
    return b'BEGIN READ ONLY; SET LOCAL search_path=pg_catalog;\n'+rights_sql()+b'ROLLBACK;\n'


def compare_restore_catalog(source_catalog, restored_catalog, source_rights, restored_rights):
    """Both structure AND actual bounded grants; never merely the owner-free hash."""
    expected = structural_catalog(restored_catalog)
    need(structural_catalog(source_catalog) == expected,'SOURCE_SCHEMA_DIFFERS_FROM_TRUSTED_RESTORE')
    def rows(raw):
        need(type(raw) is bytes and 0 < len(raw) <= MAX_CATALOG,'RIGHTS_RECORD_BOUND')
        values = [json.loads(line) for line in raw.splitlines()]
        need(0 < len(values) <= 256 and all(type(v) is dict for v in values),'RIGHTS_RECORD_BOUND')
        keys = sorted(canonical(v) for v in values)
        need(len(set(keys)) == len(keys),'RIGHTS_RECORD_DUPLICATE')
        return keys
    # Owners are part of the actual bounded dependency set. Production-role
    # LOGIN/authentication and privileged admin flags are NOT cloned; the
    # restore uses explicit NOLOGIN test counterparts and reports this limit.
    owner = lambda raw:sorted((r['kind'],r.get('table',r.get('name')),r['owner'])
                             for r in (json.loads(line) for line in raw.splitlines()) if 'owner' in r)
    need(owner(source_catalog) == owner(restored_catalog),'SOURCE_SCHEMA_OWNER_UNKNOWN')
    need(rows(source_rights) == rows(restored_rights),'SOURCE_RIGHTS_DIFFER_FROM_TRUSTED_RESTORE')
    return {'catalog_sha256':sha(canonical(expected)), 'source_catalog_sha256':sha(source_catalog),
            'restore_catalog_sha256':sha(restored_catalog), 'rights_sha256':sha(b'\n'.join(rows(source_rights))),
            'role_model':'SAME_OBJECT_GRANTS_NOLOGIN_TEST_ROLES_NOT_PRODUCTION_AUTHENTICATION',
            'sequences':'NONE_IN_ACTUAL_AND_TRUSTED_SCHEMA', 'not_production_restore_permission':True}


def fingerprint_sql(table, layout):
    need(table in TABLES and set(layout) == set(TABLES) and layout[table] and
         all(re.fullmatch('[a-z][a-z0-9_]{0,62}',n) for n in layout[table]),'FINGERPRINT_LAYOUT')
    return ("SET LOCAL TimeZone='UTC'; COPY (SELECT to_jsonb(t)::text FROM public."+table+
            ' t ORDER BY t.'+layout[table][0]+') TO STDOUT WITH (FORMAT text);\n').encode()


def fingerprint(raw):
    need(type(raw) is bytes and len(raw) <= MAX_DATA and (not raw or raw.endswith(b'\n')) and
         raw.count(b'\n') <= MAX_ROWS,'FINGERPRINT_BOUND')
    return {'bytes':len(raw),'rows':raw.count(b'\n'),'sha256':sha(raw)}


class ReadOnlySnapshot:
    """One held exported snapshot, two-table reads only; no reconnect/retry.

    Outer reviewed preparation owns authentication, fixed transport/identity,
    capacity and private custody. No DSN or password is placed in an argument.
    Production role must be the actual restricted S7 role, not a backup admin.
    """
    def __init__(self, base, env, *, deadline):
        self.base = Path(base);self.env = dict(env);self.deadline = deadline
        self.child = None;self.token = None;self.started = False
        self.env['PGOPTIONS'] = ('-c default_transaction_read_only=on -c statement_timeout=10000 '
            '-c lock_timeout=2000 -c idle_in_transaction_session_timeout=300000 -c search_path=pg_catalog '
            '-c TimeZone=UTC -c jit=off')

    def start(self, *, database, role):
        need(not self.started and time.monotonic() < self.deadline,'SNAPSHOT_REENTRY_OR_DEADLINE')
        self.started = True
        self.child = subprocess.Popen(['/usr/bin/arch','-arm64',str(self.base/'bin/psql'),'-X','-qAt',
            '--no-password','--set=ON_ERROR_STOP=1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=self.env,close_fds=True)
        sql = (b"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog; "
               b"SELECT json_build_object('snapshot',pg_export_snapshot(),'database',current_database(),"
               b"'role',current_user,'session_role',session_user,'readonly',current_setting('transaction_read_only'),"
               b"'version',current_setting('server_version_num'));\n")
        self.child.stdin.write(sql);self.child.stdin.flush()
        selector = selectors.DefaultSelector();out = bytearray();err = bytearray()
        ready = min(self.deadline,time.monotonic()+10)
        try:
            for stream,name in ((self.child.stdout,'out'),(self.child.stderr,'err')):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
            while not out.endswith(b'\n'):
                need(time.monotonic() < ready and self.child.poll() is None,'SNAPSHOT_NOT_READY')
                for key,_ in selector.select(.05):
                    raw = os.read(key.fileobj.fileno(),4096)
                    need(raw,'SNAPSHOT_PIPE_CLOSED')
                    target = out if key.data == 'out' else err;target.extend(raw)
                    need(len(out) <= 4096 and not err,'SNAPSHOT_OUTPUT_UNKNOWN')
            result = json.loads(out)
            need(set(result) == {'snapshot','database','role','session_role','readonly','version'} and
                 result['database'] == database and result['role'] == result['session_role'] == role and
                 result['readonly'] == 'on' and result['version'] == '170011' and
                 re.fullmatch('[0-9A-F]{8}-[0-9A-F]{8}-[0-9]+',result['snapshot']),
                 'SNAPSHOT_IDENTITY_OR_VERSION')
            self.token = result['snapshot'];return result
        finally:selector.close()

    def read(self, kind, layout=None, table=None):
        need(self.token is not None and self.child.poll() is None,'SNAPSHOT_NOT_LIVE')
        if kind == 'catalog':sql = catalog_sql();limit = MAX_CATALOG
        elif kind == 'rights':sql = rights_sql();limit = MAX_CATALOG
        elif kind == 'fingerprint':sql = fingerprint_sql(table,layout);limit = MAX_DATA
        else:raise Denied('SNAPSHOT_READ_KIND')
        data = ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '"+
                self.token+"'; SET LOCAL search_path=pg_catalog;\n").encode()+sql+b'ROLLBACK;\n'
        code,out,err = bounded_process(['/usr/bin/arch','-arm64',str(self.base/'bin/psql'),'-X','-qAt',
            '--no-password','--set=ON_ERROR_STOP=1','--file=-'],env=self.env,deadline=self.deadline,data=data,limit=limit)
        need(code == 0 and not err and self.child.poll() is None,'SNAPSHOT_READ_FAILED')
        return out

    def dump(self):
        need(self.token is not None and self.child.poll() is None,'SNAPSHOT_NOT_LIVE')
        code,out,err = bounded_process(['/usr/bin/arch','-arm64',str(self.base/'bin/pg_dump'),
            '--format=custom','--data-only','--no-owner','--no-privileges','--no-blobs','--strict-names',
            '--lock-wait-timeout=5000','--snapshot='+self.token,*['--table=public.'+n for n in TABLES]],
            env=self.env,deadline=self.deadline,limit=MAX_DATA)
        need(code == 0 and not err and out.startswith(b'PGDMP') and self.child.poll() is None,'SNAPSHOT_DUMP_FAILED')
        return out

    def close(self):
        if self.child is None:return
        try:
            need(self.child.poll() is None,'SNAPSHOT_LOST_BEFORE_CLOSE')
            self.child.stdin.write(b'ROLLBACK;\n\\q\n');self.child.stdin.flush();self.child.stdin.close()
            self.child.wait(timeout=5)
            need(self.child.returncode == 0,'SNAPSHOT_CLOSE_UNCONFIRMED')
        finally:
            if self.child.poll() is None:self.child.kill();self.child.wait(timeout=5)
            for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
                if not stream.closed:stream.close()


def verify_local_tools(base, client_closure):
    """Reuse the already verified eight-member client closure plus signatures.

    postgres/initdb are actual signed members of the same pre-existing App.
    Their observed hashes join the new proof; no download or installer exists.
    The independently reviewed outer input binds this closure's exact bytes.
    """
    base = Path(base)
    need(sys.platform == 'darwin' and os.uname().machine == 'arm64' and
         base.resolve(strict=True) == base,'LOCAL_TOOL_PLATFORM')
    need(type(client_closure) is dict and client_closure.get('signer_team') == TEAM and
         type(client_closure.get('members')) is dict,'LOCAL_CLIENT_CLOSURE_SCHEMA')
    members = client_closure['members']
    expected = {'bin/psql','bin/pg_dump','bin/pg_restore','lib/libpq.5.dylib','lib/libcrypto.3.dylib',
                'lib/libssl.3.dylib','lib/liblz4.1.10.0.dylib','lib/libzstd.1.5.7.dylib'}
    prefix = 'Contents/Versions/17/'
    need(set(members) == {prefix+n for n in expected},'LOCAL_CLIENT_CLOSURE_MEMBERS')
    hashes = {}
    for relative in sorted(expected | {'bin/initdb','bin/postgres'}):
        path = base/relative
        actual = path.resolve(strict=True)
        need(actual.is_relative_to(base),'LOCAL_TOOL_OUTSIDE_APP')
        raw = actual.read_bytes();digest = sha(raw)
        if relative in expected:need(digest == members[prefix+relative]['sha256'],'LOCAL_CLOSED_TOOL_CHANGED')
        code,_,_ = bounded_process(['/usr/bin/codesign','--verify','--strict','-R',
            '=anchor apple generic and certificate leaf[subject.OU] = "'+TEAM+'"',str(actual)],
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},deadline=time.monotonic()+10)
        need(code == 0,'LOCAL_TOOL_SIGNATURE')
        hashes[relative] = digest
    return hashes


def structural_catalog(raw):
    """Preserve actual authority metadata separately; never map it to trusted.

    The structural comparison excludes owner/ACL ONLY. The caller must bind
    and independently validate the actual rights and restore them as NOLOGIN
    roles in the private test. A match here alone is not V3/V4 acceptance.
    """
    need(type(raw) is bytes and 0 < len(raw) <= MAX_CATALOG,'CATALOG_BOUND')
    rows = [json.loads(line) for line in raw.splitlines()]
    need(0 < len(rows) <= 256 and all(type(r) is dict for r in rows),'CATALOG_RECORD_BOUND')
    allowed = {'relation','column','constraint','index','trigger','function'}
    need(all(r.get('kind') in allowed for r in rows),'UNSUPPORTED_SCHEMA_DEPENDENCY')
    relations = [r for r in rows if r['kind'] == 'relation']
    need(len(relations) == 2 and {r['table'] for r in relations} == set(TABLES),'RELATION_SET')
    need(all(r['relation_kind'] == 'r' and r['persistence'] == 'p' and not r['partition'] and
             not r['rls'] and not r['force_rls'] and r['options'] is None and r['tablespace_default']
             for r in relations),'RELATION_PROFILE')
    functions = [r for r in rows if r['kind'] == 'function']
    need(len(functions) == 2 and {r['name'] for r in functions} == set(FUNCTIONS) and all(
        r['schema'] == 'public' and r['arguments'] == '' and r['language'] == 'plpgsql' and
        r['security_definer'] is False and r['settings'] is None for r in functions),'FUNCTION_PROFILE')
    columns = [r for r in rows if r['kind'] == 'column']
    need(all(r['table'] in TABLES and r['type_schema'] == 'pg_catalog' and r['type_kind'] == 'b' and
        r['default_sha256'] is None and r['generated'] == r['identity'] == '' for r in columns),
        'COLUMN_DEPENDENCY_UNSUPPORTED')
    need(all(r['validated'] for r in rows if r['kind'] == 'constraint') and
         all(r['valid'] and r['ready'] for r in rows if r['kind'] == 'index'),'CONSTRAINT_OR_INDEX_NOT_VALID')
    normalized = [{k:v for k,v in r.items() if k not in ('owner','acl')} for r in rows]
    keys = [canonical(r) for r in normalized]
    need(len(set(keys)) == len(keys),'DUPLICATE_CATALOG_ROW')
    return sorted(normalized,key=canonical)


def copy_layout(trusted_catalog):
    result = {}
    for table in TABLES:
        rows = sorted((r for r in trusted_catalog if r['kind'] == 'column' and r['table'] == table),
                      key=lambda r:r['position'])
        need(0 < len(rows) <= 32 and [r['position'] for r in rows] == list(range(1,len(rows)+1)) and
             all(re.fullmatch('[a-z][a-z0-9_]{0,62}',r['name']) for r in rows),'TRUSTED_COLUMN_LAYOUT')
        result[table] = tuple(r['name'] for r in rows)
    return result


def extract_copy_data(rendered, layout):
    """Reject executable archive SQL; only COPY rows for the exact two layouts.

    Returned rows are later fed through psql's file-backed COPY protocol, not
    interpreted as a SQL script or psql commands. Even a forged custom archive
    cannot contribute SET/COPY PROGRAM/DDL/function instructions to restore.
    """
    need(type(rendered) is bytes and 0 < len(rendered) <= MAX_DATA and set(layout) == set(TABLES),
         'DUMP_RENDER_BOUND')
    headers = {('COPY public.'+table+' ('+', '.join(layout[table])+') FROM stdin;').encode():table for table in TABLES}
    settings = {b'SET statement_timeout = 0;',b'SET lock_timeout = 0;',b'SET idle_in_transaction_session_timeout = 0;',
                b'SET transaction_timeout = 0;',b"SET client_encoding = 'UTF8';",b'SET standard_conforming_strings = on;',
                b"SELECT pg_catalog.set_config('search_path', '', false);",b'SET check_function_bodies = false;',
                b'SET xmloption = content;',b'SET client_min_messages = warning;',b'SET row_security = off;'}
    copies = {}; active = None; buffer = bytearray(); rows = 0; restrict = None; unrestricted = False
    for line in rendered.splitlines(keepends=True):
        need(line.endswith(b'\n') and b'\x00' not in line,'DUMP_LINE_FORMAT')
        value = line[:-1]
        if active is not None:
            if value == b'\\.':
                copies[active] = {'data':bytes(buffer),'rows':rows};active = None;buffer.clear();rows = 0
            else:
                rows += 1;need(rows <= MAX_ROWS,'DUMP_ROW_BOUND');buffer.extend(line)
            continue
        if not value or value.startswith(b'--'):continue
        if value in settings:continue
        if re.fullmatch(rb'\\restrict [A-Za-z0-9]{1,128}',value):
            need(restrict is None and not copies,'DUMP_RESTRICT_ORDER');restrict = value.split()[1];continue
        if value.startswith(b'\\unrestrict '):
            need(restrict is not None and value == b'\\unrestrict '+restrict and
                 set(copies) == set(TABLES) and not unrestricted,'DUMP_UNRESTRICT_ORDER')
            unrestricted = True;continue
        need(value in headers and not unrestricted,'DUMP_UNTRUSTED_SQL')
        active = headers[value];need(active not in copies,'DUMP_DUPLICATE_TABLE')
    need(active is None and set(copies) == set(TABLES) and (restrict is None or unrestricted),
         'DUMP_COPY_INCOMPLETE')
    return copies


class PrivatePostgres:
    """One new owned local restore process; no service manager or TCP socket.

    directory/socket are create-only children of approved private custody or a
    synthetic native fixture. Caller binds actual tool hashes/signatures first.
    close() targets only its unreaped child and retains all private test files.
    """
    def __init__(self, base, directory, socket, *, deadline):
        self.base,self.root,self.socket = Path(base),Path(directory),Path(socket)
        self.deadline = deadline;self.child = None;self.log = None;self.created = False
        need(sys.platform == 'darwin' and os.geteuid() != 0,'LOCAL_MAC_NONROOT_REQUIRED')
        need(len(str(self.socket).encode()) < 85 and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(self.socket)) and
             re.fullmatch(r'/[A-Za-z0-9_./-]+',str(self.root)),'LOCAL_SOCKET_OR_PATH_BOUND')
        for directory in (self.root,self.socket):
            need(directory.parent.resolve(strict=True) == directory.parent,'LOCAL_CANONICAL_PARENT')
            s = directory.parent.stat()
            need(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700,'LOCAL_PRIVATE_PARENT')
        self.env = {'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null',
                    'PGHOST':str(self.socket),'PGPORT':'35433','PGUSER':'tu1nz_restore_owner','PGDATABASE':'postgres',
                    'PGSERVICEFILE':'/dev/null','PGPASSFILE':str(self.root/'absent-pgpass'),'PGCONNECT_TIMEOUT':'2'}

    def call(self, name, options, data=None, limit=MAX_CATALOG):
        need(name in TOOLS,'LOCAL_TOOL_SET')
        return bounded_process(['/usr/bin/arch','-arm64',str(self.base/'bin'/name),*options],
                               env=self.env,deadline=self.deadline,data=data,limit=limit)

    def query(self, sql, *, expect_error=None):
        need(expect_error is None or (type(expect_error) is str and re.fullmatch('[0-9A-Z]{5}',expect_error)),
             'LOCAL_EXPECTED_SQLSTATE')
        code,out,err = self.call('psql',['-X','-qAt','--no-password','--set=ON_ERROR_STOP=1',
                                        '--set=VERBOSITY=sqlstate','--file=-'],sql)
        # Connection failure, timeout or a different SQL error is never a
        # successful negative rights/constraint test. psql --file=- reports
        # the source line prefix even in sqlstate verbosity.
        if expect_error is not None:
            need(code == 3 and re.fullmatch(rb'psql:<stdin>:[0-9]+: ERROR:  '+expect_error.encode()+rb'\n',err),
                 'LOCAL_NEGATIVE_SQLSTATE_NOT_PROVED')
        else:need(code == 0 and not err,'LOCAL_SQL_RESULT')
        return out

    def install_known_owner_profile(self):
        """Local NOLOGIN counterpart of the historically observed S7 owner.

        This is a candidate profile, never proof of today's production rights.
        The actual source owner/grant comparisons remain unchanged and exact.
        No production identity, LOGIN or elevated flags are copied.
        """
        need(self.created and self.child is not None and self.child.poll() is None and
             self.env['PGHOST']==str(self.socket) and self.env['PGUSER']=='tu1nz_restore_owner' and
             not getattr(self,'owner_profile_installed',False),'LOCAL_OWNER_PROFILE_ENTRY')
        self.owner_profile_installed=True
        self.query(b'CREATE ROLE tu1nz_adult_commercial_s3_migrator NOLOGIN NOSUPERUSER NOCREATEDB '
            b'NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n'
            b'GRANT USAGE, CREATE ON SCHEMA public TO tu1nz_adult_commercial_s3_migrator;\n'
            b'ALTER FUNCTION public.tu1nz_reject_append_only_mutation() OWNER TO tu1nz_adult_commercial_s3_migrator;\n'
            b'SET ROLE tu1nz_adult_commercial_s3_migrator;\n'
            b'GRANT EXECUTE ON FUNCTION public.tu1nz_reject_append_only_mutation() TO tu1nz_adult_commercial_s3_runtime;\n'
            b'RESET ROLE;\n'
            b'REVOKE CREATE ON SCHEMA public FROM tu1nz_adult_commercial_s3_migrator;\n')

    def start(self):
        need(not self.created,'LOCAL_SERVER_REENTRY');self.created = True
        self.root.mkdir(mode=0o700);self.socket.mkdir(mode=0o700)
        need(not os.path.lexists(self.env['PGPASSFILE']),'LOCAL_PASSWORD_FILE_UNEXPECTED')
        code,_,_ = self.call('initdb',['-D',str(self.root/'pgdata'),'--username=tu1nz_restore_owner',
            '--auth-local=trust','--auth-host=reject','--encoding=UTF8','--no-locale','--no-instructions'])
        need(code == 0,'LOCAL_INITDB')
        fd = os.open(self.root/'server.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.log = os.fdopen(fd,'wb')
        self.child = subprocess.Popen(['/usr/bin/arch','-arm64',str(self.base/'bin/postgres'),'-D',str(self.root/'pgdata'),
            '-c','listen_addresses=','-c','unix_socket_directories='+str(self.socket),'-c','unix_socket_permissions=0700',
            '-p','35433','-c','autovacuum=off','-c','shared_buffers=16MB','-c','max_connections=6',
            '-c','shared_preload_libraries=','-c','session_preload_libraries=','-c','local_preload_libraries=',
            '-c','jit=off','-c','log_statement=none','-c','log_min_error_statement=panic',
            '-c','log_parameter_max_length=0','-c','log_parameter_max_length_on_error=0'],
            stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,env=self.env,close_fds=True)
        ready_deadline = min(self.deadline,time.monotonic()+10)
        while not (self.socket/'.s.PGSQL.35433').exists():
            need(self.child.poll() is None and time.monotonic() < ready_deadline,'LOCAL_SERVER_NOT_READY')
            time.sleep(.02)
        answer = self.query(b"SELECT current_setting('listen_addresses'),current_setting('unix_socket_directories'),current_setting('port');\n")
        need(answer == ('|'+str(self.socket)+'|35433\n').encode(),'LOCAL_SERVER_ISOLATION')

    def restore_copies(self, copies, layout):
        need(set(copies) == set(TABLES) and set(layout) == set(TABLES),'RESTORE_TABLE_SET')
        for table in TABLES:  # parent before the child, with FK already active
            raw = copies[table]['data'];need(len(raw) <= MAX_DATA,'RESTORE_COPY_BOUND')
            path = self.root/(table+'.copy')
            # Empty tables have a real zero-byte COPY file and zero imported
            # rows, not an omitted table or an invented successful import.
            fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            need(path.read_bytes() == raw,'RESTORE_COPY_READBACK')
            need(all(re.fullmatch('[a-z][a-z0-9_]{0,62}',n) for n in layout[table]),'RESTORE_COLUMNS')
            sql = ("\\copy public."+table+' ('+', '.join(layout[table])+") FROM '"+str(path)+"' WITH (FORMAT text)\n").encode()
            self.query(sql)
            count = self.query(('SELECT count(*) FROM public.'+table+';\n').encode())
            need(count == (str(copies[table]['rows'])+'\n').encode(),'RESTORE_ROW_COUNT')

    def close(self):
        try:
            if self.child is not None and self.child.poll() is None:
                self.child.send_signal(signal.SIGINT)  # fast stop of this unreaped child only
                try:self.child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.child.kill();self.child.wait(timeout=5)
                    raise Denied('LOCAL_SERVER_REQUIRED_FORCED_STOP') from None
            if self.child is not None:
                need(self.child.returncode == 0 and not (self.socket/'.s.PGSQL.35433').exists(),
                     'LOCAL_SERVER_CLEANUP_UNCONFIRMED')
        finally:
            if self.log is not None:self.log.close()
