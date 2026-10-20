#!/usr/bin/env python3
"""One fixed B PRECOPY coordinator. Inert unless --execute + external approval.

Standard native PG clients do all DB work. No restore/Host/writer capability.
Never print child stdout/stderr, business rows or credentials. No retry/delete
except precisely this attempt's new temporary credential file, inode-bound.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import warnings

sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_b_mac_reader as m
import tu1nz_b_data_handoff as b
from tu1nz_b_precopy_catalog import catalog_sql

ID='B-PRECOPY-20261019-1'
SUFFIX='public-production-host-r4-20261017/b-data-writer-source-20261018/dependency-extension-20261018T131302Z/fixture-fix-20261018T141735Z/B-PG17-MAC-ADMISSION-1'
STAGE=Path('/Users/daniel/Developer/tu1nz')/SUFFIX
BACKUP=Path('/Users/daniel/.codex/backups')/SUFFIX
TARGETS=(STAGE/'export-data'/ID,BACKUP/'export-data'/ID)
CLIENT_SHA='03436d097cbca3b80f7599f00a9681bbae803ecfd49ec39d029e6a5569a57f9f'
SELECTION_SHA='0088b148a7f9207c3d7d008dddbef98252ea7bc0ca996c7e86bf93b56a8ca01d'
REFERENCE_SHA='5b2a6bf3760c8bdd69d08bc2835700862b0fabb5033aef92bdacd8cdb10aeca4'
PACKAGE_CAP=256*1024*1024
RESERVE=1024*1024*1024
WIRE_CAP=512*1024*1024
SCHEMA_CAP=4*1024*1024
CAPTURE_CAP=8*1024*1024
SETTING_NAMES=frozenset(('jit','local_preload_libraries','shared_preload_libraries',
                         'session_preload_libraries','dynamic_library_path'))
# Only these three were explicitly not visible in the bound Reader reference.
# Unknown is an observation state, never an empty or proven-unchanged value.
UNKNOWN_SETTINGS=frozenset(('shared_preload_libraries','session_preload_libraries',
                           'dynamic_library_path'))

def need(x,code):
    if not x:raise m.Denied(code)

def new_file(path,raw):
    m.private_write(path,raw)

def setting_observations(rows):
    settings={}
    for row in rows:
        if row.get('kind')!='safe_setting_meta':continue
        need(set(row)=={'kind','name','value','source'} and row['name'] in SETTING_NAMES
             and row['name'] not in settings,'SETTING_METADATA_SHAPE')
        need(type(row['value']) is str and type(row['source']) is str
             and bool(row['source']),'SETTING_METADATA_MISSING')
        settings[row['name']]=dict(row)
    need(SETTING_NAMES-UNKNOWN_SETTINGS<=settings.keys(),'REQUIRED_SETTING_MISSING')
    return [settings[name] if name in settings else
            {'kind':'safe_setting_meta','name':name,'observation':'UNKNOWN_NOT_VISIBLE'}
            for name in sorted(SETTING_NAMES)]

def normalized(rows):
    # Identity is checked separately; only physical size is omitted from the
    # bound metadata. Preserve settings, including explicit unknown visibility.
    keep={'database_meta','column_meta','constraint_meta','index_meta','trigger_meta',
          'function_meta','relation_meta','incoming_fk_meta','attached_extension_meta',
          'owner_role_meta','relation','role','sequence'}
    out=[{k:v for k,v in r.items() if k!='total_bytes'} for r in rows if r.get('kind') in keep]
    out.extend(setting_observations(rows))
    return sorted(out,key=lambda r:json.dumps(r,sort_keys=True,separators=(',',':')))

def sync_directories(at,paths):
    for path in dict.fromkeys(paths):
        at.left()
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            bound=os.fstat(fd);current=path.lstat()
            need(stat.S_ISDIR(current.st_mode) and (bound.st_dev,bound.st_ino)==
                 (current.st_dev,current.st_ino),'SYNC_DIRECTORY_REBOUND')
            os.fsync(fd)
            current=path.lstat()
            need((bound.st_dev,bound.st_ino)==(current.st_dev,current.st_ino),
                 'SYNC_DIRECTORY_REBOUND')
        finally:os.close(fd)
        at.left()

def persist_bindings(at,receiptpath,receipt_raw,manifestpath,manifest_raw):
    new_file(receiptpath,receipt_raw)
    new_file(manifestpath,manifest_raw)
    sync_directories(at,(receiptpath.parent,manifestpath.parent))

def approval(raw,now):
    a=b.parse(raw)
    b.fields(a,('schema','capture_id','window_start','window_end','source_commit',
                'source_tree','selection_sha256','schema_reference_sha256',
                'client_manifest_sha256','targets','same_volume_risk_accepted'))
    need(a['schema']=='TU1NZ_B_PRECOPY_EXECUTION_WINDOW_V1' and a['capture_id']==ID,'WRONG_CAPTURE')
    need(a['selection_sha256']==SELECTION_SHA and a['schema_reference_sha256']==REFERENCE_SHA
         and a['client_manifest_sha256']==CLIENT_SHA,'APPROVAL_BINDINGS')
    need(a['targets']==list(map(str,TARGETS)) and a['same_volume_risk_accepted'] is True,'CUSTODY_APPROVAL')
    for k in ('source_commit','source_tree'):need(re.fullmatch('[a-f0-9]{40}',a[k] or ''),'SOURCE_PIN')
    start,end=(datetime.fromisoformat(a[k]) for k in ('window_start','window_end'))
    need(start.tzinfo is not None and end.tzinfo is not None and 300<=(end-start).total_seconds()<=900,'WINDOW_RANGE')
    need(start<=now<end,'WINDOW_CLOSED')
    return a,end

def ancestors(path,mac_acl=False):
    for p in reversed((path,*path.parents)):
        s=p.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.geteuid())
             and not stat.S_IMODE(s.st_mode)&0o022,'UNSAFE_ANCESTOR')
        if mac_acl:
            q=subprocess.run(['/bin/ls','-lde',str(p)],capture_output=True,timeout=5,
                             env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            need(q.returncode==0 and all(re.fullmatch(r'\s*\d+: group:everyone deny delete\s*',l)
                 for l in q.stdout.decode().splitlines()[1:]),'ANCESTOR_ACL')
    need(path.stat().st_uid==os.geteuid() and stat.S_IMODE(path.stat().st_mode)==0o700,'PRIVATE_PARENT')

class Attempt:
    def __init__(self,journal,deadline,targets):
        self.fd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.deadline=deadline;self.targets=targets;self.children=[];self.wire=0
        self.written=0;self.copied=0
        self.event('ATTEMPT_CONSUMED',capture_id=ID)
        parent=os.open(Path(journal).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    def event(self,name,**fields):
        raw=(json.dumps({'utc':datetime.now(timezone.utc).isoformat(),'event':name,**fields})+'\n').encode()
        need(os.write(self.fd,raw)==len(raw),'JOURNAL_SHORT_WRITE');os.fsync(self.fd)
    def left(self):
        left=self.deadline-time.monotonic();need(left>0,'DEADLINE');return left
    def room(self):
        self.left()
        # Shared-filesystem remaining budget is counted ONCE for BOTH copies.
        remaining=max(0,2*PACKAGE_CAP-self.written-self.copied)
        for target in self.targets:
            v=os.statvfs(target.parent)
            need(v.f_bavail*v.f_frsize>=RESERVE+remaining,'RESERVE_HOLD')
    def spawn(self,argv,env,stdin=subprocess.PIPE,stderr=subprocess.DEVNULL):
        self.left()
        child=subprocess.Popen(argv,stdin=stdin,stdout=subprocess.PIPE,stderr=stderr,env=env)
        self.children.append(child)
        # Always durable BEFORE a credential/SQL is written into this child.
        self.event('CHILD_STARTED',pid=child.pid,parent_pid=os.getpid(),argv_sha256=m.sha(json.dumps(argv).encode()))
        return child
    def pump(self,argv,env,sql,limit,path=None):
        self.room()
        p=self.spawn(argv,env)
        result=bytearray();h=hashlib.sha256();size=0;fd=None
        try:
            if path is not None:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with selectors.DefaultSelector() as ready:
                ready.register(p.stdout,selectors.EVENT_READ)
                pending=memoryview(sql)
                if pending:
                    os.set_blocking(p.stdin.fileno(),False)
                    ready.register(p.stdin,selectors.EVENT_WRITE)
                else:p.stdin.close()
                eof=False
                while not eof:
                    self.left()
                    for key,_ in ready.select(min(0.2,self.left())):
                        if key.fileobj is p.stdin:
                            pending=pending[os.write(p.stdin.fileno(),pending[:4096]):]
                            if not pending:ready.unregister(p.stdin);p.stdin.close()
                            continue
                        chunk=os.read(p.stdout.fileno(),65536)
                        if not chunk:eof=True;break
                        size+=len(chunk);self.wire+=len(chunk)
                        need(size<=limit and self.wire<=WIRE_CAP,'STREAM_LIMIT')
                        self.room();h.update(chunk)
                        if fd is not None:
                            need(self.written+len(chunk)<=PACKAGE_CAP,'PACKAGE_LIMIT')
                            need(os.write(fd,chunk)==len(chunk),'OUTPUT_SHORT_WRITE')
                            self.written+=len(chunk);self.room()
                        elif limit<=CAPTURE_CAP:result.extend(chunk)
            need(p.wait(timeout=self.left())==0,'PG_TOOL_FAILED')
            if fd is not None:os.fsync(fd)
            return bytes(result),h.hexdigest(),size
        finally:
            if fd is not None:os.close(fd)
            m.stop_owned(p)
            for stream in (p.stdin,p.stdout,p.stderr):
                if stream is not None and not stream.closed:stream.close()
    def close_children(self):
        failed=False
        for p in self.children:
            try:m.stop_owned(p)
            except BaseException:failed=True
        need(not failed and all(p.poll() is not None for p in self.children),'CHILD_CLEANUP')
    def close(self):
        try:self.close_children()
        finally:os.close(self.fd)

def cleanup(at,credential,identity,tunnel,status):
    # Independent best-effort actions: one child failure must never skip the
    # precisely authorized credential removal or other owned-child attempts.
    errors=[]
    for child in at.children:
        try:m.stop_owned(child)
        except BaseException:errors.append('CHILD_STOP')
    try:m.remove_owned_passfile(credential,identity)
    except BaseException:errors.append('CREDENTIAL_CLEANUP')
    if tunnel is not None:
        try:
            p=subprocess.run(['/usr/sbin/lsof','-nP','-iTCP:15432','-sTCP:LISTEN'],capture_output=True,timeout=5)
            need(p.returncode==1 and not p.stdout,'LISTENER_CLEANUP')
        except BaseException:errors.append('LISTENER_CLEANUP')
    try:need(all(p.poll() is not None for p in at.children),'CHILD_CLEANUP')
    except BaseException:errors.append('CHILD_CLEANUP')
    try:
        if status=='PRECOPY_BYTES_CHECKED_NOT_RESTORED':at.left()
    except BaseException:errors.append('DEADLINE')
    try:at.close_children()
    except BaseException:errors.append('FINAL_CHILD_CLEANUP')
    try:
        at.event('FINISH',status='PARTIAL_HOLD' if errors else status,
                 own_children_ended=not any(e.startswith('CHILD') for e in errors),
                 temporary_credential_removed='CREDENTIAL_CLEANUP' not in errors,
                 cleanup_errors=errors)
    except BaseException:errors.append('JOURNAL_CLEANUP')
    try:os.close(at.fd)
    except BaseException:errors.append('JOURNAL_FD_CLEANUP')
    need(not errors,'CLEANUP_HOLD')

SETTINGS="SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'; SET LOCAL DateStyle='ISO,YMD'; SET LOCAL bytea_output='hex'; SET LOCAL extra_float_digits=3; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='5s';"

def snapshot_sql(token,body):
    need(re.fullmatch('[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+',token or ''),'SNAPSHOT_TOKEN')
    return ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '"+token+"';"+SETTINGS+body+'COMMIT;\n').encode()

def table_fingerprint(at,psql,env,token,name):
    need(re.fullmatch('commercial_[a-z0-9_]+',name) is not None,'TABLE_IDENTIFIER')
    raw,_,_=at.pump(psql,env,snapshot_sql(token,'SELECT count(*) FROM ONLY public."'+name+'";'),128)
    need(re.fullmatch(b'[0-9]+\n',raw) is not None,'COUNT_SHAPE')
    body='COPY (SELECT row_to_json(t)::text FROM ONLY public."'+name+'" t ORDER BY row_to_json(t)::text COLLATE "C") TO STDOUT;'
    _,digest,size=at.pump(psql,env,snapshot_sql(token,body),256*1024*1024)
    return {'count':int(raw),'canonical_copy_sha256':digest,'canonical_copy_bytes':size}

def capture(at,base,env,names,reference,selected,selection_sha,validate=m.validate_observation):
    psql=[str(base/'bin/psql'),'-X','-qAt','--no-password','--set=ON_ERROR_STOP=1','--set=VERBOSITY=sqlstate','--dbname=service=tu1nz_b_export','--file=-']
    initial=m.metadata_sql(b.read_small(b.CATALOG)).decode().replace('COMMIT;\n',catalog_sql().decode()+'COMMIT;\n')
    initial_raw,_,_=at.pump(psql,env,initial.encode(),CAPTURE_CAP)
    initial_rows=[json.loads(l) for l in initial_raw.splitlines()]
    validate(initial_rows,b.read_small(b.CATALOG))
    need(normalized(initial_rows)==normalized(reference),'PREFLIGHT_SCHEMA_OR_RIGHTS_DRIFT')
    keeper=at.spawn(psql,env)
    keeper.stdin.write(('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'+SETTINGS+
        "SELECT json_build_object('database',current_database(),'role',current_user,'session_role',session_user,'version',current_setting('server_version_num'),'postmaster_start',pg_postmaster_start_time(),'read_only',current_setting('transaction_read_only'),'ssl',(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()));\n").encode());keeper.stdin.flush()
    ownerline=bytearray()
    while not ownerline.endswith(b'\n'):
        need(len(ownerline)<4096 and keeper.poll() is None,'OWNER_IDENTITY_FAILED')
        if select.select([keeper.stdout],[],[],min(0.2,at.left()))[0]:
            chunk=os.read(keeper.stdout.fileno(),1);need(bool(chunk),'OWNER_IDENTITY_CLOSED');ownerline.extend(chunk)
    owner=json.loads(ownerline)
    observed_identity=next(r for r in initial_rows if r['kind']=='identity')
    need(all(owner[k]==observed_identity[k] for k in ('database','role','session_role','version','postmaster_start','ssl')) and owner['read_only']=='on','OWNER_WRONG_SOURCE')
    keeper.stdin.write(('LOCK TABLE '+','.join('public."'+n+'"' for n in names)+' IN ACCESS SHARE MODE;SELECT pg_export_snapshot();\n').encode());keeper.stdin.flush()
    token=bytearray()
    while not token.endswith(b'\n'):
        need(len(token)<128 and keeper.poll() is None,'SNAPSHOT_HOLDER_FAILED')
        if select.select([keeper.stdout],[],[],min(0.2,at.left()))[0]:
            part=os.read(keeper.stdout.fileno(),1);need(bool(part),'SNAPSHOT_HOLDER_CLOSED');token.extend(part)
    token=token.decode().strip();snapshot_sql(token,'')
    metadata=m.metadata_sql(b.read_small(b.CATALOG)).decode()
    metadata=metadata.replace('COMMIT;\n',catalog_sql().decode()+'COMMIT;\n')
    metadata=metadata.replace('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;',
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '"+token+"';",1)
    rows_raw,_,_=at.pump(psql,env,metadata.encode(),CAPTURE_CAP)
    rows=[json.loads(l) for l in rows_raw.splitlines()]
    validate(rows,b.read_small(b.CATALOG))
    need(normalized(rows)==normalized(reference),'SCHEMA_OR_RIGHTS_DRIFT')
    dump=b.dump_argv(selected,token);dump[0]=str(base/'bin/pg_dump')
    _,dump_hash,dump_size=at.pump(dump,env,b'',240*1024*1024,at.targets[0]/'postgres.data.dump')
    schema=[str(base/'bin/pg_dump'),'--dbname=service=tu1nz_b_export','--schema-only','--no-owner','--no-privileges','--strict-names','--lock-wait-timeout=5000','--snapshot='+token,*['--table=public.'+n for n in names]]
    _,schema_hash,schema_size=at.pump(schema,env,b'',SCHEMA_CAP,at.targets[0]/'schema.observed.sql')
    fingerprints={}
    for name in names:
        need(keeper.poll() is None,'SNAPSHOT_HOLDER_LOST')
        fingerprints[name]=table_fingerprint(at,psql,env,token,name)
    # Fresh independent transaction detects visible end-of-capture DDL drift.
    fresh=m.metadata_sql(b.read_small(b.CATALOG)).decode().replace('COMMIT;\n',catalog_sql().decode()+'COMMIT;\n')
    end_raw,_,_=at.pump(psql,env,fresh.encode(),CAPTURE_CAP)
    end=[json.loads(l) for l in end_raw.splitlines()];validate(end,b.read_small(b.CATALOG))
    need(normalized(end)==normalized(reference) and keeper.poll() is None,'FINAL_SCHEMA_OR_HOLDER_DRIFT')
    keeper.stdin.write(b'ROLLBACK;\n\\q\n');keeper.stdin.flush();keeper.communicate(timeout=at.left());need(keeper.returncode==0,'HOLDER_CLOSE_FAILED')
    observed={'capture_id':ID,'phase':'precopy','snapshot':token,'source_identity':[r for r in rows if r['kind']=='identity'],'schema_metadata':rows,'settings_observation':setting_observations(rows),'fingerprints':fingerprints,'selection_sha256':selection_sha,'writer_freedom':'UNPROVEN','restore':'UNPROVEN','source_historical_truth':'NOT_PROVEN'}
    raw=(json.dumps(observed,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=CAPTURE_CAP,'CAPTURE_JSON_LIMIT')
    at.room();need(at.written+len(raw)<=PACKAGE_CAP,'PACKAGE_LIMIT');new_file(at.targets[0]/'postgres.capture.json',raw);at.written+=len(raw);at.room()
    artifacts=[{'name':'postgres.data.dump','sha256':dump_hash,'size':dump_size},{'name':'schema.observed.sql','sha256':schema_hash,'size':schema_size},{'name':'postgres.capture.json','sha256':m.sha(raw),'size':len(raw)}]
    return artifacts,observed

def duplicate(at,artifacts):
    for item in artifacts:
        source=at.targets[0]/item['name'];dest=at.targets[1]/item['name']
        f=os.open(source,os.O_RDONLY|os.O_NOFOLLOW);out=None;h=hashlib.sha256();size=0
        try:
            before=b.identity(os.fstat(f));need(stat.S_ISREG(os.fstat(f).st_mode) and before[5]==1,'COPY_SOURCE_KIND')
            out=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            while True:
                at.room();raw=os.read(f,65536)
                if not raw:break
                size+=len(raw);need(size<=item['size'],'COPY_SIZE');h.update(raw)
                need(os.write(out,raw)==len(raw),'COPY_SHORT_WRITE');at.copied+=len(raw);at.room()
            os.fsync(out)
            need(size==item['size'] and h.hexdigest()==item['sha256'] and b.identity(os.fstat(f))==before,'COPY_CHANGED')
        finally:
            os.close(f)
            if out is not None:os.close(out)
    # Persist both file entries and the newly created payload-directory names.
    sync_directories(at,(*at.targets,*(target.parent for target in at.targets)))

def execute(args):
    need(sys.platform=='darwin' and sys.stdin.isatty(),'SECURE_NATIVE_MAC_TTY')
    a,end=approval(b.read_small(args.approval),datetime.now(timezone.utc))
    need(m.sha(b.read_small(args.approval))==args.approval_sha256,'APPROVAL_HASH')
    # Approval is an external explicit human authorization, not a self-set bit.
    repo=Path(__file__).resolve().parents[1]
    for flag,key in (('HEAD','source_commit'),('HEAD^{tree}','source_tree')):
        got=subprocess.check_output(['/usr/bin/git','-C',str(repo),'rev-parse',flag],timeout=5).decode().strip();need(got==a[key],'SOURCE_CHANGED')
    need(not subprocess.check_output(['/usr/bin/git','-C',str(repo),'status','--porcelain'],timeout=5),'DIRTY_SOURCE')
    raw=b.read_small(STAGE/'B_EXPORT_SELECTION_CANDIDATE-20261019.json');need(m.sha(raw)==SELECTION_SHA,'SELECTION_CHANGED')
    selected=b.selection(raw,b.parse(b.read_small(b.CATALOG)))
    names=sorted(r['name'] for r in selected['relations'] if r['disposition']=='export')
    need(len(names)==34 and not selected['files'] and all(r['disposition']=='export' for r in selected['relations']),'EXACT_DB_ONLY34')
    refraw=b.read_small(STAGE/'BUNDLED_READER-20261019.json');need(m.sha(refraw)==REFERENCE_SHA,'REFERENCE_CHANGED')
    reference=json.loads(refraw)['observations']
    for target in TARGETS:ancestors(target.parent,mac_acl=True);need(not os.path.lexists(target),'TARGET_EXISTS_NO_RETRY')
    base=STAGE/'Postgres.app/Contents/Versions/17'
    m.verify_client(STAGE/'Postgres.app',STAGE/'CLIENT_CLOSURE.json',CLIENT_SHA)
    options=m.transport(repo/'scripts/tu1nz_public_operator.py')
    vpn=json.loads(subprocess.check_output(['/opt/homebrew/bin/tailscale','status','--json'],stderr=subprocess.DEVNULL,timeout=8,env=m.vpn_status_environment()));need(m.expected_vpn_online(vpn),'VPN_NOT_CONFIRMED')
    with socket.socket() as probe:probe.bind(('127.0.0.1',15432))
    at=Attempt(STAGE/(ID+'.attempt.jsonl'),time.monotonic()+(end-datetime.now(timezone.utc)).total_seconds(),TARGETS)
    credential=identity=None;tunnel=None;status='PARTIAL_HOLD';secret=None
    try:
        warnings.simplefilter('error',m.getpass.GetPassWarning)
        secret=m.getpass.getpass('chatops sudo — nur lokal verdeckt, genau bestehende DSN: ')
        need(secret and '\n' not in secret and '\r' not in secret,'AUTH_INPUT')
        at.left();m.verify_client(STAGE/'Postgres.app',STAGE/'CLIENT_CLOSURE.json',CLIENT_SHA);at.left()
        remote='LC_ALL=C '+shlex.join(['/usr/bin/sudo','-S','-k','-p','','--','/usr/bin/timeout','--kill-after=3s','10s','/usr/bin/python3','-I','-B','-S','-c',m.REMOTE_READ])
        child=at.spawn(m.ssh(options)+[remote],{'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        dsn,_=child.communicate((secret+'\n').encode(),timeout=min(25,at.left()));secret=None;need(child.returncode==0,'DSN_READ_FAILED')
        values=m.parse_dsn(dsn,base/'lib/libpq.5.dylib');password=m.validate_dsn(values);dsn=values=None
        private=Path(tempfile.mkdtemp(prefix='tu1nz-b-precopy-',dir='/private/tmp'));credential=private/'pgpass'
        fd=os.open(credential,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);s=os.fstat(fd);identity=(s.st_dev,s.st_ino,s.st_uid)
        at.event('OWN_TEMP_CREDENTIAL',path=str(credential),dev=s.st_dev,inode=s.st_ino,uid=s.st_uid)
        with os.fdopen(fd,'wb') as f:f.write(m.passfile_bytes(password));f.flush();os.fsync(f.fileno())
        password=None
        service=private/'service.conf';new_file(service,('[tu1nz_b_export]\nhost=127.0.0.1\nport=15432\ndbname='+m.DATABASE+'\nuser='+m.ROLE+'\n').encode())
        env=m.clean_environment(credential,base,private);env['PGSERVICEFILE']=str(service)
        forward=tuple('ClearAllForwardings=no' if x=='ClearAllForwardings=yes' else x for x in options)
        tunnel=at.spawn(m.ssh(forward,'-v','-N','-o','ExitOnForwardFailure=yes','-L','127.0.0.1:15432:127.0.0.1:5432'),{'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL,stderr=subprocess.PIPE)
        ready_deadline=min(at.deadline,time.monotonic()+15);debug=bytearray()
        while b'Local forwarding listening on 127.0.0.1 port 15432.' not in debug:
            need(time.monotonic()<ready_deadline and tunnel.poll() is None,'TUNNEL_NOT_READY')
            if select.select([tunnel.stderr],[],[],min(0.2,at.left()))[0]:
                part=os.read(tunnel.stderr.fileno(),4096);need(bool(part) and len(debug)+len(part)<=65536,'TUNNEL_READY_BOUND');debug.extend(part)
        for target in TARGETS:
            ancestors(target.parent,mac_acl=True);need(not os.path.lexists(target),'TARGET_EXISTS_NO_RETRY')
            os.mkdir(target,0o700)
        at.deadline=min(at.deadline,time.monotonic()+300);at.event('CAPTURE_300S_STARTED')
        artifacts,observed=capture(at,base,env,names,reference,selected,SELECTION_SHA)
        receipt={'capture_id':ID,'source_commit':a['source_commit'],'approval_sha256':args.approval_sha256,'selection_sha256':SELECTION_SHA,'artifacts':artifacts,'source_historical_truth':'NOT_PROVEN','writer_freedom':'UNPROVEN','restore':'UNPROVEN','phase':'precopy'}
        receipt_raw=(json.dumps(receipt,sort_keys=True)+'\n').encode();receiptpath=STAGE/(ID+'.receipt.json')
        manifest={'schema':'TU1NZ_B_DATA_PACKAGE_V1','phase':'precopy','selection_sha256':SELECTION_SHA,'capture_receipt_sha256':m.sha(receipt_raw),'artifacts':artifacts}
        mr=(json.dumps(manifest,sort_keys=True)+'\n').encode();mp=STAGE/(ID+'.manifest.json')
        persist_bindings(at,receiptpath,receipt_raw,mp,mr)
        duplicate(at,artifacts)
        for target in TARGETS:
            verifier=['/usr/bin/python3','-I','-B','-S',str(repo/'scripts/tu1nz_b_data_handoff.py'),'--selection',str(STAGE/'B_EXPORT_SELECTION_CANDIDATE-20261019.json'),'--selection-sha256',SELECTION_SHA,'verify','--directory',str(target),'--manifest',str(mp),'--manifest-sha256',m.sha(mr)]
            out,_,_=at.pump(verifier,{'PATH':'/usr/bin:/bin','LC_ALL':'C'},b'',1024*1024)
            need(json.loads(out)['status']=='BYTES_CHECKED_NOT_ADMITTED','INDEPENDENT_REREAD')
        at.room();status='PRECOPY_BYTES_CHECKED_NOT_RESTORED';return 0
    finally:
        secret=None
        cleanup(at,credential,identity,tunnel,status)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--approval',type=Path);parser.add_argument('--approval-sha256')
    args=parser.parse_args()
    def interrupted(_n,_f):raise InterruptedError('SIGNAL')
    for sig in (signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    try:
        if not args.execute:
            print(json.dumps({'status':'PLAN_ONLY_NOT_AUTHORIZED','capture_id':ID,'targets':list(map(str,TARGETS)),'deadline_seconds':300,'package_cap_each':PACKAGE_CAP,'shared_reserve':RESERVE,'wire_cap':WIRE_CAP}));return 0
        need(args.approval is not None and args.approval_sha256 is not None,'EXPLICIT_WINDOW_APPROVAL_REQUIRED')
        return execute(args)
    except BaseException as exc:
        print(json.dumps({'status':'HOLD','code':str(exc) if isinstance(exc,m.Denied) else type(exc).__name__}));return 2
if __name__=='__main__':sys.exit(main())
