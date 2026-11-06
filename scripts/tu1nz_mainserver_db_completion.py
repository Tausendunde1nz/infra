"""Approved E1: one additive two-table capture after the immutable prior HOLD.

Import is inert. The real entry has fixed paths, no options, one SSH -N channel,
no remote program, no sudo, no original-reader replay and no automatic resume.
Private data and authentication never leave the approved Mac custody or enter
review/CI logs. Root file restore is a separate personally entered fixed entry.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

TX='public-rights-20261014-1'
D=Path('/Users/daniel/Documents/ChatGPT/TausendundE1NZ/mainserver-recovery-20261101')
INPUT=D/'execution/db-completion'
OLD=D/'execution/pre-stop-backup'
OUTPUT=Path('/Users/daniel/.codex/backups/mainserver-recovery-20261101/pre-stop-protection')/TX
SOCKET=Path('/private/tmp/tu1nz-mainserver-restore-public-rights-20261014-1')
SOURCE=Path('/Users/daniel/Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts')
DECISION='9fda4f850eb2a67297c68721f327b9ceaffdd157cbcc13adc449c055768d1629'
APPROVAL='e68c3cd660b10b58b32f003b8308db5ffd22bee218cbadb3e3ec43d0b407f4b1'
OLD_SCOPE='e93854ece5dfb27cc6210b3b20462f39c6c67b037446f296123823421f47c473'
OLD_REVIEW='1f3c19e69dbf886034436fedf3124275cc8a33f806dfd45592b164acd9648ea6'
OLD_ATTEMPT='5a076e121ed664d204bf0f99c2fea81abf81e1c5de3ad9549a527b75be7424b6'
OLD_RESULT='088859f0b4f8f1cab38461f5407758315c79fe899a5d7a99595bdf9028f2abf0'
MODULES=('tu1nz_mainserver_db_completion.py','tu1nz_mainserver_db_file_restore.py',
 'tu1nz_mainserver_backup.py','tu1nz_mainserver_restore.py','tu1nz_mainserver_file_restore.py',
 'tu1nz_mainserver_file_restore_entry.py')
TESTS=('tests/test_mainserver_db_completion.py','tests/test_mainserver_restore.py',
 'tests/test_mainserver_backup.py','.github/workflows/control-validation.yml')
PROOFS=('pre-stop-owner-profile-native-2/RESULT.json','file-restore-rights-20261104/root-context-RESULT.json',
 'pre-stop-backup/linux-native.json','db-completion/native/RESULT.json','db-completion/linux-native.json',
 'db-completion/CLEANUP_BOUNDARY.json')
HELPERS=('/usr/bin/ssh','/usr/sbin/lsof')
ORIGINAL=('ATTEMPT.json','RESULT.json','files.json','files-receipt.json','blobs',
 'trusted-schema.sql','trusted-grants.sql','restore-server.log')
NEW=('DB_COMPLETION_ATTEMPT.json','source-catalog.jsonl','source-rights.jsonl','s7.dump',
 'restored-catalog.jsonl','restored-rights.jsonl','DB_COMPLETION_RESULT.json',
 'db-completion-restore-server.log','db-completion-restore','db-completion-transient.pgpass',
 'privileged-restore','FILE_RESTORE_RESULT.json','PROTECTION_COMPLETION.json')
CAPTURE_FILES=set(NEW[:8])
PASS='E1_REAL_DB_RESTORE_PASS_FIRST_PRIVILEGED_FILE_RESTORE_PENDING'


class Denied(RuntimeError):pass
def need(value,code):
    if not value:raise Denied(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def input_changed(path,differences):
    error=Denied('E1_INPUT_CHANGED')
    error.input_observation={'check':'read/E1_INPUT_CHANGED','path':str(path),'differences':differences}
    return error


def read(path,limit,owner=501):
    path=Path(path);need(path.resolve(strict=True)==path,'E1_INPUT_CANONICAL')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==owner and stat.S_IMODE(s.st_mode)==0o600 and
             s.st_nlink==1 and 0<=s.st_size<=limit,'E1_INPUT_PROFILE')
        raw=b''
        while len(raw)<=limit:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw+=part
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if len(raw)!=s.st_size:
            raise input_changed(path,[{'attribute':'read_bytes','expected':s.st_size,'actual':len(raw)}])
        observed=(os.fstat(fd),path.lstat())
        if not all(tuple(getattr(a,k) for k in fields)==tuple(getattr(s,k) for k in fields) for a in observed):
            raise input_changed(path,[{'observation':kind,'attribute':k,'expected':getattr(s,k),'actual':getattr(a,k)}
                for kind,a in zip(('fd','path'),observed) for k in fields if getattr(a,k)!=getattr(s,k)])
        return raw
    finally:os.close(fd)


def directory(path,owner=501):
    need(path.resolve(strict=True)==path,'E1_DIRECTORY_CANONICAL')
    s=path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==owner and stat.S_IMODE(s.st_mode)==0o700,'E1_DIRECTORY_PROFILE')
    return s.st_dev,s.st_ino,s.st_uid,s.st_mode


def load(name,raw):
    need(name in MODULES,'E1_MODULE_SET')
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,None))
    exec(compile(raw,name,'exec'),module.__dict__);return module


def validate_inputs():
    raw=read(INPUT/'SCOPE.json',512*1024);scope=json.loads(raw)
    need(set(scope)=={'schema','transaction','host_id','decision_sha256','approval_sha256','old_scope_sha256',
        'output','socket_parent','source_sha256','tests_sha256','proof_sha256','original_sha256',
        'helpers_sha256','ssh_options_sha256','client_closure_sha256','tool_sha256','schema_reference'} and
        scope['schema']=='TU1NZ_E1_DB_COMPLETION_SCOPE_V1' and scope['transaction']==TX and scope['host_id']==109772243 and
        scope['decision_sha256']==DECISION and scope['approval_sha256']==APPROVAL and scope['old_scope_sha256']==OLD_SCOPE and
        scope['output']==str(OUTPUT) and scope['socket_parent']==str(SOCKET),'E1_SCOPE')
    need(sha(read(OLD/'DB_COMPLETION_DECISION.txt',65536))==DECISION and
         sha(read(INPUT/'APPROVAL.json',65536))==APPROVAL,'E1_APPROVAL_BINDING')
    review_raw=read(INPUT/'INDEPENDENT_REVIEW.json',65536);review=json.loads(review_raw)
    need(review.get('verdict')=='PASS' and review.get('independent_of_implementer') is True and
         review.get('scope_sha256')==sha(raw) and review.get('unresolved_findings')==[], 'E1_INDEPENDENT_REVIEW')
    need(set(scope['source_sha256'])==set(MODULES) and set(scope['tests_sha256'])==set(TESTS) and
         set(scope['proof_sha256'])==set(PROOFS) and set(scope['helpers_sha256'])==set(HELPERS),'E1_BOUND_SETS')
    source={}
    for name,digest in scope['source_sha256'].items():
        source[name]=read(INPUT/'source'/name,256*1024)
        need(sha(source[name])==digest and (SOURCE/name).read_bytes()==source[name],'E1_SOURCE_CHANGED')
    for name,digest in scope['tests_sha256'].items():
        need(sha((SOURCE.parent/name).read_bytes())==digest,'E1_TEST_CHANGED')
    proofs={}
    for name,digest in scope['proof_sha256'].items():
        proof=read(INPUT.parent/name,512*1024);need(sha(proof)==digest,'E1_PROOF_CHANGED');proofs[name]=json.loads(proof)
    profile,mac,oldlinux,native,linux,cleanup=(proofs[n] for n in PROOFS)
    need(profile['status']=='PASS_SYNTHETIC_OWNER_PROFILE_NOT_CURRENT_HOST_OR_REAL_RESTORE' and
         profile['cleanup']==[] and profile['source_sha256']['tu1nz_mainserver_restore.py']==scope['source_sha256']['tu1nz_mainserver_restore.py'] and
         mac['restore']['status']=='PASS' and mac['restore']['proof']['actual_ownership'] is True and
         oldlinux['status']=='PASS_SYNTHETIC_LINUX_BACKUP_BOUNDARY' and
         native['status']=='PASS_E1_SYNTHETIC_NATIVE_NOT_REAL_BACKUP' and native['cleanup']==[] and
         linux['status']=='PASS_E1_SYNTHETIC_LINUX_BOUNDARY' and linux['skipped']==0 and
         native['source_sha256']==linux['source_sha256']==scope['source_sha256'] and
         cleanup['original_remote_closed_ACK_received'] is False and cleanup['no_remote_cleanup_claimed'] is True,
         'E1_NATIVE_GATES')
    need(scope['source_sha256']['tu1nz_mainserver_file_restore.py']=='b0ef13342a722371f2fc9c79efa1b755e5cb0586c4cc74093389df697e5b54de' and
         scope['source_sha256']['tu1nz_mainserver_file_restore_entry.py']=='c421735d620b0142dc4e31fdb4317f1df110801b19f8c0fb034167326012ca70',
         'E1_CLOSED_FILE_RESTORE_CHANGED')
    for name,digest in scope['helpers_sha256'].items():need(sha(Path(name).read_bytes())==digest,'E1_HELPER_CHANGED')
    b=load('tu1nz_mainserver_backup.py',source['tu1nz_mainserver_backup.py'])
    need(sha(canonical(b.SSH_OPTIONS))==scope['ssh_options_sha256'] and b.OUTPUT==OUTPUT and b.SOCKET==SOCKET,'E1_TRANSPORT_BINDING')
    return scope,sha(raw),sha(review_raw),source,b


def prior_files(scope,b,f,*,phase):
    need(phase in ('capture','root','final'),'E1_PHASE')
    directory(OUTPUT);directory(OUTPUT/'blobs')
    allowed=set(ORIGINAL)
    if phase in ('root','final'):allowed |= CAPTURE_FILES
    if phase=='final':allowed |= {'privileged-restore','FILE_RESTORE_RESULT.json'}
    need(set(os.listdir(OUTPUT))==allowed,'E1_OCCUPIED_OR_FOREIGN_OBJECT')
    need(not os.path.lexists(SOCKET),'E1_SOCKET_ALREADY_PRESENT')
    originals={name:read(OUTPUT/name,512*1024 if name!='restore-server.log' else 1024*1024)
               for name in ORIGINAL if name!='blobs'}
    need(set(scope['original_sha256'])==set(originals) and
         all(sha(raw)==scope['original_sha256'][name] for name,raw in originals.items()),'E1_ORIGINAL_CHANGED')
    need(sha(originals['ATTEMPT.json'])==OLD_ATTEMPT and sha(originals['RESULT.json'])==OLD_RESULT,'E1_OLD_HOLD_CHANGED')
    prior=json.loads(originals['RESULT.json']);attempt=json.loads(originals['ATTEMPT.json'])
    need(prior['status']=='HOLD' and prior['failure']=='SOURCE_SCHEMA_OWNER_UNKNOWN' and prior['cleanup']==[] and
         prior['private_restore_cleanup']['own_cluster_removed'] is True and prior['private_restore_cleanup']['own_socket_removed'] is True and
         prior['host_services_changed'] is False and prior['production_restore'] is False and
         attempt['scope_sha256']==prior['scope_sha256']==OLD_SCOPE and attempt['review_sha256']==prior['review_sha256']==OLD_REVIEW,
         'E1_PRIOR_STATE')
    old_scope_raw=read(OLD/'SCOPE.json',512*1024);old_review=read(OLD/'INDEPENDENT_REVIEW.json',65536)
    need(sha(old_scope_raw)==OLD_SCOPE and sha(old_review)==OLD_REVIEW,'E1_OLD_BINDING')
    old_scope=json.loads(old_scope_raw);manifest=json.loads(originals['files.json']);receipt=json.loads(originals['files-receipt.json'])
    need(receipt['objects']==len(manifest)==102 and receipt['bytes']==6533068 and
         receipt['manifest_sha256']==sha(originals['files.json']) and
         receipt['scope_sha256']==sha(canonical(old_scope['reader_scope'])) and
         receipt['semantics']=='PER_OBJECT_STABLE_PRESTOP_COPY_NOT_GLOBAL_ATOMIC_OR_WRITER_FENCED','E1_FILE_RECEIPT')
    digests={row['sha256'] for row in manifest.values() if row['sha256'] is not None}
    need(set(os.listdir(OUTPUT/'blobs'))==digests and all(re.fullmatch('[0-9a-f]{64}',s) for s in digests),'E1_BLOB_SET')
    blobs={digest:read(OUTPUT/'blobs'/digest,8*1024*1024) for digest in digests}
    total=f.profile(manifest,blobs,old_scope['reader_scope']['files'])
    need(total==receipt['bytes'],'E1_FULL_FILE_READBACK')
    return manifest,blobs,old_scope['reader_scope']['files'],originals


def port_free():
    with socket.socket() as probe:probe.bind(('127.0.0.1',15432))


class Tunnel:
    """Single owned SSH child; readiness is its listener, never a probe connection."""
    def __init__(self,b,r,deadline):
        self.deadline=deadline;self.child=None;self.closed=False;self.selector=selectors.DefaultSelector();self.r=r
        argv=['/usr/bin/ssh','-F','/dev/null','-T','-N']
        for option in b.SSH_OPTIONS:argv.extend(('-o',option))
        argv.extend(('-L','127.0.0.1:15432:127.0.0.1:5432','100.121.130.51'))
        try:
            self.child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            for stream in (self.child.stdout,self.child.stderr):
                os.set_blocking(stream.fileno(),False);self.selector.register(stream,selectors.EVENT_READ)
            ready=min(deadline,time.monotonic()+10)
            while True:
                self.live();need(time.monotonic()<ready,'E1_TUNNEL_NOT_READY')
                code,out,err=r.bounded_process(['/usr/sbin/lsof','-nP','-a','-p',str(self.child.pid),
                    '-iTCP@127.0.0.1:15432','-sTCP:LISTEN','-Fpn'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                    deadline=ready,limit=4096)
                need(not err and code in (0,1),'E1_TUNNEL_LISTENER_UNKNOWN')
                if code==0:
                    need(re.fullmatch(('p'+str(self.child.pid)+r'\nf[0-9]{1,6}\nn127\.0\.0\.1:15432\n').encode(),out),'E1_TUNNEL_LISTENER_MISMATCH')
                    self.live();break
                need(not out,'E1_TUNNEL_LISTENER_UNKNOWN');time.sleep(.05)
        except BaseException:self.abort();raise
    def live(self):
        need(time.monotonic()<self.deadline and self.child is not None and self.child.poll() is None,'E1_CHANNEL_LOST_OR_DEADLINE')
        for key,_ in self.selector.select(0):
            raw=os.read(key.fileobj.fileno(),4096)
            need(not raw,'E1_CHANNEL_UNEXPECTED_DIAGNOSTIC')
            raise Denied('E1_CHANNEL_PIPE_CLOSED')
    def finish(self):
        self.live();self.child.terminate()
        try:code=self.child.wait(timeout=max(.001,min(5,self.deadline-time.monotonic())))
        except subprocess.TimeoutExpired:self.abort();raise Denied('E1_TUNNEL_CLOSE_UNCONFIRMED') from None
        need(time.monotonic()<self.deadline and code in (0,255,-signal.SIGTERM),'E1_TUNNEL_CLOSE_UNCONFIRMED')
        # SIGTERM is intentional local teardown after acknowledged DB ROLLBACK;
        # never described as a remote-program or old-reader ACK.
        self.abort();port_free()
        return {'own_ssh_ended':True,'exit_code_after_local_SIGTERM':code,'local_forward_removed':True,
                'remote_program_executed':False,'remote_process_cleanup_observed':False}
    def abort(self):
        if self.closed:return
        self.closed=True;self.selector.close()
        if self.child is not None:
            if self.child.poll() is None:self.child.kill();self.child.wait(timeout=5)
            for stream in (self.child.stdout,self.child.stderr):
                if stream is not None and not stream.closed:stream.close()


def environment(b,base):
    env=b.database_environment(OUTPUT,base);env['PGPASSFILE']=str(OUTPUT/'db-completion-transient.pgpass');return env


def prepare_pg(r,b,base,ddl,grants):
    pg=r.PrivatePostgres(base,OUTPUT/'db-completion-restore',SOCKET/'s',deadline=time.monotonic()+120)
    # Caller owns the object even when start/schema setup fails.
    return pg


def initialize_pg(pg,b,ddl,grants):
    pg.start()
    identity=lambda p:(p.stat().st_dev,p.stat().st_ino,p.stat().st_uid,p.stat().st_mode)
    pg.restore_identity=identity(pg.root);pg.socket_identity=identity(pg.socket);pg.socket_parent_identity=identity(pg.socket.parent)
    pg.query(('CREATE ROLE postgres NOLOGIN; CREATE ROLE '+b.ROLE+' NOLOGIN NOSUPERUSER NOCREATEDB '
        'NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE real_restore;\n').encode())
    pg.env['PGDATABASE']='real_restore'
    pg.query(b'GRANT CREATE,USAGE ON SCHEMA public TO postgres; SET ROLE postgres;\n'+ddl+grants+b'RESET ROLE;\n')
    pg.install_known_owner_profile()


def capture_and_restore(r,b,pg,base,local_catalog,local_rights,*,tunnel_factory=Tunnel,snapshot_factory=None,receipt=None):
    """Production and synthetic fixtures use the identical finite orchestration."""
    layout=r.copy_layout(r.structural_catalog(local_catalog));snapshot=channel=None
    started=time.monotonic();deadline=started+300;result={} if receipt is None else receipt
    result['source_snapshot_cleanup']='NOT_STARTED'
    try:
        channel=tunnel_factory(b,r,deadline)
        snapshot=(snapshot_factory or r.ReadOnlySnapshot)(base,environment(b,base),deadline=deadline)
        result['source_snapshot_cleanup']='UNCONFIRMED'
        identity=snapshot.start(database=b.DATABASE,role=b.ROLE);channel.live()
        catalog=snapshot.read('catalog');channel.live();rights=snapshot.read('rights');channel.live()
        r.private_create(OUTPUT/'source-catalog.jsonl',catalog);r.private_create(OUTPUT/'source-rights.jsonl',rights)
        result['admission']=r.compare_restore_catalog(catalog,local_catalog,rights,local_rights)
        before={}
        for name in r.TABLES:
            before[name]=r.fingerprint(snapshot.read('fingerprint',layout,name));channel.live()
        archive=snapshot.dump();channel.live();r.private_create(OUTPUT/'s7.dump',archive)
        need(read(OUTPUT/'s7.dump',r.MAX_DATA)==archive,'E1_ARCHIVE_FULL_READBACK')
        for name in r.TABLES:
            need(before[name]==r.fingerprint(snapshot.read('fingerprint',layout,name)),'E1_SNAPSHOT_DRIFT');channel.live()
        closing=snapshot;snapshot=None;closing.close();channel.live()
        result['snapshot_rollback_acknowledged']=True;result['source_snapshot_cleanup']='ROLLBACK_ACKNOWLEDGED'
        result['transport']=channel.finish();channel=None
        result['capture_seconds']=time.monotonic()-started
        need(result['capture_seconds']<300,'E1_CAPTURE_DEADLINE')
        result['snapshot']={**identity,'fingerprints':before,'archive_sha256':sha(archive),'captured_unix':time.time()}
        restore_started=time.monotonic();pg.deadline=restore_started+300
        code,rendered,err=pg.call('pg_restore',['--data-only','--no-owner','--no-privileges','--file=-',str(OUTPUT/'s7.dump')],limit=r.MAX_DATA)
        need(code==0 and not err,'E1_ARCHIVE_RENDER')
        pg.restore_copies(r.extract_copy_data(rendered,layout),layout)
        restored=pg.query(r.catalog_transaction());restored_rights=pg.query(r.rights_transaction())
        result['restored_catalog']=r.compare_restore_catalog(catalog,restored,rights,restored_rights)
        after={n:r.fingerprint(pg.query(b'BEGIN READ ONLY; SET LOCAL search_path=pg_catalog;\n'+r.fingerprint_sql(n,layout)+b'ROLLBACK;\n')) for n in r.TABLES}
        need(before==after,'E1_REAL_RESTORE_CONTENT_MISMATCH')
        r.private_create(OUTPUT/'restored-catalog.jsonl',restored);r.private_create(OUTPUT/'restored-rights.jsonl',restored_rights)
        need(time.monotonic()<pg.deadline,'E1_LOCAL_RESTORE_DEADLINE')
        result['restored_fingerprints']=after;result['restore_seconds']=time.monotonic()-restore_started
        return result
    finally:
        try:
            if snapshot is not None:
                snapshot.close();result['source_snapshot_cleanup']='ROLLBACK_ACKNOWLEDGED'
        finally:
            if channel is not None:
                result['transport_cleanup']='UNCONFIRMED'
                channel.abort();result['transport_cleanup']='OWN_LOCAL_CHILD_ENDED_NO_REMOTE_ACK_CLAIMED'


def begin(r,scope_sha,review_sha,scope):
    # O_EXCL persists consumption before any child or network. Even partial
    # creation, an exception or a missing result makes this entry unavailable.
    r.private_create(OUTPUT/'DB_COMPLETION_ATTEMPT.json',canonical({'schema':'TU1NZ_E1_ATTEMPT_V1',
        'transaction':TX,'scope_sha256':scope_sha,'review_sha256':review_sha,'approval_sha256':APPROVAL,
        'original_attempt_sha256':OLD_ATTEMPT,'original_hold_sha256':OLD_RESULT,
        'file_manifest_sha256':scope['original_sha256']['files.json'],'started_unix':time.time(),
        'retry_allowed':False,'original_remote_closed_ACK_received':False}))


def capture_main():
    need(sys.platform=='darwin' and os.getuid()==os.geteuid()==501 and len(sys.argv)==1 and sys.stdin.isatty(),
         'E1_PERSONAL_MAC_TTY_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    scope,scope_sha,review_sha,source,b=validate_inputs()
    need(Path(__file__).resolve(strict=True)==INPUT/'source'/'tu1nz_mainserver_db_completion.py' and
         Path(__file__).read_bytes()==source['tu1nz_mainserver_db_completion.py'],'E1_ENTRY_SOURCE_CHANGED')
    r=load('tu1nz_mainserver_restore.py',source['tu1nz_mainserver_restore.py'])
    f=load('tu1nz_mainserver_file_restore.py',source['tu1nz_mainserver_file_restore.py'])
    manifest,blobs,paths,originals=prior_files(scope,b,f,phase='capture')
    closure=read(b.CLIENT/'CLIENT_CLOSURE.json',1024*1024);base=b.CLIENT/'Postgres.app/Contents/Versions/17'
    need(sha(closure)==scope['client_closure_sha256'] and r.verify_local_tools(base,json.loads(closure))==scope['tool_sha256'],
         'E1_CLIENT_BINDING')
    ddl,grants,reference=r.trusted_schema(b.APP)
    need(reference==scope['schema_reference'] and ddl==originals['trusted-schema.sql'] and grants==originals['trusted-grants.sql'],
         'E1_TRUSTED_SCHEMA_CHANGED')
    need(os.statvfs(OUTPUT).f_bavail*os.statvfs(OUTPUT).f_frsize>=4*1024**3,'E1_FREE_CAPACITY')
    code,out,err=r.bounded_process(['/usr/bin/fdesetup','status'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},deadline=time.monotonic()+5)
    need(code==0 and not err and out==b'FileVault is On.\n','E1_STORAGE_PROTECTION');port_free()
    auth=b.passfile_bytes(b.parse_dsn(blobs[manifest['/etc/tu1nz/adult-commercial-s7-database.dsn']['sha256']],base/'lib/libpq.5.dylib'))
    del blobs
    print('E1: genau eine lesende DB-Verbindung; vorhandene Dateikopien bleiben unverändert. Keine Passworteingabe.')
    begin(r,scope_sha,review_sha,scope)
    result={'schema':'TU1NZ_E1_DB_RESULT_V1','status':'HOLD','scope_sha256':scope_sha,'review_sha256':review_sha,
        'original_hold_sha256':OLD_RESULT,'original_remote_closed_ACK_received':False,'original_remote_cleanup_observed':False,
        'host_mutations':False,'production_restore':False,'cleanup':[],'started_unix':time.time()}
    pg=None;auth_identity=None;socket_identity=None
    try:
        SOCKET.mkdir(mode=0o700);socket_identity=directory(SOCKET)
        pg=prepare_pg(r,b,base,ddl,grants);initialize_pg(pg,b,ddl,grants)
        local_catalog=pg.query(r.catalog_transaction());local_rights=pg.query(r.rights_transaction())
        r.private_create(OUTPUT/'db-completion-transient.pgpass',auth)
        auth_identity=(OUTPUT/'db-completion-transient.pgpass').lstat();del auth
        capture_and_restore(r,b,pg,base,local_catalog,local_rights,receipt=result)
        result['status']=PASS
    except BaseException as error:
        result['failure']=str(error) if isinstance(error,(Denied,r.Denied,b.Denied,f.Denied)) else type(error).__name__
    finally:
        if 'auth' in locals():del auth
        if pg is not None:
            try:pg.close()
            except BaseException:result['cleanup'].append('E1_OWN_PG_END_UNCONFIRMED')
        if auth_identity is None and os.path.lexists(OUTPUT/'db-completion-transient.pgpass'):
            result['cleanup'].append('E1_PARTIAL_AUTH_FILE_RETAINED')
        if auth_identity is not None:
            try:
                p=OUTPUT/'db-completion-transient.pgpass';s=p.lstat()
                need((s.st_dev,s.st_ino,s.st_uid,s.st_mode)==(auth_identity.st_dev,auth_identity.st_ino,auth_identity.st_uid,auth_identity.st_mode),
                     'E1_AUTH_FILE_CHANGED');p.unlink()
            except BaseException:result['cleanup'].append('E1_AUTH_CLEANUP_UNCONFIRMED')
        if pg is not None and pg.child is not None and pg.child.poll()==0:
            try:
                r.private_create(OUTPUT/'db-completion-restore-server.log',read(pg.root/'server.log',1024*1024))
                result['private_restore_cleanup']=b.cleanup_owned_cluster(pg,pg.root)
            except BaseException:result['cleanup'].append('E1_PRIVATE_RESTORE_CLEANUP_UNCONFIRMED')
        elif socket_identity is not None:
            # No guessing or recursive cleanup of a partial cluster.
            try:
                need(directory(SOCKET)==socket_identity and os.listdir(SOCKET)==[] and
                     not os.path.lexists(OUTPUT/'db-completion-restore'),'E1_PARTIAL_CLUSTER_RETAINED');SOCKET.rmdir()
            except BaseException:result['cleanup'].append('E1_PARTIAL_CLUSTER_RETAINED')
        try:port_free()
        except BaseException:result['cleanup'].append('E1_LOCAL_FORWARD_CLEANUP_UNCONFIRMED')
        for name,raw in originals.items():
            try:need(read(OUTPUT/name,1024*1024)==raw,'E1_ORIGINAL_CHANGED')
            except BaseException:result['cleanup'].append('E1_ORIGINAL_CUSTODY_CHANGED');break
        try:
            need(sha(read(INPUT/'SCOPE.json',512*1024))==scope_sha and
                 sha(read(INPUT/'INDEPENDENT_REVIEW.json',65536))==review_sha,'E1_BINDING_CHANGED_DURING_CAPTURE')
        except BaseException:result['cleanup'].append('E1_BINDING_CHANGED_DURING_CAPTURE')
        if result['cleanup']:result['status']='HOLD'
        result['finished_unix']=time.time()
        r.private_create(OUTPUT/'DB_COMPLETION_RESULT.json',canonical(result))
    print('E1 DB-Ergebnis:',result['status'],'— Einzelbelege und Daten bleiben privat.')
    return 0 if result['status']==PASS else 1


def checked_db_receipt(scope,scope_sha,review_sha,r):
    raw=read(OUTPUT/'DB_COMPLETION_RESULT.json',512*1024);result=json.loads(raw)
    attempt=json.loads(read(OUTPUT/'DB_COMPLETION_ATTEMPT.json',65536))
    need(attempt['schema']=='TU1NZ_E1_ATTEMPT_V1' and attempt['transaction']==TX and
         attempt['scope_sha256']==scope_sha and attempt['review_sha256']==review_sha and
         attempt['approval_sha256']==APPROVAL and attempt['original_attempt_sha256']==OLD_ATTEMPT and
         attempt['original_hold_sha256']==OLD_RESULT and attempt['retry_allowed'] is False and
         attempt['file_manifest_sha256']==scope['original_sha256']['files.json'] and
         attempt['original_remote_closed_ACK_received'] is False,'E1_ADDITIVE_ATTEMPT_BINDING')
    need(result['schema']=='TU1NZ_E1_DB_RESULT_V1' and result['status']==PASS and result['cleanup']==[] and
         result['scope_sha256']==scope_sha and result['review_sha256']==review_sha and
         result['original_hold_sha256']==OLD_RESULT and result['original_remote_closed_ACK_received'] is False and
         result['original_remote_cleanup_observed'] is False and result['host_mutations'] is False and result['production_restore'] is False and
         result['snapshot_rollback_acknowledged'] is True and result['source_snapshot_cleanup']=='ROLLBACK_ACKNOWLEDGED' and result['transport']['own_ssh_ended'] is True and
         result['transport']['local_forward_removed'] is True and result['transport']['remote_program_executed'] is False and
         result['private_restore_cleanup']['own_cluster_removed'] is True and result['private_restore_cleanup']['own_socket_removed'] is True and
         0<=result['capture_seconds']<300 and 0<=result['restore_seconds']<300,'E1_REAL_DB_GATE')
    catalog=read(OUTPUT/'source-catalog.jsonl',r.MAX_CATALOG);rights=read(OUTPUT/'source-rights.jsonl',r.MAX_CATALOG)
    restored=read(OUTPUT/'restored-catalog.jsonl',r.MAX_CATALOG);rrights=read(OUTPUT/'restored-rights.jsonl',r.MAX_CATALOG)
    proof=r.compare_restore_catalog(catalog,restored,rights,rrights)
    need(proof==result['restored_catalog'] and result['admission']['source_catalog_sha256']==sha(catalog) and
         result['admission']['rights_sha256']==proof['rights_sha256'] and
         result['snapshot']['database']=='tu1nz_adult_commercial_s3' and
         result['snapshot']['role']==result['snapshot']['session_role']=='tu1nz_adult_commercial_s3_runtime' and
         result['snapshot']['readonly']=='on' and result['snapshot']['version']=='170011' and
         result['snapshot']['fingerprints']==result['restored_fingerprints'] and
         set(result['restored_fingerprints'])==set(r.TABLES),'E1_DB_PROOF_BINDING')
    for row in result['restored_fingerprints'].values():
        need(type(row)==dict and set(row)=={'bytes','rows','sha256'} and type(row['rows']) is int and
             0<=row['rows']<=r.MAX_ROWS and type(row['bytes']) is int and 0<=row['bytes']<=r.MAX_DATA and
             re.fullmatch('[0-9a-f]{64}',row['sha256']),'E1_DB_FINGERPRINT')
    archive=read(OUTPUT/'s7.dump',r.MAX_DATA)
    need(archive.startswith(b'PGDMP') and sha(archive)==result['snapshot']['archive_sha256'],'E1_REAL_ARCHIVE_READBACK')
    return raw,result


if __name__=='__main__':
    try:raise SystemExit(capture_main())
    except Exception as error:
        print('E1 vorzeitig abgebrochen:',str(error) if isinstance(error,Denied) else type(error).__name__)
        if isinstance(error,Denied) and getattr(error,'input_observation',None) is not None:
            print('E1 Prüfabweichung:',json.dumps(error.input_observation,sort_keys=True))
        raise SystemExit(1)
