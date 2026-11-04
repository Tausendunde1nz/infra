"""Rev4 private pre-stop copy and actual S7 restore; import never connects.

One reviewed local entry, one authenticated read-only SSH connection and its
fixed loopback forward. No Host output file, claim, service or business write.
Real data stays in the approved Mac custody, never CI or public diagnostics.
"""
import base64
import ctypes
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shlex
import socket
import stat
import subprocess
import sys
import time
import warnings

TX='public-rights-20261014-1'
USER_ROOT=Path('/Users/daniel')
INPUT=USER_ROOT/'Documents/ChatGPT/TausendundE1NZ/mainserver-recovery-20261101/execution/pre-stop-backup'
OUTPUT=USER_ROOT/'.codex/backups/mainserver-recovery-20261101/pre-stop-protection'/TX
SOCKET=Path('/private/tmp/tu1nz-mainserver-restore-public-rights-20261014-1')
APP=USER_ROOT/'Developer/tu1nz/s8-atomic-source.r1'
CLIENT=USER_ROOT/'Developer/tu1nz/public-production-host-r4-20261017/b-data-writer-source-20261018/dependency-extension-20261018T131302Z/fixture-fix-20261018T141735Z/B-PG17-MAC-ADMISSION-1'
SOURCE=USER_ROOT/'Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts'
DATABASE='tu1nz_adult_commercial_s3'
ROLE='tu1nz_adult_commercial_s3_runtime'
DECISION='e6794711443f5768c2e720c7552948964976c246ab59ff89236f53125fbd49fc'
APPROVAL='576251012fb1e73fcc29a49334140660339b74fbdda05273822e53cb6f80c3a4'
MODULES=('tu1nz_mainserver_backup.py','tu1nz_mainserver_backup_read.py','tu1nz_mainserver_restore.py',
         'tu1nz_mainserver_file_restore.py','tu1nz_mainserver_file_restore_entry.py')
TESTS=('tests/test_mainserver_backup.py','tests/test_mainserver_backup_read.py',
       'tests/test_mainserver_file_restore.py','tests/test_mainserver_restore.py',
       '.github/workflows/control-validation.yml')
EVIDENCE=('file-restore-rights-20261104/root-context-RESULT.json','restore-native-4/RESULT.json',
          'pre-stop-backup-native/RESULT.json','pre-stop-backup/linux-native.json')
# Same closed SSH identity/host-key restrictions as the early reader. Only the
# one explicitly bound PostgreSQL loopback forward is added; no multiplexing.
SSH_OPTIONS=(
    'HostName=100.121.130.51','User=chatops','Port=22','BatchMode=yes','ConnectTimeout=10',
    'StrictHostKeyChecking=yes','UpdateHostKeys=no',
    'UserKnownHostsFile=/Users/daniel/.ssh/known_hosts','GlobalKnownHostsFile=/dev/null',
    'KnownHostsCommand=none','HostKeyAlias=100.121.130.51','CanonicalizeHostname=no',
    'ProxyCommand=none','ProxyJump=none','PermitLocalCommand=no','RemoteCommand=none',
    'IdentityFile=/Users/daniel/.ssh/id_ed25519','IdentityAgent=none','IdentitiesOnly=yes',
    'CertificateFile=none','PreferredAuthentications=publickey','PasswordAuthentication=no',
    'KbdInteractiveAuthentication=no','GSSAPIAuthentication=no','HostbasedAuthentication=no',
    'ControlMaster=no','ControlPath=none','ForwardAgent=no','ForwardX11=no',
    'ExitOnForwardFailure=yes','GatewayPorts=no',
    'ServerAliveInterval=5','ServerAliveCountMax=2','LogLevel=ERROR')


class Denied(RuntimeError):pass
def need(value,code):
    if not value:raise Denied(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def private_read(path,limit,*,owner=501):
    path=Path(path);need(path.resolve(strict=True)==path,'PRIVATE_CANONICAL_INPUT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==owner and stat.S_IMODE(s.st_mode)==0o600 and
             s.st_nlink==1 and s.st_size<=limit,'PRIVATE_INPUT_PROFILE')
        chunks=[];size=0
        while True:
            raw=os.read(fd,min(65536,limit+1-size))
            if not raw:break
            chunks.append(raw);size+=len(raw);need(size<=limit,'PRIVATE_INPUT_BOUND')
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(size==s.st_size and all(tuple(getattr(v,k) for k in fields)==tuple(getattr(s,k) for k in fields)
             for v in (os.fstat(fd),path.lstat())),'PRIVATE_INPUT_CHANGED')
        return b''.join(chunks)
    finally:os.close(fd)


def load_source(name,raw):
    need(name in MODULES,'SOURCE_MODULE_SET')
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,None))
    exec(compile(raw,name,'exec'),module.__dict__)
    return module


def validate_inputs():
    scope_raw=private_read(INPUT/'SCOPE.json',512*1024);scope=json.loads(scope_raw)
    fields={'schema','transaction','host_id','contract_sha256','approval_sha256','output','socket_parent',
            'reader_scope','source_sha256','ssh_options_sha256','tool_sha256','client_closure_sha256',
            'schema_reference','native_evidence_sha256','tests_sha256'}
    need(set(scope)==fields and scope['schema']=='TU1NZ_REV4_PRESTOP_BACKUP_SCOPE_V1' and
         scope['transaction']==TX and scope['host_id']==109772243 and scope['contract_sha256']==DECISION and
         scope['approval_sha256']==APPROVAL and scope['output']==str(OUTPUT) and
         scope['socket_parent']==str(SOCKET) and scope['ssh_options_sha256']==sha(canonical(SSH_OPTIONS)) and
         set(scope['source_sha256'])==set(MODULES),'BACKUP_SCOPE_BINDING')
    review_raw=private_read(INPUT/'INDEPENDENT_REVIEW.json',65536);review=json.loads(review_raw)
    need(review.get('verdict')=='PASS' and review.get('scope_sha256')==sha(scope_raw) and
         review.get('independent_of_implementer') is True and review.get('unresolved_findings')==[],
         'INDEPENDENT_BACKUP_REVIEW_REQUIRED')
    source={}
    for name in MODULES:
        raw=private_read(INPUT/'source'/name,256*1024)
        need(sha(raw)==scope['source_sha256'][name] and (SOURCE/name).read_bytes()==raw,'REVIEWED_SOURCE_CHANGED')
        source[name]=raw
    reader=load_source(MODULES[1],source[MODULES[1]])
    reader.bound_selection(scope['reader_scope'])
    need(set(scope['tests_sha256'])==set(TESTS) and set(scope['native_evidence_sha256'])==set(EVIDENCE),
         'BACKUP_PROOF_SET')
    for name,digest in scope['tests_sha256'].items():
        need(sha((SOURCE.parent/name).read_bytes())==digest,'BACKUP_TEST_OR_WORKFLOW_CHANGED')
    proofs={}
    for name,digest in scope['native_evidence_sha256'].items():
        raw=private_read(INPUT.parent/name,512*1024)
        need(sha(raw)==digest,'BACKUP_NATIVE_PROOF_CHANGED');proofs[name]=json.loads(raw)
    mac,db,glue,linux=(proofs[n] for n in EVIDENCE)
    need(mac['restore']['status']=='PASS' and mac['restore']['proof']['actual_ownership'] is True and
         mac['restore']['proof']['empty_acl_xattrs'] is True and
         db['status']=='PASS_SYNTHETIC_NOT_REAL_HOST_RESTORE' and db['cleanup']==[] and
         db['source_sha256']==scope['source_sha256']['tu1nz_mainserver_restore.py'] and
         scope['source_sha256']['tu1nz_mainserver_file_restore.py']==
         'b0ef13342a722371f2fc9c79efa1b755e5cb0586c4cc74093389df697e5b54de' and
         glue['status']=='PASS_SYNTHETIC_NEW_LOCAL_INTEGRATION_NOT_REAL_RESTORE' and glue['cleanup']==[] and
         glue['cleanup_proof']['own_cluster_removed'] is True and
         linux['status']=='PASS_SYNTHETIC_LINUX_BACKUP_BOUNDARY' and
         linux['source_sha256']==scope['source_sha256'],'BACKUP_NATIVE_GATE')
    return scope,sha(scope_raw),sha(review_raw),source


def parse_dsn(raw,library):
    """Reuse the closed libpq parser; neither connects nor expands defaults."""
    need(0<len(raw)<=4096 and b'\0' not in raw,'DSN_BOUND')
    class Option(ctypes.Structure):
        _fields_=[(n,ctypes.c_char_p) for n in ('keyword','envvar','compiled','val','label','dispchar')]+[('dispsize',ctypes.c_int)]
    lib=ctypes.CDLL(str(library));lib.PQconninfoParse.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)]
    lib.PQconninfoParse.restype=ctypes.POINTER(Option);lib.PQconninfoFree.argtypes=[ctypes.POINTER(Option)]
    lib.PQfreemem.argtypes=[ctypes.c_void_p];error=ctypes.c_void_p()
    options=lib.PQconninfoParse(raw.strip(),ctypes.byref(error))
    try:
        need(bool(options),'DSN_PARSE');values={};index=0
        while options[index].keyword:
            need(index<256,'DSN_OPTIONS_BOUND');item=options[index]
            if item.val is not None:values[item.keyword.decode('ascii')]=item.val.decode('utf-8')
            index+=1
        return values
    finally:
        if options:lib.PQconninfoFree(options)
        if error.value:lib.PQfreemem(error)


def passfile_bytes(values):
    allowed={'user','password','dbname','host','port','sslmode','connect_timeout','application_name','channel_binding','gssencmode'}
    need(set(values)<=allowed and values.get('user')==ROLE and values.get('dbname')==DATABASE and
         values.get('host','') in ('','localhost','127.0.0.1','/var/run/postgresql') and
         values.get('port','5432')=='5432','DSN_SCOPE')
    need(values.get('sslmode','prefer') in ('disable','allow','prefer','require') and
         values.get('channel_binding','prefer') in ('disable','prefer','require') and
         values.get('gssencmode','prefer') in ('disable','prefer'),'DSN_STRONGER_BINDING_OR_OTHER_AUTH')
    password=values.get('password','')
    need(password and not any(c in password for c in '\r\n\0'),'DSN_PASSWORD_UNUSABLE')
    escaped=password.replace('\\','\\\\').replace(':','\\:')
    return ('127.0.0.1:15432:'+DATABASE+':'+ROLE+':'+escaped+'\n').encode()


def database_environment(root,base):
    """Explicit TLS/SCRAM channel binding inside the authenticated SSH path."""
    return {'PATH':'/usr/bin:/bin','LC_ALL':'C','PGHOST':'127.0.0.1','PGPORT':'15432',
            'PGUSER':ROLE,'PGDATABASE':DATABASE,'PGPASSFILE':str(root/'transient.pgpass'),
            'PGSERVICEFILE':'/dev/null','PGSSLMODE':'require','PGCHANNELBINDING':'require',
            'PGGSSENCMODE':'disable','PGCONNECT_TIMEOUT':'5','OPENSSL_CONF':'/dev/null',
            'OPENSSL_MODULES':str(base/'lib/ossl-modules'),
            **{key:str(root/name) for key,name in (
                ('PGSSLROOTCERT','absent-ca.crt'),('PGSSLCERT','absent-client.crt'),
                ('PGSSLKEY','absent-client.key'),('PGSSLCRL','absent-crl'),('PGSSLCRLDIR','absent-crldir'))}}


class PrivateSSH:
    def __init__(self,reader,scope,secret,deadline):
        self.deadline=deadline;self.child=None;self.selector=selectors.DefaultSelector()
        self.buffer=bytearray();self.err=bytearray();self.out_count=0;self.closed=False
        invocation=(reader.decode()+"\ntry:\n main("+repr(sha(canonical(scope)))+")\n"
                    "except BaseException as e:\n sys.stderr.write(type(e).__name__+'\\n');sys.exit(1)\n")
        command=shlex.join(['/usr/bin/sudo','-k','-S','-p','','--','/usr/bin/python3','-I','-B','-S','-c',invocation])
        argv=['/usr/bin/ssh','-F','/dev/null','-T']
        for option in SSH_OPTIONS:argv.extend(('-o',option))
        argv.extend(('-L','127.0.0.1:15432:127.0.0.1:5432','100.121.130.51',command))
        try:
            self.child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                        close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            for stream,label in ((self.child.stdout,'out'),(self.child.stderr,'err')):
                os.set_blocking(stream.fileno(),False);self.selector.register(stream,selectors.EVENT_READ,label)
            os.set_blocking(self.child.stdin.fileno(),False)
            self.write(secret);secret[:]=b'\0'*len(secret)
            self.write(canonical(scope)+b'\n')
        except BaseException:self.close();raise
        finally:secret[:]=b'\0'*len(secret)
    def live(self):need(time.monotonic()<self.deadline,'SSH_CAPTURE_DEADLINE')
    def pump(self):
        self.live()
        for key,_ in self.selector.select(.05):
            raw=os.read(key.fileobj.fileno(),65536)
            if not raw:self.selector.unregister(key.fileobj);continue
            if key.data=='err':
                self.err.extend(raw);need(len(self.err)<=65536,'SSH_ERROR_BOUND')
                # No raw diagnostics can be interpreted as protocol or printed.
                raise Denied('SSH_OR_SUDO_DIAGNOSTIC')
            self.buffer.extend(raw);self.out_count+=len(raw)
            need(len(self.buffer)<=16*1024*1024 and self.out_count<=64*1024*1024,'SSH_OUTPUT_BOUND')
    def write(self,raw):
        offset=0
        while offset<len(raw):
            self.live()
            try:offset+=os.write(self.child.stdin.fileno(),raw[offset:offset+65536])
            except BlockingIOError:self.pump()
    def frame(self):
        while b'\n' not in self.buffer:
            self.pump();need(self.selector.get_map() or b'\n' in self.buffer,'SSH_STREAM_TRUNCATED')
        raw,_,rest=self.buffer.partition(b'\n');self.buffer=bytearray(rest)
        return json.loads(raw)
    def finish(self):
        self.write(b'REV4_BACKUP_CLOSE\n');self.child.stdin.close()
        need(self.frame()=={'kind':'closed','fds_closed':True,'host_mutations':False},'HOST_READ_CLOSE_UNCONFIRMED')
        while self.selector.get_map():self.pump()
        need(not self.buffer and not self.err,'SSH_TRAILING_OUTPUT')
        need(self.child.wait(timeout=max(.001,self.deadline-time.monotonic()))==0,'SSH_EXIT')
        self.close()
    def close(self):
        if self.closed:return
        self.closed=True;self.selector.close()
        if self.child is not None:
            if self.child.poll() is None:self.child.kill();self.child.wait(timeout=5)
            for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
                if not stream.closed:stream.close()


def receive_files(channel,scope,root,r,f):
    wanted=scope['reader_scope']['files'];rows={};blobs={};total=0
    for path in sorted(wanted):
        frame=channel.frame()
        need(set(frame)=={'kind','path','row','content_base64'} and frame['kind']=='file' and frame['path']==path,
             'BACKUP_FILE_FRAME')
        row=frame['row'];encoded=frame['content_base64']
        need(type(row) is dict and set(row)=={'sha256','metadata'},'BACKUP_FILE_ROW')
        if encoded is None:need(row['sha256'] is None,'BACKUP_DIRECTORY_CONTENT')
        else:
            raw=base64.b64decode(encoded,validate=True);total+=len(raw)
            need(len(raw)<=8*1024*1024 and total<=32*1024*1024 and sha(raw)==row['sha256'],'BACKUP_FILE_HASH')
            if row['sha256'] not in blobs:r.private_create(root/'blobs'/row['sha256'],raw)
            blobs[row['sha256']]=raw
        rows[path]=row
    complete=channel.frame()
    keys={'kind','scope_sha256','machine_sha256','boot_id','started_unix','finished_unix','objects','bytes',
          'manifest_sha256','directories','semantics'}
    need(set(complete)==keys and complete['kind']=='files_complete' and
         complete['scope_sha256']==sha(canonical(scope['reader_scope'])) and
         complete['machine_sha256']==scope['reader_scope']['machine_sha256'] and
         re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',complete['boot_id']) and
         complete['objects']==len(rows)==102 and complete['bytes']==total and
         complete['manifest_sha256']==sha(canonical(rows)) and complete['semantics']==
         'PER_OBJECT_STABLE_PRESTOP_COPY_NOT_GLOBAL_ATOMIC_OR_WRITER_FENCED','BACKUP_COMPLETION_BINDING')
    f.profile(rows,blobs,wanted)
    r.private_create(root/'files.json',canonical(rows));r.private_create(root/'files-receipt.json',canonical(complete))
    need(json.loads(private_read(root/'files.json',512*1024))==rows,'FILE_MANIFEST_READBACK')
    for digest,raw in blobs.items():need(private_read(root/'blobs'/digest,8*1024*1024)==raw,'FILE_BLOB_READBACK')
    return rows,blobs,complete


def cleanup_owned_cluster(pg,root):
    """Only the ended, created private cluster; retain archive and receipts.

    Inventory first, same-device/no-links/owner/permissions checks throughout.
    No guessed glob, shared parent deletion, or cleanup of an unrelated server.
    """
    need(pg.created and pg.child is not None and pg.child.poll()==0,'RESTORE_PROCESS_NOT_CLEANLY_ENDED')
    root=Path(root);need(root==pg.root and root.resolve(strict=True)==root,'RESTORE_CLEANUP_ROOT')
    identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_mode)
    need(identity(root.lstat())==pg.restore_identity,'RESTORE_CLEANUP_ROOT_REPLACED')
    need(identity(pg.socket.lstat())==pg.socket_identity and
         identity(pg.socket.parent.lstat())==pg.socket_parent_identity,'RESTORE_SOCKET_REPLACED')
    rows=[];dirs=[];count=0;total=0;device=root.lstat().st_dev
    rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    def scan(parent,name):
        nonlocal count,total
        s=os.stat(name,dir_fd=parent,follow_symlinks=False);count+=1;total+=s.st_size
        need(count<=8192 and total<=2*1024**3 and s.st_dev==device and s.st_uid==os.geteuid() and
             not stat.S_IMODE(s.st_mode)&0o077 and (stat.S_ISDIR(s.st_mode) or
             (stat.S_ISREG(s.st_mode) and s.st_nlink==1)),'RESTORE_CLEANUP_FOREIGN_OBJECT')
        if stat.S_ISDIR(s.st_mode):
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);dirs.append(fd)
            need(len(dirs)<=128 and identity(os.fstat(fd))==identity(s),'RESTORE_CLEANUP_DIRECTORY_CHANGED')
            for child in sorted(os.listdir(fd)):scan(fd,child)
        rows.append((parent,name,s))
    try:
        need(identity(os.fstat(rootfd))==pg.restore_identity,'RESTORE_CLEANUP_ROOT_REPLACED')
        for name in sorted(os.listdir(rootfd)):scan(rootfd,name)
        for parent,name,s in rows:
            now=os.stat(name,dir_fd=parent,follow_symlinks=False)
            need(identity(now)==identity(s),'RESTORE_CLEANUP_REPLACED')
            if stat.S_ISDIR(s.st_mode):os.rmdir(name,dir_fd=parent)
            else:os.unlink(name,dir_fd=parent)
        need(os.listdir(rootfd)==[] and identity(root.lstat())==pg.restore_identity,'RESTORE_ROOT_FOREIGN_ENTRY')
        root.rmdir()
    finally:
        for fd in reversed(dirs):os.close(fd)
        os.close(rootfd)
    pg.socket.rmdir();pg.socket.parent.rmdir()
    return {'own_cluster_removed':True,'own_socket_removed':True,'objects':count,'archive_and_receipts_retained':True}


def main():
    need(sys.platform=='darwin' and os.geteuid()==501 and len(sys.argv)==1 and sys.stdin.isatty(),
         'PERSONAL_MAC_TTY_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    scope,scope_sha,review_sha,source=validate_inputs()
    r=load_source(MODULES[2],source[MODULES[2]]);f=load_source(MODULES[3],source[MODULES[3]])
    closure=private_read(CLIENT/'CLIENT_CLOSURE.json',1024*1024)
    need(sha(closure)==scope['client_closure_sha256'],'CLIENT_CLOSURE_CHANGED')
    base=CLIENT/'Postgres.app/Contents/Versions/17'
    need(r.verify_local_tools(base,json.loads(closure))==scope['tool_sha256'],'TOOL_BINDING_CHANGED')
    ddl,grants,reference=r.trusted_schema(APP);need(reference==scope['schema_reference'],'TRUSTED_SCHEMA_CHANGED')
    need(not os.path.lexists(OUTPUT) and not os.path.lexists(SOCKET),'BACKUP_ENTRY_ALREADY_PRESENT')
    parent=OUTPUT.parent
    need(parent.resolve(strict=True)==parent and parent.stat().st_uid==501 and
         stat.S_IMODE(parent.stat().st_mode)==0o700,'BACKUP_PRIVATE_PARENT')
    capacity=os.statvfs(parent)
    need(capacity.f_bavail*capacity.f_frsize>=4*1024**3,'BACKUP_FREE_CAPACITY')
    code,out,err=r.bounded_process(['/usr/bin/fdesetup','status'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                                  deadline=time.monotonic()+5)
    need(code==0 and not err and out==b'FileVault is On.\n','MAC_STORAGE_PROTECTION')
    with socket.socket() as probe:probe.bind(('127.0.0.1',15432))
    print('Hauptserver 109772243: gebundene Dateisicherung und lesender S7-Snapshot; keine Dienstaktion.')
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        password=getpass.getpass('sudo-Passwort für chatops persönlich eingeben (unsichtbar): ')
    need(password and len(password)<=1024 and not any(c in password for c in '\n\r\0'),'PERSONAL_PASSWORD_INPUT')
    secret=bytearray(password.encode()+b'\n');del password
    OUTPUT.mkdir(mode=0o700);(OUTPUT/'blobs').mkdir(mode=0o700);SOCKET.mkdir(mode=0o700)
    r.private_create(OUTPUT/'ATTEMPT.json',canonical({'scope_sha256':scope_sha,'review_sha256':review_sha,
        'started_unix':time.time(),'kind':'PRESTOP_COPY_NOT_HOST_CLAIM','retry_automatically':False}))
    r.private_create(OUTPUT/'trusted-schema.sql',ddl);r.private_create(OUTPUT/'trusted-grants.sql',grants)
    result={'schema':'TU1NZ_REV4_PRESTOP_BACKUP_RESULT_V1','scope_sha256':scope_sha,'review_sha256':review_sha,
            'status':'HOLD','host_services_changed':False,'production_restore':False,'cleanup':[]}
    pg=channel=snapshot=None;pass_identity=None
    try:
        # Trusted empty schema/rights first. No production credentials or roles
        # enter this Unix-only cluster; same-named counterparts are NOLOGIN.
        pg=r.PrivatePostgres(base,OUTPUT/'db-restore',SOCKET/'s',deadline=time.monotonic()+300)
        pg.start()
        identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_mode)
        pg.restore_identity=identity(pg.root.lstat());pg.socket_identity=identity(pg.socket.lstat())
        pg.socket_parent_identity=identity(pg.socket.parent.lstat())
        pg.query(('CREATE ROLE postgres NOLOGIN; CREATE ROLE '+ROLE+' NOLOGIN NOSUPERUSER NOCREATEDB '
            'NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE real_restore;\n').encode())
        pg.env['PGDATABASE']='real_restore'
        pg.query(b'GRANT CREATE,USAGE ON SCHEMA public TO postgres; SET ROLE postgres;\n'+ddl+grants+b'RESET ROLE;\n')
        local_catalog=pg.query(r.catalog_transaction());local_rights=pg.query(r.rights_transaction())
        layout=r.copy_layout(r.structural_catalog(local_catalog))
        capture_started=time.monotonic();deadline=capture_started+300
        channel=PrivateSSH(source[MODULES[1]],scope['reader_scope'],secret,deadline)
        rows,blobs,files_receipt=receive_files(channel,scope,OUTPUT,r,f)
        dsn=blobs[rows['/etc/tu1nz/adult-commercial-s7-database.dsn']['sha256']]
        values=parse_dsn(dsn,base/'lib/libpq.5.dylib')
        r.private_create(OUTPUT/'transient.pgpass',passfile_bytes(values));del dsn,values
        pass_identity=(OUTPUT/'transient.pgpass').lstat()
        snapshot=r.ReadOnlySnapshot(base,database_environment(OUTPUT,base),deadline=deadline)
        identity=snapshot.start(database=DATABASE,role=ROLE)
        source_catalog=snapshot.read('catalog');source_rights=snapshot.read('rights')
        admission=r.compare_restore_catalog(source_catalog,local_catalog,source_rights,local_rights)
        r.private_create(OUTPUT/'source-catalog.jsonl',source_catalog);r.private_create(OUTPUT/'source-rights.jsonl',source_rights)
        before={n:r.fingerprint(snapshot.read('fingerprint',layout,n)) for n in r.TABLES}
        archive=snapshot.dump();r.private_create(OUTPUT/'s7.dump',archive)
        need(private_read(OUTPUT/'s7.dump',r.MAX_DATA)==archive,'DB_ARCHIVE_FULL_READBACK')
        need(before=={n:r.fingerprint(snapshot.read('fingerprint',layout,n)) for n in r.TABLES},'DB_SNAPSHOT_CHANGED')
        snapshot.close();snapshot=None;channel.finish();channel=None
        result['capture_seconds']=time.monotonic()-capture_started
        result['snapshot']={**identity,'captured_unix':time.time(),'fingerprints':before,'archive_sha256':sha(archive)}
        result['file_copy']=files_receipt
        # Local restore has its own pre-stop test deadline, never extends the
        # read-only capture or either later 600-second Host execution window.
        pg.deadline=time.monotonic()+300
        code,rendered,err=pg.call('pg_restore',['--data-only','--no-owner','--no-privileges','--file=-',str(OUTPUT/'s7.dump')],limit=r.MAX_DATA)
        need(code==0 and not err,'DB_ARCHIVE_RENDER');copies=r.extract_copy_data(rendered,layout)
        pg.restore_copies(copies,layout)
        restored_catalog=pg.query(r.catalog_transaction());restored_rights=pg.query(r.rights_transaction())
        result['restore_catalog']=r.compare_restore_catalog(source_catalog,restored_catalog,source_rights,restored_rights)
        after={n:r.fingerprint(pg.query(b'BEGIN READ ONLY; SET LOCAL search_path=pg_catalog;\n'+
            r.fingerprint_sql(n,layout)+b'ROLLBACK;\n')) for n in r.TABLES}
        need(before==after,'REAL_DB_RESTORE_CONTENT_MISMATCH')
        result['restored_fingerprints']=after
        r.private_create(OUTPUT/'restored-catalog.jsonl',restored_catalog);r.private_create(OUTPUT/'restored-rights.jsonl',restored_rights)
        result['status']='REAL_DB_RESTORE_AND_FILE_READBACK_PASS_PRIVILEGED_FILE_RESTORE_PENDING'
    except BaseException as error:
        # Fixed exception codes only. Never include psql errors/rows/passwords.
        result['failure']=str(error) if isinstance(error,(Denied,r.Denied,f.Denied)) else type(error).__name__
    finally:
        secret[:]=b'\0'*len(secret)
        for obj,label in ((snapshot,'SOURCE_SNAPSHOT'),(channel,'SSH'),(pg,'PRIVATE_POSTGRES')):
            if obj is not None:
                try:obj.close()
                except BaseException:result['cleanup'].append(label+'_CLOSE_UNCONFIRMED')
        if pass_identity is not None:
            try:
                now=(OUTPUT/'transient.pgpass').lstat()
                need((now.st_dev,now.st_ino,now.st_uid,now.st_mode)==
                     (pass_identity.st_dev,pass_identity.st_ino,pass_identity.st_uid,pass_identity.st_mode),
                     'TRANSIENT_AUTH_FILE_REPLACED')
                (OUTPUT/'transient.pgpass').unlink()
            except BaseException:result['cleanup'].append('TRANSIENT_AUTH_CLEANUP_UNCONFIRMED')
        if pg is not None and pg.child is not None and pg.child.poll()==0:
            try:
                r.private_create(OUTPUT/'restore-server.log',private_read(pg.root/'server.log',1024*1024))
                result['private_restore_cleanup']=cleanup_owned_cluster(pg,pg.root)
            except BaseException:result['cleanup'].append('PRIVATE_RESTORE_DATA_CLEANUP_UNCONFIRMED')
        else:result['cleanup'].append('PRIVATE_RESTORE_DATA_RETAINED_AFTER_FAILURE')
        if result['cleanup']:result['status']='HOLD'
        r.private_create(OUTPUT/'RESULT.json',canonical(result))
    print('Ergebnis:',result['status'],'— Daten und Einzelbelege bleiben privat.')
    return 0 if result['status'].startswith('REAL_DB_RESTORE_AND_FILE_READBACK_PASS') else 1


if __name__=='__main__':
    if sys.argv[1:]==['--help']:print(__doc__)
    else:
        try:raise SystemExit(main())
        except Exception as error:
            print('Abbruch:',str(error) if isinstance(error,Denied) else type(error).__name__)
            raise SystemExit(1)
