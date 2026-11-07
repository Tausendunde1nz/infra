"""One expressly approved S7 supplement. Import is inert; E1 stays HOLD.

Fixed local custody, one SSH child, at most eight source sessions with one
snapshot and at most two concurrent sessions. No service/Host mutation/retry.
"""
import ast
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
INPUT=D/'execution/s7-noinherit-followup-20261106'
PREVIOUS_INPUT=D/'execution/s7-supplement-20261106'
PROPOSAL=D/'execution/s7-noinherit-proposal-20261106'
E1=D/'execution/db-completion'
SOURCE=Path('/Users/daniel/Developer/tu1nz/infra-mainserver-recovery-r4-20261104/scripts')
PARENT=Path('/Users/daniel/.codex/backups/mainserver-recovery-20261101/pre-stop-protection')/TX
PREVIOUS_OUTPUT=PARENT/'s7-supplement-20261106'
OUTPUT=PREVIOUS_OUTPUT/'noinherit-followup-1'
SOCKET=Path('/private/tmp/tu1nz-mainserver-restore-public-rights-20261014-1')
APPROVAL='f1130ae96d6e45a55655df1bb8e705a89a33a27309a8af64e1314e23c1fbe208'
E1_SCOPE='38ca6a048c4f7cdb69aa93ffa8afe581482118a66a3286dbc76e61cda1d659db'
E1_REVIEW='ca50ee695592c600e3d6a40a002a7be3312b1fa279afba2588fb72ccf3688fc5'
E1_ATTEMPT='9f17ff628d264ca1ff0d108aa3dbab867d38da7c0730f1e63ece119d1c7597e6'
E1_RESULT='edf69f4c8b2a900aae1be4efb355d933681dd19e1f11767f78e86a3f93ba31a3'
NEW_MODULES=('tu1nz_mainserver_s7_noinherit.py','tu1nz_mainserver_s7_noinherit_file_restore.py')
PREVIOUS_MODULES=('tu1nz_mainserver_s7_supplement.py','tu1nz_mainserver_s7_file_restore.py')
OLD_MODULES=('tu1nz_mainserver_db_completion.py','tu1nz_mainserver_db_file_restore.py',
 'tu1nz_mainserver_backup.py','tu1nz_mainserver_restore.py','tu1nz_mainserver_file_restore.py',
 'tu1nz_mainserver_file_restore_entry.py')
MODULES=NEW_MODULES+OLD_MODULES+PREVIOUS_MODULES
TESTS=('tests/test_mainserver_s7_noinherit.py','.github/workflows/mainserver-s7-noinherit.yml')
PASS='PASS_S7_REAL_DB_RESTORE_CLEAN_FIRST_FILE_RESTORE_PENDING'
CAPTURE={'ATTEMPT.json','RESULT.json','source-catalog.jsonl','source-rights.jsonl','s7.dump',
 'restored-catalog.jsonl','restored-rights.jsonl','restore-server.log','transport.json'}

PREVIOUS_INPUT_SHA256={'SCOPE.json': 'edd472bb647015feaa713b60b6f493d6927029499b070b0200a4a7f55a28adf4', 'INDEPENDENT_REVIEW.json': 'f3e1566811554048879bdd8c8ac71658f3377494d3a5527bc1f396c0d4a0ec0e'}
PROPOSAL_SHA256={'SCOPE.json': '73611caf8cb63decf895ca74d10e9e03d310ef84ea2a17f5745e1f63ae4b8547', 'NOINHERIT.patch': '73920d0b4344077d1129eab6ece642a7ede59e8b96e5c182432bfeea1ab0e8b9', 'candidate/tu1nz_mainserver_db_completion.py': '3bc0d68032b3f153c16fa67ff33843c610c3dd26fbaedf3bc47ac904f48bc89a', 'TEST_RESULT.json': 'b121bbd5da5b43a67876e824ababeaa38448e9e74a86254ae88e1715409b0350', 'INDEPENDENT_REVIEW.json': 'b761897024efdf3117354ddf8d3c7a5d04713e167a95b43354acb2bf1210ff2b', 'REVIEW_BINDING.json': 'f23f277555fa95103083368dbf644f7c1b19cf0d5b8ce4825ae15e75e02e6b57'}
PREVIOUS_OUTPUT_SHA256={'ATTEMPT.json': '9a61132a86a57c4ae13356a02ef0aa68cf6d28047d0433561009239e25edfb70', 'RESULT.json': 'd29b11ff9bef1df1f16498a265cba5f031a9a2713c6d7c52a112f124767345e9', 'source-catalog.jsonl': 'f5a358aab4405e112e8bb711e10bbbdc29c1cde21908f0ea2d342508d9b09e38', 'source-rights.jsonl': '3bd33e6425c6336fd4498f4d4f18f5aa5bafc5e5882cf37db67a74cb8d77120e', 'restore-server.log': '120e661713ae64f17a0f2f13b384d8f9164d410865e98c34c6dd66a186cf3832', 'transport.json': 'b9d93ffd345d173522a04f51595b82af2796fe976ae9b3dd222577bfee92cba5'}
PREVIOUS_ATTEMPT=PREVIOUS_OUTPUT_SHA256['ATTEMPT.json']
PREVIOUS_HOLD=PREVIOUS_OUTPUT_SHA256['RESULT.json']


class Denied(RuntimeError):
    def __init__(self,code,observation=None):
        super().__init__(code);self.observation=observation
def need(value,code):
    if not value:raise Denied(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def identity(s):return s.st_dev,s.st_ino,s.st_uid,s.st_mode


def read(path,limit,owner=501):
    path=Path(path);need(path.resolve(strict=True)==path,'S7_INPUT_CANONICAL')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid==owner and stat.S_IMODE(before.st_mode)==0o600 and
                before.st_nlink==1 and 0<=before.st_size<=limit):
            raise Denied('S7_INPUT_PROFILE',{'path':str(path),'checkpoint':'profile',
                'expected':{'regular':True,'uid':owner,'mode':384,'nlink':1,'size_min':0,'size_max':limit},
                'actual':{'regular':stat.S_ISREG(before.st_mode),'uid':before.st_uid,'mode':stat.S_IMODE(before.st_mode),
                          'nlink':before.st_nlink,'size':before.st_size}})
        raw=b''
        while len(raw)<=limit:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw+=part
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        after_fd,after_path=os.fstat(fd),path.lstat()
        if not (len(raw)==before.st_size and all(tuple(getattr(v,k) for k in fields)==tuple(getattr(before,k) for k in fields)
                for v in (after_fd,after_path))):
            raise Denied('S7_INPUT_CHANGED',{'path':str(path),'checkpoint':'stable_read',
                'bytes_read':len(raw),'expected':dict(zip(fields,(getattr(before,k) for k in fields))),
                'actual_fd':dict(zip(fields,(getattr(after_fd,k) for k in fields))),
                'actual_path':dict(zip(fields,(getattr(after_path,k) for k in fields)))})
        return raw
    finally:os.close(fd)


def directory(path):
    need(path.resolve(strict=True)==path,'S7_DIRECTORY_CANONICAL');s=path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o700,'S7_DIRECTORY_PROFILE')
    return identity(s)


def load(name,raw):
    need(name in MODULES,'S7_MODULE_SET')
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,None))
    exec(compile(raw,name,'exec'),module.__dict__);return module


def validate_inputs():
    raw=read(INPUT/'SCOPE.json',512*1024);scope=json.loads(raw)
    need(set(scope)=={'schema','transaction','host_id','approval_sha256','output','socket_parent',
        'source_sha256','tests_sha256','proof_sha256','e1_scope_sha256','e1_review_sha256','e1_extra_sha256',
        'previous_input_sha256','previous_output_sha256','proposal_sha256'} and
        scope['schema']=='TU1NZ_S7_NOINHERIT_SCOPE_V1' and scope['transaction']==TX and scope['host_id']==109772243 and
        scope['approval_sha256']==APPROVAL and scope['output']==str(OUTPUT) and scope['socket_parent']==str(SOCKET) and
        scope['e1_scope_sha256']==E1_SCOPE and scope['e1_review_sha256']==E1_REVIEW,'S7_SCOPE')
    need(sha(read(INPUT/'APPROVAL.json',65536))==APPROVAL,'S7_APPROVAL')
    review_raw=read(INPUT/'INDEPENDENT_REVIEW.json',65536);review=json.loads(review_raw)
    need(review.get('verdict')=='PASS' and review.get('independent_of_implementer') is True and
         review.get('scope_sha256')==sha(raw) and review.get('unresolved_findings')==[],'S7_REVIEW')
    need(set(scope['source_sha256'])==set(MODULES) and set(scope['tests_sha256'])==set(TESTS) and
         set(scope['proof_sha256'])=={'native/RESULT.json','linux-native.json'},'S7_BOUND_SETS')
    source={}
    for name,digest in scope['source_sha256'].items():
        source[name]=read(INPUT/'source'/name,256*1024)
        need(sha(source[name])==digest and (SOURCE/name).read_bytes()==source[name],'S7_SOURCE_CHANGED')
    for name,digest in scope['tests_sha256'].items():need(sha((SOURCE.parent/name).read_bytes())==digest,'S7_TEST_CHANGED')
    proofs={}
    for name,digest in scope['proof_sha256'].items():
        data=read(INPUT/name,512*1024);need(sha(data)==digest,'S7_PROOF_CHANGED');proofs[name]=json.loads(data)
    native,linux=proofs['native/RESULT.json'],proofs['linux-native.json']
    need(native['status']=='PASS_S7_NATIVE_SYNTHETIC_NOT_REAL_DATA' and native['cleanup']==[] and
         native['source_sha256']==linux['source_sha256']==scope['source_sha256'] and
         linux['status']=='PASS_S7_LINUX_SYNTHETIC' and linux['skipped']==0,'S7_NATIVE_GATES')
    need(scope['previous_input_sha256']==PREVIOUS_INPUT_SHA256 and
         scope['previous_output_sha256']==PREVIOUS_OUTPUT_SHA256 and
         scope['proposal_sha256']==PROPOSAL_SHA256,'S7_PREVIOUS_BINDING')
    for name,digest in PREVIOUS_INPUT_SHA256.items():
        need(sha(read(PREVIOUS_INPUT/name,512*1024))==digest,'S7_PREVIOUS_INPUT_CHANGED')
    proposal={}
    for name,digest in PROPOSAL_SHA256.items():
        proposal[name]=read(PROPOSAL/name,512*1024)
        need(sha(proposal[name])==digest,'S7_PROPOSAL_CHANGED')
    reviewed=json.loads(proposal['INDEPENDENT_REVIEW.json'])
    need(reviewed['verdict']=='PASS' and reviewed['independent_of_implementer'] is True and
         reviewed['unresolved_findings']==[] and reviewed['scope_sha256']==PROPOSAL_SHA256['SCOPE.json'],
         'S7_NOINHERIT_REVIEW')
    def initializer(raw):
        tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='initialize_pg']
        need(len(nodes)==1,'S7_NOINHERIT_FUNCTION_SET');return ast.dump(nodes[0],include_attributes=False)
    need(initializer(source[NEW_MODULES[0]])==initializer(proposal['candidate/tu1nz_mainserver_db_completion.py']),
         'S7_NOINHERIT_DELTA_CHANGED')
    previous=load(PREVIOUS_MODULES[0],source[PREVIOUS_MODULES[0]])
    previous_scope,previous_sha,previous_review,previous_source,c,b,old=previous.validate_inputs()
    need(previous_sha==PREVIOUS_INPUT_SHA256['SCOPE.json'] and
         previous_review==PREVIOUS_INPUT_SHA256['INDEPENDENT_REVIEW.json'] and
         all(source[n]==previous_source[n] for n in OLD_MODULES+PREVIOUS_MODULES) and
         scope['e1_extra_sha256']==previous_scope['e1_extra_sha256'],'S7_PREVIOUS_SOURCE_CHANGED')
    need(set(scope['e1_extra_sha256'])=={'DB_COMPLETION_ATTEMPT.json','DB_COMPLETION_RESULT.json','db-completion-restore-server.log'} and
         scope['e1_extra_sha256']['DB_COMPLETION_ATTEMPT.json']==E1_ATTEMPT and
         scope['e1_extra_sha256']['DB_COMPLETION_RESULT.json']==E1_RESULT,'S7_E1_HOLD_BINDING')
    return scope,sha(raw),sha(review_raw),source,c,b,old


def prior_files(scope,c,b,f,old,*,supplement_exists):
    directory(PARENT);directory(PARENT/'blobs')
    allowed=set(c.ORIGINAL)|set(scope['e1_extra_sha256'])|{PREVIOUS_OUTPUT.name}
    need(set(os.listdir(PARENT))==allowed,'S7_PARENT_FOREIGN_OR_OCCUPIED')
    originals={name:read(PARENT/name,1024*1024) for name in c.ORIGINAL if name!='blobs'}
    need(set(originals)==set(old['original_sha256']) and
         all(sha(raw)==old['original_sha256'][name] for name,raw in originals.items()),'S7_ORIGINAL_CHANGED')
    for name,digest in scope['e1_extra_sha256'].items():
        originals[name]=read(PARENT/name,1024*1024);need(sha(originals[name])==digest,'S7_E1_HOLD_CHANGED')
    failed=json.loads(originals['DB_COMPLETION_RESULT.json'])
    need(failed['status']=='HOLD' and failed['failure']=='E1_CHANNEL_LOST_OR_DEADLINE' and
         failed['source_snapshot_cleanup']=='NOT_STARTED' and failed['cleanup']==[] and
         failed['private_restore_cleanup']['own_cluster_removed'] is True and
         failed['private_restore_cleanup']['own_socket_removed'] is True,'S7_PRIOR_CLEANUP_UNKNOWN')
    need(sha(read(c.OLD/'SCOPE.json',512*1024))==c.OLD_SCOPE,'S7_ORIGINAL_SCOPE_CHANGED')
    paths=json.loads(read(c.OLD/'SCOPE.json',512*1024))['reader_scope']['files']
    manifest=json.loads(originals['files.json']);receipt=json.loads(originals['files-receipt.json'])
    need(receipt['objects']==len(manifest)==102 and receipt['bytes']==6533068 and
         receipt['manifest_sha256']==sha(originals['files.json']),'S7_FILE_RECEIPT')
    digests={row['sha256'] for row in manifest.values() if row['sha256'] is not None}
    need(set(os.listdir(PARENT/'blobs'))==digests and all(re.fullmatch('[0-9a-f]{64}',s) for s in digests),'S7_BLOB_SET')
    blobs={digest:read(PARENT/'blobs'/digest,8*1024*1024) for digest in digests}
    need(f.profile(manifest,blobs,paths)==receipt['bytes'],'S7_FILE_READBACK')
    originals.update(previous_hold(supplement_exists=supplement_exists))
    return manifest,blobs,paths,originals


def previous_hold(*,supplement_exists):
    directory(PREVIOUS_OUTPUT)
    allowed=set(PREVIOUS_OUTPUT_SHA256)|({OUTPUT.name} if supplement_exists else set())
    need(set(os.listdir(PREVIOUS_OUTPUT))==allowed,'S7_PREVIOUS_OUTPUT_FOREIGN_OR_OCCUPIED')
    originals={}
    for name,digest in PREVIOUS_OUTPUT_SHA256.items():
        raw=read(PREVIOUS_OUTPUT/name,1024*1024)
        need(sha(raw)==digest,'S7_PREVIOUS_HOLD_CHANGED');originals[PREVIOUS_OUTPUT.name+'/'+name]=raw
    failed=json.loads(originals[PREVIOUS_OUTPUT.name+'/RESULT.json'])
    need(failed['status']=='HOLD' and failed['failure']=='SOURCE_RIGHTS_DIFFER_FROM_TRUSTED_RESTORE' and
         failed['source_sessions']=={'attempted':3,'max_simultaneous':2} and
         failed['source_snapshot_cleanup']=='ROLLBACK_ACKNOWLEDGED' and failed['cleanup']==[] and
         failed['private_restore_cleanup']['own_cluster_removed'] is True and
         failed['private_restore_cleanup']['own_socket_removed'] is True,'S7_PREVIOUS_CLEANUP_UNKNOWN')
    return originals


def port_free():
    with socket.socket() as probe:probe.bind(('127.0.0.1',15432))


class ObservedTunnel:
    """Bounded diagnostic belongs to this one child, including constructor failure."""
    def __init__(self,b,r,deadline,receipt):
        self.child=None;self.closed=False;self.r=r;self.deadline=deadline;self.started=time.monotonic()
        self.ready_deadline=min(deadline,self.started+10)
        self.selector=selectors.DefaultSelector();self.buffers={'stdout':bytearray(),'stderr':bytearray()}
        self.receipt=receipt;receipt.update(phase='SPAWN',launches=0,deadline_seconds=300,
            readiness_seconds=10,diagnostic_bytes_per_stream_max=4096,truncated=False)
        argv=['/usr/bin/ssh','-F','/dev/null','-T','-N']
        for option in b.SSH_OPTIONS:argv.extend(('-o',option))
        argv.extend(('-L','127.0.0.1:15432:127.0.0.1:5432','100.121.130.51'))
        try:
            receipt['launches']=1
            self.child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            for stream,name in ((self.child.stdout,'stdout'),(self.child.stderr,'stderr')):
                os.set_blocking(stream.fileno(),False);self.selector.register(stream,selectors.EVENT_READ,name)
            receipt['phase']='WAIT_FIXED_LISTENER';ready=self.ready_deadline
            while True:
                self.live();need(time.monotonic()<ready,'S7_READY_DEADLINE')
                code,out,err=r.bounded_process(['/usr/sbin/lsof','-nP','-a','-p',str(self.child.pid),
                    '-iTCP@127.0.0.1:15432','-sTCP:LISTEN','-Fpn'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                    deadline=ready,limit=4096)
                need(not err and code in (0,1),'S7_LISTENER_UNKNOWN')
                if code==0:
                    need(re.fullmatch(('p'+str(self.child.pid)+r'\nf[0-9]{1,6}\nn127\.0\.0\.1:15432\n').encode(),out),
                         'S7_LISTENER_MISMATCH');self.live();receipt['phase']='READY';break
                need(not out,'S7_LISTENER_UNKNOWN');time.sleep(.05)
        except BaseException:self.abort();raise
    def drain(self):
        for key,_ in self.selector.select(0):
            try:raw=os.read(key.fileobj.fileno(),4097)
            except BlockingIOError:continue
            if not raw:self.selector.unregister(key.fileobj);continue
            target=self.buffers[key.data];room=4096-len(target);target.extend(raw[:room])
            if len(raw)>room:self.receipt['truncated']=True
    def observe(self):
        self.drain();self.receipt.update(elapsed_seconds=time.monotonic()-self.started,
            deadline_expired=time.monotonic()>=self.deadline,
            readiness_deadline_expired=(time.monotonic()>=self.ready_deadline if self.receipt['phase']=='WAIT_FIXED_LISTENER' else None),
            child_status=None if self.child is None else self.child.poll())
    def live(self):
        self.observe()
        need(not self.receipt['deadline_expired'],'S7_CAPTURE_DEADLINE')
        need(self.child is not None and self.child.poll() is None,'S7_TRANSPORT_EXIT')
        need(not self.receipt['truncated'] and not any(self.buffers.values()),'S7_TRANSPORT_DIAGNOSTIC')
    def finish(self):
        self.live();self.receipt['phase']='OWN_TERMINATION_AFTER_ROLLBACK';self.child.terminate()
        try:code=self.child.wait(timeout=max(.001,min(5,self.deadline-time.monotonic())))
        except subprocess.TimeoutExpired:self.abort();raise Denied('S7_TUNNEL_CLOSE_UNCONFIRMED') from None
        self.observe();need(time.monotonic()<self.deadline and code in (0,255,-signal.SIGTERM),'S7_TUNNEL_CLOSE_UNCONFIRMED')
        need(not self.receipt['truncated'] and not any(self.buffers.values()),'S7_TUNNEL_CLOSE_DIAGNOSTIC')
        self.receipt['normal_close_after_rollback']=True;self.abort();port_free()
        return {'own_ssh_ended':True,'local_forward_removed':True,'remote_program_executed':False,
                'remote_process_cleanup_observed':False,'exit_after_own_SIGTERM':code}
    def abort(self):
        if self.closed:return
        try:
            self.observe();self.receipt['status_before_cleanup']=self.receipt['child_status']
            if self.child is not None and self.child.poll() is None:
                self.receipt['forced_own_child_kill']=True;self.child.kill();self.child.wait(timeout=5)
            self.observe();self.receipt['own_child_ended']=self.child is None or self.child.poll() is not None
            for name,raw in self.buffers.items():self.receipt[name+'_private']=bytes(raw).decode('utf-8','replace')
        finally:
            self.closed=True;self.selector.close()
            if self.child is not None:
                for stream in (self.child.stdout,self.child.stderr):
                    if stream is not None and not stream.closed:stream.close()


class SnapshotBudget:
    """Fixed synchronous order: one anchor plus seven sequential workers."""
    def __init__(self,snapshot,tables,receipt):
        self.inner=snapshot;self.receipt=receipt;self.index=0;self.worker=False;self.token=None
        self.plan=('start','catalog','rights',*(('fingerprint',n) for n in tables),'dump',
                   *(('fingerprint',n) for n in tables))
        need(len(self.plan)==8,'S7_SESSION_PLAN');receipt.update(attempted=0,max_simultaneous=0)
    def reserve(self,kind):
        need(not self.worker and self.index<8 and self.plan[self.index]==kind,'S7_SESSION_BUDGET_OR_ORDER')
        if self.index:need(self.inner.token==self.token and self.token is not None,'S7_SNAPSHOT_CHANGED')
        self.index+=1;self.receipt['attempted']=self.index
        self.receipt['max_simultaneous']=1 if self.index==1 else 2;self.worker=True
    def start(self,**kwargs):
        self.reserve('start')
        try:
            value=self.inner.start(**kwargs);self.token=self.inner.token;return value
        finally:self.worker=False
    def read(self,kind,layout=None,table=None):
        self.reserve((kind,table) if kind=='fingerprint' else kind)
        try:return self.inner.read(kind,layout,table)
        finally:self.worker=False
    def dump(self):
        self.reserve('dump')
        try:return self.inner.dump()
        finally:self.worker=False
    def close(self):self.inner.close()


def capture_and_restore(r,b,pg,base,local_catalog,local_rights,receipt,*,tunnel_factory=ObservedTunnel,snapshot_factory=None):
    layout=r.copy_layout(r.structural_catalog(local_catalog));snapshot=channel=None
    started=time.monotonic();deadline=started+300;receipt['source_snapshot_cleanup']='NOT_STARTED'
    receipt['transport_diagnostic']={};receipt['source_sessions']={'attempted':0,'max_simultaneous':0}
    try:
        receipt['phase']='SSH_CHANNEL_SETUP';channel=tunnel_factory(b,r,deadline,receipt['transport_diagnostic'])
        env=b.database_environment(OUTPUT,base);env['PGPASSFILE']=str(OUTPUT/'transient.pgpass')
        inner=(snapshot_factory or r.ReadOnlySnapshot)(base,env,deadline=deadline)
        snapshot=SnapshotBudget(inner,r.TABLES,receipt['source_sessions']);receipt['source_snapshot_cleanup']='UNCONFIRMED'
        receipt['phase']='SOURCE_SNAPSHOT';snapshot_started=time.time()
        source_identity=snapshot.start(database=b.DATABASE,role=b.ROLE);channel.live()
        catalog=snapshot.read('catalog');channel.live();rights=snapshot.read('rights');channel.live()
        r.private_create(OUTPUT/'source-catalog.jsonl',catalog);r.private_create(OUTPUT/'source-rights.jsonl',rights)
        receipt['admission']=r.compare_restore_catalog(catalog,local_catalog,rights,local_rights)
        before={}
        for name in r.TABLES:before[name]=r.fingerprint(snapshot.read('fingerprint',layout,name));channel.live()
        receipt['phase']='SOURCE_DUMP';archive=snapshot.dump();channel.live();r.private_create(OUTPUT/'s7.dump',archive)
        need(read(OUTPUT/'s7.dump',r.MAX_DATA)==archive,'S7_ARCHIVE_READBACK')
        for name in r.TABLES:
            need(before[name]==r.fingerprint(snapshot.read('fingerprint',layout,name)),'S7_SNAPSHOT_DRIFT');channel.live()
        need(snapshot.index==8,'S7_SESSION_COUNT');closing=snapshot;snapshot=None;closing.close();channel.live()
        receipt['snapshot_rollback_acknowledged']=True;receipt['source_snapshot_cleanup']='ROLLBACK_ACKNOWLEDGED'
        receipt['transport']=channel.finish();channel=None
        receipt['capture_seconds']=time.monotonic()-started;need(receipt['capture_seconds']<300,'S7_CAPTURE_DEADLINE')
        receipt['snapshot']={**source_identity,'fingerprints':before,'archive_sha256':sha(archive),
            'snapshot_started_unix':snapshot_started,'captured_unix':time.time()}
        receipt['phase']='ISOLATED_RESTORE';restore_started=time.monotonic();pg.deadline=restore_started+300
        code,rendered,err=pg.call('pg_restore',['--data-only','--no-owner','--no-privileges','--file=-',str(OUTPUT/'s7.dump')],limit=r.MAX_DATA)
        need(code==0 and not err,'S7_ARCHIVE_RENDER');pg.restore_copies(r.extract_copy_data(rendered,layout),layout)
        restored=pg.query(r.catalog_transaction());restored_rights=pg.query(r.rights_transaction())
        receipt['restored_catalog']=r.compare_restore_catalog(catalog,restored,rights,restored_rights)
        after={n:r.fingerprint(pg.query(b'BEGIN READ ONLY; SET LOCAL search_path=pg_catalog;\n'+r.fingerprint_sql(n,layout)+b'ROLLBACK;\n')) for n in r.TABLES}
        need(before==after,'S7_RESTORED_CONTENT_MISMATCH')
        r.private_create(OUTPUT/'restored-catalog.jsonl',restored);r.private_create(OUTPUT/'restored-rights.jsonl',restored_rights)
        need(time.monotonic()<pg.deadline,'S7_RESTORE_DEADLINE')
        receipt['restored_fingerprints']=after;receipt['restore_seconds']=time.monotonic()-restore_started
    finally:
        try:
            if snapshot is not None:
                had_child=snapshot.inner.child is not None
                snapshot.close()
                receipt['source_snapshot_cleanup']='ROLLBACK_ACKNOWLEDGED' if had_child else 'NOT_STARTED'
        finally:
            if channel is not None:
                receipt['transport_cleanup']='UNCONFIRMED';channel.abort()
                receipt['transport_cleanup']='OWN_CHILD_ENDED_NO_REMOTE_ACK_CLAIMED'


def begin(r,scope_sha,review_sha,old):
    parent_identity=directory(PREVIOUS_OUTPUT);need(not os.path.lexists(OUTPUT),'S7_ATTEMPT_OCCUPIED')
    OUTPUT.mkdir(mode=0o700);directory(OUTPUT);need(directory(PREVIOUS_OUTPUT)==parent_identity,'S7_PARENT_CHANGED')
    r.private_create(OUTPUT/'ATTEMPT.json',canonical({'schema':'TU1NZ_S7_NOINHERIT_ATTEMPT_V1','transaction':TX,
        'scope_sha256':scope_sha,'review_sha256':review_sha,'approval_sha256':APPROVAL,'e1_attempt_sha256':E1_ATTEMPT,
        'e1_hold_sha256':E1_RESULT,'previous_s7_attempt_sha256':PREVIOUS_ATTEMPT,'previous_s7_hold_sha256':PREVIOUS_HOLD,'file_manifest_sha256':old['original_sha256']['files.json'],
        'started_unix':time.time(),'retry_allowed':False,'SSH_max':1,'DB_sessions_max':8,'concurrent_DB_max':2}))


def initialize_pg(pg,b,ddl,grants):
    pg.start()
    identity=lambda p:(p.stat().st_dev,p.stat().st_ino,p.stat().st_uid,p.stat().st_mode)
    pg.restore_identity=identity(pg.root);pg.socket_identity=identity(pg.socket);pg.socket_parent_identity=identity(pg.socket.parent)
    pg.query(('CREATE ROLE postgres NOLOGIN; CREATE ROLE '+b.ROLE+' NOLOGIN NOSUPERUSER NOCREATEDB '
        'NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT; CREATE DATABASE real_restore;\n').encode())
    pg.env['PGDATABASE']='real_restore'
    pg.query(b'GRANT CREATE,USAGE ON SCHEMA public TO postgres; SET ROLE postgres;\n'+ddl+grants+b'RESET ROLE;\n')
    pg.install_known_owner_profile()


def capture_main():
    need(sys.platform=='darwin' and os.getuid()==os.geteuid()==501 and len(sys.argv)==1,'S7_MAC_DANIEL_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    scope,scope_sha,review_sha,source,c,b,old=validate_inputs()
    need(Path(__file__).resolve(strict=True)==INPUT/'source'/NEW_MODULES[0] and
         Path(__file__).read_bytes()==source[NEW_MODULES[0]],'S7_ENTRY_CHANGED')
    r=load('tu1nz_mainserver_restore.py',source['tu1nz_mainserver_restore.py'])
    f=load('tu1nz_mainserver_file_restore.py',source['tu1nz_mainserver_file_restore.py'])
    manifest,blobs,paths,originals=prior_files(scope,c,b,f,old,supplement_exists=False)
    need(not os.path.lexists(SOCKET),'S7_SOCKET_OCCUPIED')
    closure=read(b.CLIENT/'CLIENT_CLOSURE.json',1024*1024);base=b.CLIENT/'Postgres.app/Contents/Versions/17'
    need(sha(closure)==old['client_closure_sha256'] and r.verify_local_tools(base,json.loads(closure))==old['tool_sha256'],'S7_CLIENT_BINDING')
    ddl,grants,reference=r.trusted_schema(b.APP)
    need(reference==old['schema_reference'] and ddl==originals['trusted-schema.sql'] and grants==originals['trusted-grants.sql'],'S7_TRUSTED_SCHEMA')
    capacity=os.statvfs(PARENT);need(capacity.f_bavail*capacity.f_frsize>=4*1024**3,'S7_CAPACITY')
    code,out,err=r.bounded_process(['/usr/bin/fdesetup','status'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},deadline=time.monotonic()+5)
    need(code==0 and not err and out==b'FileVault is On.\n','S7_STORAGE_PROTECTION');port_free()
    auth=b.passfile_bytes(b.parse_dsn(blobs[manifest['/etc/tu1nz/adult-commercial-s7-database.dsn']['sha256']],base/'lib/libpq.5.dylib'))
    del blobs;begin(r,scope_sha,review_sha,old)
    result={'schema':'TU1NZ_S7_NOINHERIT_RESULT_V1','status':'HOLD','scope_sha256':scope_sha,'review_sha256':review_sha,
        'e1_hold_sha256':E1_RESULT,'previous_s7_attempt_sha256':PREVIOUS_ATTEMPT,'previous_s7_hold_sha256':PREVIOUS_HOLD,'original_remote_closed_ACK_received':False,'host_mutations':False,
        'production_restore':False,'cleanup':[],'phase':'LOCAL_PREPARATION','started_unix':time.time()}
    pg=None;auth_identity=None;socket_identity=None
    print('S7-Zusatz: ein SSH-Versuch, maximal acht lesende DB-Sitzungen; keine Passworteingabe.')
    try:
        SOCKET.mkdir(mode=0o700);socket_identity=directory(SOCKET)
        pg=r.PrivatePostgres(base,OUTPUT/'restore',SOCKET/'s',deadline=time.monotonic()+120)
        initialize_pg(pg,b,ddl,grants)
        catalog=pg.query(r.catalog_transaction());rights=pg.query(r.rights_transaction())
        r.private_create(OUTPUT/'transient.pgpass',auth);auth_identity=identity((OUTPUT/'transient.pgpass').lstat());del auth
        capture_and_restore(r,b,pg,base,catalog,rights,result);result['status']=PASS
    except BaseException as error:
        result['local_read_observation']=getattr(error,'observation',None)
        result['failure']=str(error) if isinstance(error,(Denied,c.Denied,r.Denied,b.Denied,f.Denied)) else type(error).__name__
    finally:
        if 'auth' in locals():del auth
        if pg is not None:
            try:pg.close()
            except BaseException:result['cleanup'].append('S7_PG_END_UNCONFIRMED')
        if auth_identity is None and os.path.lexists(OUTPUT/'transient.pgpass'):result['cleanup'].append('S7_PARTIAL_AUTH_RETAINED')
        if auth_identity is not None:
            try:
                need(identity((OUTPUT/'transient.pgpass').lstat())==auth_identity,'S7_AUTH_CHANGED');(OUTPUT/'transient.pgpass').unlink()
            except BaseException:result['cleanup'].append('S7_AUTH_CLEANUP_UNCONFIRMED')
        if pg is not None and pg.child is not None and pg.child.poll()==0:
            try:
                r.private_create(OUTPUT/'restore-server.log',read(pg.root/'server.log',1024*1024))
                result['private_restore_cleanup']=b.cleanup_owned_cluster(pg,pg.root)
            except BaseException:result['cleanup'].append('S7_CLUSTER_CLEANUP_UNCONFIRMED')
        elif socket_identity is not None:
            try:
                need(directory(SOCKET)==socket_identity and os.listdir(SOCKET)==[] and not os.path.lexists(OUTPUT/'restore'),
                     'S7_PARTIAL_CLUSTER_RETAINED');SOCKET.rmdir()
            except BaseException:result['cleanup'].append('S7_PARTIAL_CLUSTER_RETAINED')
        try:port_free()
        except BaseException:result['cleanup'].append('S7_FORWARD_RETAINED')
        try:
            for name,raw in originals.items():need(read(PARENT/name,1024*1024)==raw,'S7_ORIGINAL_CHANGED')
            need(sha(read(INPUT/'SCOPE.json',512*1024))==scope_sha and sha(read(INPUT/'INDEPENDENT_REVIEW.json',65536))==review_sha,
                 'S7_BINDING_CHANGED')
        except BaseException:result['cleanup'].append('S7_INPUT_CUSTODY_CHANGED')
        diagnostic=result.pop('transport_diagnostic',{'phase':'NOT_STARTED','launches':0})
        diagnostic_raw=canonical(diagnostic);r.private_create(OUTPUT/'transport.json',diagnostic_raw)
        result['transport_diagnostic_sha256']=sha(diagnostic_raw)
        if result['cleanup']:result['status']='HOLD'
        result['finished_unix']=time.time();r.private_create(OUTPUT/'RESULT.json',canonical(result))
    print('S7-Zusatz Ergebnis:',result['status'],'— Daten und Fehlerdetails bleiben privat.')
    return 0 if result['status']==PASS else 1


def checked_db_receipt(scope,scope_sha,review_sha,r,old,*,files_done=False):
    directory(OUTPUT)
    allowed=CAPTURE|({'privileged-restore','FILE_RESTORE_RESULT.json'} if files_done else set())
    need(set(os.listdir(OUTPUT))==allowed and not os.path.lexists(SOCKET),'S7_DB_OUTPUT_SET_OR_CLEANUP')
    raw=read(OUTPUT/'RESULT.json',512*1024);result=json.loads(raw)
    attempt=json.loads(read(OUTPUT/'ATTEMPT.json',65536))
    need(attempt['schema']=='TU1NZ_S7_NOINHERIT_ATTEMPT_V1' and attempt['transaction']==TX and
         attempt['approval_sha256']==APPROVAL and attempt['scope_sha256']==scope_sha and attempt['review_sha256']==review_sha and
         attempt['e1_attempt_sha256']==E1_ATTEMPT and attempt['e1_hold_sha256']==E1_RESULT and
         attempt['previous_s7_attempt_sha256']==PREVIOUS_ATTEMPT and attempt['previous_s7_hold_sha256']==PREVIOUS_HOLD and attempt['retry_allowed'] is False and
         attempt['file_manifest_sha256']==old['original_sha256']['files.json'] and
         (attempt['SSH_max'],attempt['DB_sessions_max'],attempt['concurrent_DB_max'])==(1,8,2),'S7_ATTEMPT_BINDING')
    need(result['schema']=='TU1NZ_S7_NOINHERIT_RESULT_V1' and result['status']==PASS and result['cleanup']==[] and
         result['scope_sha256']==scope_sha and result['review_sha256']==review_sha and result['e1_hold_sha256']==E1_RESULT and
         result['previous_s7_attempt_sha256']==PREVIOUS_ATTEMPT and result['previous_s7_hold_sha256']==PREVIOUS_HOLD and
         result['original_remote_closed_ACK_received'] is False and result['host_mutations'] is False and result['production_restore'] is False and
         result['snapshot_rollback_acknowledged'] is True and result['source_snapshot_cleanup']=='ROLLBACK_ACKNOWLEDGED' and
         result['transport']['own_ssh_ended'] is True and result['transport']['local_forward_removed'] is True and
         result['transport']['remote_program_executed'] is False and result['private_restore_cleanup']['own_cluster_removed'] is True and
         result['private_restore_cleanup']['own_socket_removed'] is True and result['source_sessions']=={'attempted':8,'max_simultaneous':2} and
         0<=result['capture_seconds']<300 and 0<=result['restore_seconds']<300,'S7_REAL_DB_GATE')
    diagnostic=read(OUTPUT/'transport.json',65536);d=json.loads(diagnostic)
    need(sha(diagnostic)==result['transport_diagnostic_sha256'] and d['launches']==1 and d['own_child_ended'] is True and
         d['normal_close_after_rollback'] is True and d['truncated'] is False and
         d['stdout_private']==d['stderr_private']=='','S7_TRANSPORT_PROOF')
    catalog=read(OUTPUT/'source-catalog.jsonl',r.MAX_CATALOG);rights=read(OUTPUT/'source-rights.jsonl',r.MAX_CATALOG)
    restored=read(OUTPUT/'restored-catalog.jsonl',r.MAX_CATALOG);rrights=read(OUTPUT/'restored-rights.jsonl',r.MAX_CATALOG)
    proof=r.compare_restore_catalog(catalog,restored,rights,rrights)
    need(proof==result['restored_catalog'] and result['admission']['source_catalog_sha256']==sha(catalog) and
         result['admission']['rights_sha256']==proof['rights_sha256'],'S7_CATALOG_PROOF')
    snapshot=result['snapshot'];need(snapshot['database']=='tu1nz_adult_commercial_s3' and
         snapshot['role']==snapshot['session_role']=='tu1nz_adult_commercial_s3_runtime' and snapshot['readonly']=='on' and
         snapshot['version']=='170011' and snapshot['fingerprints']==result['restored_fingerprints'] and
         set(result['restored_fingerprints'])==set(r.TABLES),'S7_SNAPSHOT_PROOF')
    for row in result['restored_fingerprints'].values():
        need(type(row)==dict and set(row)=={'bytes','rows','sha256'} and type(row['rows']) is int and
             0<=row['rows']<=r.MAX_ROWS and type(row['bytes']) is int and 0<=row['bytes']<=r.MAX_DATA and
             re.fullmatch('[0-9a-f]{64}',row['sha256']),'S7_FINGERPRINT')
    archive=read(OUTPUT/'s7.dump',r.MAX_DATA)
    need(archive.startswith(b'PGDMP') and sha(archive)==snapshot['archive_sha256'],'S7_ARCHIVE_FULL_READBACK')
    return raw,result


if __name__=='__main__':
    try:raise SystemExit(capture_main())
    except Exception as error:
        print('S7-Zusatz abgebrochen:',str(error) if isinstance(error,Denied) else type(error).__name__)
        if isinstance(error,Denied) and error.observation is not None:print(json.dumps(error.observation,sort_keys=True))
        raise SystemExit(1)
