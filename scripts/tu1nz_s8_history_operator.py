"""Version-bound R5 history-only operator, never admission or installation.

Pre/post observations never read historical Git/evidence contents. Only the
unchanged, separately pinned stdin program may do that. No persistent host
files, signals to foreign processes, retries, or metadata modifications.
"""
import ctypes
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import time
import shlex
import zlib

import tu1nz_s8_execution_contract as c
from tu1nz_s8_historical_capacity import probe

ROOTS = (Path('/opt/tu1nz_repos/adult-publishing-core'), Path('/opt/tu1nz_repos/control'))
HISTORY = Path('/etc/tu1nz/adult-commercial-s12-1-private/state')
FILES = ('repository-barrier.json', 'repository-barrier.r12-bindings.json',
         'repository-barrier.r12-abort.json', 'deployment-attempted.json')
MARKERS = ('repository-barrier.r15-containment.json', 'repository-barrier.r15-containment-progress.json',
           'repository-barrier.r15-contained.json', 'repository-barrier.r15-containment-failed.json',
           'r13-followup-1.consumed.json')
OTHER_FIXED = (Path('/etc/tu1nz/s8-atomic-admission-r1'), Path('/tu1nz-s8-admission-anchor-v1'))
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1',
       'HOME':'/nonexistent','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0'}
PUBLIC = ('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service',
          'tu1nz-adult-public-s10-wms.service','nginx.service')
SEPARATE = ('tu1nz-adult-public-s8-telegram.service','tu1nz-adult-public-s9-health.service',
            'tu1nz-adult-public-s10-health.service','tu1nz-adult-public-s11-canary-controller.service',
            'tu1nz-adult-commercial-s12-yoti-runtime.service','mychatbuddy-private-alpha.service')
HTTP = {'https://wantmeseen.com/':'200','https://wantmeseen.com/health':'200',
        'https://wantmeseen.com/privacy':'200','https://wantmeseen.com/terms':'200',
        'https://wantmeseen.com/imprint':'200','https://wantmeseen.de/':'308'}


def now(): return datetime.now(timezone.utc).isoformat()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def require(ok, code):
    if not ok: raise RuntimeError(code)
def error_info(error):
    return dict(type=type(error).__name__, errno=getattr(error,'errno',None),
                code=str(error) if type(error) is RuntimeError else c.failure_record(error)['code'])
def command(argv, timeout=15):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=ENV)


def health():
    result = dict(at=now(),services={},http={})
    props = 'ActiveState,SubState,Result,MainPID,ControlPID,ExecMainStatus,NRestarts,InvocationID,NeedDaemonReload,Restart,UnitFileState'
    for unit in (*PUBLIC,*SEPARATE):
        r=command(['/usr/bin/systemctl','show',unit,'--no-pager','--property='+props])
        require(r.returncode == 0,'SERVICE_READ_UNAVAILABLE')
        values=dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
        require(set(values) == set(props.split(',')),'SERVICE_ENVELOPE_RED')
        result['services'][unit]=values
    for url in HTTP:
        r=command(['/usr/bin/curl','--disable','--silent','--max-time','10','--output','/dev/null',
                   '--write-out','%{http_code}',url],12)
        result['http'][url]=dict(exit_code=r.returncode,code=r.stdout if r.stdout.isdigit() else 'UNKNOWN')
    return result


def require_public_health(value):
    for unit in PUBLIC:
        v=value['services'][unit]
        require(v['ActiveState']=='active' and v['SubState']=='running' and
                v['NRestarts']=='0' and v['NeedDaemonReload']=='no','PUBLIC_BASELINE_RED')
    for url,wanted in HTTP.items():
        require(value['http'][url] == dict(exit_code=0,code=wanted),'PUBLIC_HTTP_BASELINE_RED')
    v=value['services']['tu1nz-adult-commercial-s12-yoti-runtime.service']
    require(v['ActiveState']=='inactive' and v['MainPID']=='0','S12_BASELINE_CHANGED')


def process_rows(group=None):
    rows=[]; unknown=0
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            fields=(p/'stat').read_text().rpartition(')')[2].split()
            if group is None or int(fields[2])==group:
                rows.append(dict(pid=int(p.name),ppid=int(fields[1]),group=int(fields[2]),
                                 state=fields[0],start_ticks=int(fields[19])))
        except FileNotFoundError: continue
        except (OSError,ValueError): unknown+=1
    return dict(rows=rows,unknown=unknown)


def fingerprint(m):
    # Access time is outside the unchanged-content/rights claim. Read-only
    # directory enumeration may update it; it is never restored/normalized.
    return [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns,m.st_mode,m.st_uid,m.st_gid,m.st_nlink]


def metadata():
    deadline=time.monotonic()+30; rows={}; targets=set(); regular=0
    fixed=[HISTORY,*(HISTORY/name for name in FILES),*(HISTORY/name for name in MARKERS),*OTHER_FIXED]
    for root in ROOTS: fixed.extend((root,root/'.git',root/'.git.s12-1-recovery'))
    for p in fixed:
        targets.add(p)
        targets.update(p.parents)
    pending=sorted(targets,key=str); recursive={root/'.git.s12-1-recovery' for root in ROOTS}
    while pending:
        require(time.monotonic()<deadline and len(rows)<65536,'METADATA_READ_BOUND')
        p=pending.pop()
        if str(p) in rows: continue
        try: m=p.lstat()
        except FileNotFoundError:
            rows[str(p)]=dict(state='ABSENT');continue
        require(stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode),'METADATA_OBJECT_TYPE_RED')
        fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK|
                   (os.O_DIRECTORY if stat.S_ISDIR(m.st_mode) else 0))
        try:
            require(fingerprint(m)==fingerprint(os.fstat(fd)),'METADATA_UNSTABLE')
            names=sorted(os.listxattr(fd))
            acls={name:sha(os.getxattr(fd,name)) for name in names if name.startswith('system.posix_acl_')}
            flags=fcntl.ioctl(fd,0x80086601,b'\0'*8)
            record=dict(fingerprint=fingerprint(m),xattr_names=names,acl_sha256=acls,
                        inode_flags=int.from_bytes(flags[:4],'little'))
            if p in recursive or any(r in p.parents for r in recursive):
                if stat.S_ISDIR(m.st_mode):
                    children=sorted(os.listdir(fd));require(len(children)<=65536,'METADATA_READ_BOUND')
                    pending.extend(p/name for name in children)
            if stat.S_ISREG(m.st_mode): regular+=1
            require(fingerprint(m)==fingerprint(os.fstat(fd))==fingerprint(p.lstat()),'METADATA_UNSTABLE')
            rows[str(p)]=record
        finally: os.close(fd)
    targets={(v['fingerprint'][0],v['fingerprint'][1]) for v in rows.values() if 'fingerprint' in v}
    locks=[]
    for line in Path('/proc/locks').read_text().splitlines():
        parts=[part for part in line.split() if part!='->']
        if len(parts)<6 or 'LEASE' not in parts: continue
        try:
            device=parts[5].split(':'); key=(os.makedev(int(device[0],16),int(device[1],16)),int(device[2]))
            if key in targets: locks.append(dict(kind=parts[1],state=parts[2],access=parts[3],pid=int(parts[4]),inode=key))
        except (ValueError,IndexError): raise RuntimeError('LOCK_ENVELOPE_UNKNOWN')
    raw=json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
    # No branch names, contents, credentials, or unrelated process arguments.
    return dict(at=now(),rows_sha256=sha(raw),objects=len(rows),regular_objects=regular,
                fixed={str(p):rows[str(p)] for p in fixed},target_leases=locks,
                scope='ALL_EXISTING_QUARANTINED_GIT_METADATA_PLUS_FIXED_ANCESTRY_EVIDENCE_AND_S8_ROOTS',
                access_time_excluded=True), rows


def prerequisites(machine_sha256):
    require(os.geteuid()==0 and os.uname().sysname=='Linux','PROTECTED_LINUX_REQUIRED')
    # The existing Host pin includes machine-id's terminating newline.
    machine=sha(Path('/etc/machine-id').read_bytes())
    require(c.hex_value(machine_sha256,64) and machine==machine_sha256,'HOST_MACHINE_MISMATCH')
    require(Path('/proc/sys/fs/leases-enable').read_text().strip()=='1','KERNEL_LEASES_DISABLED')
    libs=ctypes.CDLL(None,use_errno=True);types={}
    libs.fstatfs.argtypes=[ctypes.c_int,ctypes.c_void_p];libs.fstatfs.restype=ctypes.c_int
    for p in (*ROOTS,HISTORY):
        fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            buffer=ctypes.create_string_buffer(256)
            require(libs.fstatfs(fd,buffer)==0,'FILESYSTEM_READ_UNAVAILABLE')
            kind=ctypes.c_long.from_buffer(buffer).value;types[str(p)]=hex(kind)
            require(kind==0xef53,'NATIVE_EXT4_REQUIRED')
        finally: os.close(fd)
    caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(int(caps['CapEff'].strip(),16)&(1<<28),'CAP_LEASE_REQUIRED')
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    return dict(at=now(),machine_sha256=machine,boot_sha256=sha(Path('/proc/sys/kernel/random/boot_id').read_bytes().strip()),
                mount_namespace=os.readlink('/proc/self/ns/mnt'),kernel=os.uname().release,filesystems=types,
                leases_enabled=True,cap_lease=True,fd_soft=soft,fd_hard=hard,
                delegated_kernel_privileges='UNKNOWN_NOT_A_WRITER_TRUST_EXCEPTION',
                signal_collision_and_real_lease_function='CHECKED_ONLY_BY_CANONICAL_READER')


def execute(program, *, program_sha256, machine_sha256):
    """One child, recorded before any later failure; cleanup runs on every path.

    GNU timeout is the only signal authority. Unknown child/output/cleanup is
    RED, never a replacement launch or retry. The supervisor's limit is not
    raised: the exact embedded Reader admits its actual FD context before any
    lease acquisition. This parent's hard-capacity probe is an earlier deny.
    """
    out=dict(schema='TU1NZ_S8_R5_HOST_SUPERVISOR_V1',started_at=now(),reader_started=False,
             reader_launches=0,primary=None,abort=None,cleanup=[],live_authority=False,
             slot_consumed_by_tool=False,automatic_retry=False)
    proc=None
    def fail(error):
        record=error_info(error)
        if out['primary'] is None:out['primary']=record
        else:out['cleanup'].append(record)
    try:
        require(c.hex_value(program_sha256,64) and sha(program)==program_sha256 and
                0<len(program)<=100000,'FROZEN_PROGRAM_DRIFT')
        out['prerequisites']=prerequisites(machine_sha256)
        out['before_health']=health();require_public_health(out['before_health'])
        out['before_metadata'],before=metadata()
        require(not out['before_metadata']['target_leases'],'COMPETING_TARGET_LEASE')
        out['fd_preflight'],_=probe(ROOTS,HISTORY)
        # close_fds + fixed argv/env make the child inheritance explicit.
        proc=subprocess.Popen(['/usr/bin/timeout','--signal=TERM','--kill-after=5s','40s',
                               '/usr/bin/python3','-I','-B','-S','-'],stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,
                              close_fds=True,start_new_session=True)
        out.update(reader_started=True,reader_launches=1,own_timeout_pid=proc.pid,own_process_group=proc.pid)
        owned_deadline=time.monotonic()+55
        try:
            stdout,stderr=proc.communicate(input=program,timeout=55)
            out['timeout_exit_code']=proc.returncode
            require(len(stdout)<=1048576 and len(stderr)<=65536,'OUTPUT_BOUND_RED')
            try:out['canonical_result']=json.loads(stdout)
            except (ValueError,UnicodeError):out['canonical_result']=None
            out['stderr_bytes']=len(stderr);out['stderr_sha256']=sha(stderr)
            require(proc.returncode in (0,2) and isinstance(out.get('canonical_result'),dict),'CANONICAL_OUTCOME_UNCERTAIN')
            value=out['canonical_result']
            require(value.get('schema')=='TU1NZ_S8_HISTORICAL_READ_R5_DELTA_V1' and
                    ((proc.returncode==0 and value.get('historical_capture')=='GREEN') or
                     (proc.returncode==2 and value.get('historical_capture')=='RED')),'CANONICAL_ENVELOPE_RED')
        except BaseException as error:
            fail(error)
            # Do not communicate/submit stdin a second time. The original owned
            # timeout already has the sole termination schedule.
            if proc.poll() is None:
                try:proc.wait(timeout=max(0,owned_deadline-time.monotonic()))
                except BaseException as cleanup:fail(cleanup)
    except BaseException as error:fail(error)
    finally:
        if proc is not None:
            # Independently attempt every postcheck; preserve primary origin.
            out['reader_exit_observed']=proc.poll() is not None
            try:out['remaining_own_group']=process_rows(proc.pid)
            except BaseException as error:fail(error)
            try:
                out['after_metadata'],after=metadata()
                out['metadata_equal']=before==after
            except BaseException as error:fail(error)
            try:
                out['after_health']=health()
                changed={unit:{key:dict(before=out['before_health']['services'][unit].get(key),after=value)
                         for key,value in row.items() if out['before_health']['services'][unit].get(key)!=value}
                         for unit,row in out['after_health']['services'].items()
                         if out['before_health']['services'][unit]!=row}
                out['service_deltas']=changed
                out['health_equal']=not changed and out['before_health']['http']==out['after_health']['http']
                # No silent exception for periodic invocations or assumption of
                # their cause. Any delta remains a separately assessable RED.
            except BaseException as error:fail(error)
            try:
                group=out.get('remaining_own_group',{})
                out['own_protection_released']=bool(out['reader_exit_observed'] and
                    group.get('rows')==[] and group.get('unknown')==0 and
                    out.get('after_metadata',{}).get('target_leases')==[])
                require(out['own_protection_released'],'CLEANUP_UNPROVEN')
                require(out.get('metadata_equal') is True,'POST_METADATA_CHANGED')
                require(out.get('health_equal') is True,'POST_SERVICE_OR_HTTP_CHANGED')
                result=out.get('canonical_result',{})
                require(result.get('historical_capture')=='GREEN' and
                        result.get('fd_capacity',{}).get('limit_restored') is True and
                        result.get('fd_capacity',{}).get('fd_baseline_restored') is True,
                        'CANONICAL_HISTORY_RED')
            except BaseException as error:fail(error)
            for stream in (proc.stdin,proc.stdout,proc.stderr):
                try:
                    if stream is not None:stream.close()
                except BaseException as error:fail(error)
    out['status']='HOST_CAPTURE_GREEN_CURRENT_INTERVAL_ONLY' if out['primary'] is None else 'INCOMPLETE_OR_RED_NO_RETRY'
    out['finished_at']=now()
    return out


def sudo_command(program):
    """Only exact isolated embedded code, password on the operator's own TTY.

    Command-only -k requests no reusable sudo cache, no standalone invalidation.
    The operator must verify the exact versioned program digest before calling.
    No -v/-K, shell/profile startup, persistent Host file or configurable argv.
    """
    require(type(program) is bytes and 0<len(program)<=100000,'OPERATOR_PROGRAM_RED')
    packed=base64.b64encode(zlib.compress(program,9)).decode('ascii')
    code='import base64,zlib;exec(compile(zlib.decompress(base64.b64decode('+repr(packed)+')),"<frozen-s8-history-operator>","exec"))'
    return ['/usr/bin/sudo','-k','-p','[S8 protected history] sudo password for %u: ',
            '--','/usr/bin/python3','-I','-B','-S','-c',code]


def ssh_command(program):
    return 'LC_ALL=C '+shlex.join(sudo_command(program))


def parse_report(data, exit_code):
    text=data.decode(errors='replace').replace('\r\n','\n')
    begin='S8_HISTORY_REPORT_BEGIN\n';end='\nS8_HISTORY_REPORT_END'
    if len(data)<=4*1024*1024 and text.count(begin)==text.count(end)==1 and exit_code==0:
        try:return json.loads(text.split(begin,1)[1].split(end,1)[0])
        except ValueError:pass
    return dict(status='INCOMPLETE_OUTPUT_NO_RETRY',ssh_exit_code=exit_code,
                reader_outcome='UNKNOWN',cleanup='UNKNOWN',live_authority=False)
