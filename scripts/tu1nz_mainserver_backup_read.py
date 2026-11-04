"""Rev4 finite read-only file backup producer, never a Host mutation entry.

Import is inert. Protected execution needs the separately reviewed exact scope
and personal SSH/sudo transport. All content goes only to that private stream;
no Host output files, service commands, database access, claims or retries.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import resource
import signal
import stat
import struct
import sys
import time

TX='public-rights-20261014-1'
MACHINE='a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae'
DECISION='e6794711443f5768c2e720c7552948964976c246ab59ff89236f53125fbd49fc'
APPROVAL='576251012fb1e73fcc29a49334140660339b74fbdda05273822e53cb6f80c3a4'
PLAN='e9ac7f6056c42c5bcc67b9823d4cd65740a5037bae816a10431b0c8635dd6b36'
LIGHTING='/var/www/lighting.tu1nz.com'
UNITS=('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service',
       'tu1nz-adult-public-s10-wms.service')
UNIT_FILES={
    '/etc/systemd/system/'+UNITS[0]:'ad098f7533716f2e26f9aff500bc82a7b98c939b5b021a442f37d778edc7b692',
    '/etc/systemd/system/'+UNITS[1]:'f2663c4f1e57e91aa938d67bc5533fa5324dd355282bdf6e52fe40102b7b994d',
    '/etc/systemd/system/'+UNITS[2]:'53237fc837a28cabbab7e34693db67bfaa2736b5153818f6b218c7dbcd65b89a',
    '/etc/systemd/system/'+UNITS[1]+'.d/s9-growth.conf':'2e10d790f1ed2dd736c9b0c7ec1dda5b58c6cc767e5d5cb2574fe76eb99ceb4b'}
CONFIGS=tuple('/etc/tu1nz/'+n for n in (
    'adult-commercial-s7-public.json','adult-commercial-s7-form.secret','adult-commercial-s7-database.dsn',
    'adult-commercial-s8-landing.json','adult-commercial-s10-wms.json','adult-commercial-s10-wms-copy.json',
    'adult-commercial-s10-wms-bot-identity.json','adult-commercial-s10-2d-community.json'))
DYNAMIC=('/var/lib/tu1nz-adult-public-s9/landing-aggregates.json',
         '/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json')
MAX_FILE=8*1024*1024
MAX_TOTAL=32*1024*1024
MAX_SCOPE=256*1024
FIELDS=frozenset(('device','inode','uid','gid','mode','type','nlink','size','mtime_ns','ctime_ns','attrs','flags'))


class Denied(RuntimeError):pass
def need(value,code):
    if not value:raise Denied(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def bound_selection(scope):
    fields={'schema','transaction','host_id','machine_sha256','contract_sha256','approval_sha256',
            'owner_plan_base64','files','max_file_bytes','max_total_bytes','capture_seconds'}
    need(type(scope) is dict and set(scope)==fields and scope['schema']=='TU1NZ_REV4_FILE_BACKUP_SCOPE_V1' and
         scope['transaction']==TX and scope['host_id']==109772243 and scope['machine_sha256']==MACHINE and
         scope['contract_sha256']==DECISION and scope['approval_sha256']==APPROVAL and
         scope['max_file_bytes']==MAX_FILE and scope['max_total_bytes']==MAX_TOTAL and scope['capture_seconds']==300,
         'BACKUP_SCOPE')
    raw=base64.b64decode(scope['owner_plan_base64'],validate=True)
    need(len(raw)<=MAX_SCOPE and sha(raw)==PLAN,'BACKUP_OWNER_PLAN')
    plan=json.loads(raw);objects=plan['capture']['objects']
    need(plan['host']==MACHINE and plan['root']==LIGHTING and plan['objects']==88 and
         plan['changed_objects']==84 and plan['existing_root_objects_unchanged']==4 and
         len(objects)==88 and plan['capture']['second_pass']==objects,'BACKUP_OWNER_PLAN_PROFILE')
    selected={}
    for relative,row in objects.items():
        p=PurePosixPath(relative)
        need(relative=='.' or (not p.is_absolute() and relative==str(p) and '..' not in p.parts and
             all(re.fullmatch('[A-Za-z0-9_.-]{1,160}',x) for x in p.parts)),'BACKUP_LIGHTING_PATH')
        path=LIGHTING if relative=='.' else LIGHTING+'/'+relative
        need(set(row)=={'metadata','sha256'} and set(row['metadata'])==FIELDS and
             row['metadata']['type'] in (stat.S_IFREG,stat.S_IFDIR),'BACKUP_LIGHTING_SCHEMA')
        selected[path]=row
    expected=set(selected)|set(UNIT_FILES)|set(CONFIGS)|set(DYNAMIC)
    need(type(scope['files']) is list and len(scope['files'])==len(expected) and set(scope['files'])==expected and
         len(expected)<=128,'BACKUP_FINITE_FILE_SET')
    return selected


def metadata(fd):
    s=os.fstat(fd)
    need(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode),'BACKUP_OBJECT_TYPE')
    names=os.listxattr(fd);need(len(names)<=16,'BACKUP_ATTRIBUTE_BOUND');attrs={}
    for name in sorted(names):
        need(len(name.encode())<=256,'BACKUP_ATTRIBUTE_BOUND');raw=os.getxattr(fd,name)
        need(len(raw)<=4096,'BACKUP_ATTRIBUTE_BOUND');attrs[name]=base64.b64encode(raw).decode()
    flags=struct.unpack('I',fcntl.ioctl(fd,0x80086601,struct.pack('I',0)))[0]
    return dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode),
                type=stat.S_IFMT(s.st_mode),nlink=s.st_nlink,size=s.st_size,mtime_ns=s.st_mtime_ns,
                ctime_ns=s.st_ctime_ns,atime_ns=s.st_atime_ns,attrs=attrs,flags=flags)


class Capture:
    """Descriptor-bound read of only the exact admitted paths and ancestors."""
    def __init__(self,root_fd,scope,*,deadline):
        self.scope=scope;self.lighting=bound_selection(scope);self.deadline=deadline
        self.dirs={'/':os.dup(root_fd)};self.edges=[];self.total=0;self.rows={};self.closed=False
    def live(self):need(time.monotonic()<self.deadline,'BACKUP_CAPTURE_DEADLINE')
    @staticmethod
    def identity(s):return s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode
    def parent(self,path):
        self.live();p=PurePosixPath(path);need(p.is_absolute() and str(p)==path and '..' not in p.parts,'BACKUP_PATH')
        current='/'
        for part in p.parent.parts[1:]:
            nxt=current.rstrip('/')+'/'+part
            if nxt not in self.dirs:
                fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME,dir_fd=self.dirs[current])
                self.dirs[nxt]=fd
                before=self.identity(os.fstat(fd));self.edges.append((self.dirs[current],part,fd,before))
                need(before==self.identity(os.stat(part,dir_fd=self.dirs[current],follow_symlinks=False)),'BACKUP_ANCESTOR_CHANGED')
                need(len(self.dirs)<=64,'BACKUP_FD_BOUND')
            current=nxt
        return self.dirs[current],p.name
    def identity_file(self,path):
        need(path in ('/etc/machine-id','/proc/sys/kernel/random/boot_id'),'BACKUP_IDENTITY_SCOPE')
        parent,name=self.parent(path)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK|os.O_NOATIME,dir_fd=parent)
        try:
            s=os.fstat(fd);need(stat.S_ISREG(s.st_mode),'BACKUP_IDENTITY_TYPE');raw=os.read(fd,129)
            need(len(raw)<=128 and not os.read(fd,1) and self.identity(s)==self.identity(os.fstat(fd)),
                 'BACKUP_IDENTITY_BOUND')
            return raw
        finally:os.close(fd)
    def directory_members(self,path,expected,*,optional=False):
        parent,name=self.parent(path)
        try:fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME,dir_fd=parent)
        except FileNotFoundError:
            need(optional and not expected,'BACKUP_DIRECTORY_ABSENT');return {'absent':True}
        try:
            before=metadata(fd);names=os.listdir(fd);self.live()
            need(len(names)<=128 and set(names)==set(expected),'BACKUP_UNKNOWN_DIRECTORY_MEMBER')
            after=metadata(fd)
            need(all(before[k]==after[k] for k in FIELDS),'BACKUP_DIRECTORY_CHANGED')
            need(self.identity(os.fstat(fd))==self.identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                 'BACKUP_DIRECTORY_REPLACED')
            return {'metadata':before,'names':sorted(names)}
        finally:os.close(fd)
    def file(self,path):
        need(path in self.scope['files'],'BACKUP_READ_OUT_OF_SCOPE');parent,name=self.parent(path)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK|os.O_NOATIME,dir_fd=parent)
        try:
            before=metadata(fd);self.live()
            need(before['attrs']=={} and not before['flags'] & ~(0x80000|0x1000) and
                 before['mode']<=0o777,'BACKUP_UNSUPPORTED_RESTORE_PROFILE')
            if before['type']==stat.S_IFREG:
                need(before['nlink']==1 and not before['mode'] & 0o111 and before['size']<=MAX_FILE,
                     'BACKUP_REGULAR_PROFILE')
                chunks=[];count=0
                while True:
                    self.live();part=os.read(fd,65536)
                    if not part:break
                    count+=len(part);need(count<=MAX_FILE and self.total+count<=MAX_TOTAL,'BACKUP_BYTE_BOUND');chunks.append(part)
                raw=b''.join(chunks);need(len(raw)==before['size'],'BACKUP_READ_SIZE');digest=sha(raw);self.total+=len(raw)
            else:need(path in self.lighting,'BACKUP_DIRECTORY_SCOPE');raw=None;digest=None
            after=metadata(fd)
            need(all(before[k]==after[k] for k in FIELDS) and
                 self.identity(os.fstat(fd))==self.identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                 'BACKUP_OBJECT_CHANGED')
            if path in self.lighting:
                wanted=self.lighting[path]
                need(wanted['sha256']==digest and all(before[k]==wanted['metadata'][k] for k in FIELDS),
                     'BACKUP_FIXED_OWNER_PLAN_DRIFT')
            if path in UNIT_FILES:need(digest==UNIT_FILES[path],'BACKUP_UNIT_BYTES_CHANGED')
            if path in CONFIGS:need(before['uid']==before['gid']==0 and not before['mode'] & 0o022,
                                    'BACKUP_CONFIG_AUTHORITY')
            if path in DYNAMIC:
                need(before['uid']==before['gid']==1001 and before['mode']==0o600 and before['size']<=1024*1024,
                     'BACKUP_DYNAMIC_PROFILE')
            if path.endswith(('.secret','.dsn')):need(before['mode']==0o600 and before['size']<=4096,
                                                    'BACKUP_CREDENTIAL_PROFILE')
            row={'metadata':before,'sha256':digest};self.rows[path]=row
            return row,raw
        finally:os.close(fd)
    def directories(self):
        out={}
        for path,row in self.lighting.items():
            if row['metadata']['type']==stat.S_IFDIR:
                expected=[PurePosixPath(p).name for p in self.lighting if str(PurePosixPath(p).parent)==path]
                out[path]=self.directory_members(path,expected)
        for unit in UNITS:
            directory='/etc/systemd/system/'+unit+'.d'
            expected=[PurePosixPath(p).name for p in UNIT_FILES if str(PurePosixPath(p).parent)==directory]
            out[directory]=self.directory_members(directory,expected,optional=True)
        return out
    def close(self):
        if self.closed:return
        self.closed=True
        for fd in self.dirs.values():os.close(fd)
        self.dirs.clear()
    def check(self):
        self.live()
        for parent,name,fd,before in self.edges:
            need(before==self.identity(os.fstat(fd))==self.identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                 'BACKUP_ANCESTOR_REPLACED')


def main(expected_scope_sha):
    need(sys.platform=='linux' and os.geteuid()==0,'BACKUP_LINUX_ROOT_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_NOFILE,(192,192))
    resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024));resource.setrlimit(resource.RLIMIT_CPU,(30,35))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Denied('BACKUP_CAPTURE_DEADLINE')));signal.alarm(300)
    raw=sys.stdin.buffer.readline(MAX_SCOPE+1)
    need(len(raw)<=MAX_SCOPE and raw.endswith(b'\n') and sha(raw[:-1])==expected_scope_sha,'BACKUP_SCOPE_BYTES')
    scope=json.loads(raw);bound_selection(scope);deadline=time.monotonic()+300
    namespaces={n:os.readlink('/proc/self/ns/'+n) for n in ('mnt','pid','user')}
    need(all(v==os.readlink('/proc/1/ns/'+n) for n,v in namespaces.items()),'BACKUP_INITIAL_NAMESPACE')
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME)
    capture=Capture(root,scope,deadline=deadline);os.close(root);began=time.time()
    def emit(value):
        data=canonical(value);need(len(data)<=MAX_FILE*2,'BACKUP_FRAME_BOUND')
        sys.stdout.buffer.write(data+b'\n');sys.stdout.buffer.flush()
    try:
        need(sha(capture.identity_file('/etc/machine-id'))==MACHINE,'BACKUP_WRONG_HOST')
        boot=capture.identity_file('/proc/sys/kernel/random/boot_id').decode('ascii').strip()
        need(re.fullmatch('[0-9a-f-]{36}',boot),'BACKUP_BOOT_FORMAT')
        directories=capture.directories()
        for path in sorted(scope['files']):
            row,raw=capture.file(path);emit({'kind':'file','path':path,'row':row,
                'content_base64':base64.b64encode(raw).decode() if raw is not None else None})
        current=capture.directories()
        need(all(current[p].get('names')==v.get('names') and current[p].get('absent')==v.get('absent')
                 for p,v in directories.items()),'BACKUP_DIRECTORY_SET_CHANGED')
        capture.check()
        emit({'kind':'files_complete','scope_sha256':expected_scope_sha,'machine_sha256':MACHINE,'boot_id':boot,
              'started_unix':began,'finished_unix':time.time(),'objects':len(capture.rows),'bytes':capture.total,
              'manifest_sha256':sha(canonical(capture.rows)),'directories':directories,
              'semantics':'PER_OBJECT_STABLE_PRESTOP_COPY_NOT_GLOBAL_ATOMIC_OR_WRITER_FENCED'})
        # Keep this authenticated connection/its fixed SSH forward alive while
        # the Mac takes the readonly S7 snapshot. One exact completion token.
        need(sys.stdin.buffer.readline(64)==b'REV4_BACKUP_CLOSE\n','BACKUP_CLOSE_TOKEN')
        capture.check();capture.close();emit({'kind':'closed','fds_closed':True,'host_mutations':False})
    finally:capture.close();signal.alarm(0)
