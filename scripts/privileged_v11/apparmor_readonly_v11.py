"""Fixed, read-only collector for later bound root staging. No activation CLI.

Returns sanitized data to the transaction's private atomic evidence writer.
Does not load, compile, change, apply or interpret a policy or application.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat

CONTAINER='e2473c1d0a106b515eee5e63984260046beae22b16724af281368f32c7bd69c7'
IMAGE='sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db'
POLICY='df4af4ca290fd03237a7e50b674bf9b3c23fbbc1fd8e18702730778c92447d0a'
SECURITY=Path('/sys/kernel/security/apparmor')
SOURCE=Path('/etc/apparmor.d')

class Refused(RuntimeError):pass

def digest(data):return hashlib.sha256(data).hexdigest()

class Unix(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(15);self.sock.connect('/run/docker.sock')

def docker_get(path):
    if path not in ('/version','/containers/'+CONTAINER+'/json'):raise Refused('docker_path')
    c=Unix('localhost',timeout=15)
    try:
        c.request('GET',path);r=c.getresponse();b=r.read(2_000_001)
        if r.status!=200 or len(b)>2_000_000:raise Refused('docker_response')
        return json.loads(b)
    finally:c.close()

def read(path,limit=1_000_000):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno());b=f.read(limit+1);after=os.fstat(f.fileno())
    if len(b)>limit:raise Refused('read_limit')
    if not stat.S_ISREG(before.st_mode):raise Refused('file_type')
    if (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns):raise Refused('read_drift')
    return b

def identity(c):
    if c['Id']!=CONTAINER or c['Image']!=IMAGE or not c['State']['Running']:raise Refused('container_drift')
    pid=c['State']['Pid']
    if type(pid) is not int or pid<=1:raise Refused('pid')
    return (c['Id'],c['Image'],pid,c['State']['StartedAt'],c.get('AppArmorProfile'))

def include_names(text):
    result=[]
    for line in text.splitlines():
        if re.match(r'^\s*#?include\b',line):
            m=re.fullmatch(r'\s*#?include\s+(?:if exists\s+)?[<"]([A-Za-z0-9_./-]+)[>"]\s*',line)
            if not m:raise Refused('unresolved_include_syntax')
            value=m.group(1)
            if value.startswith('/') or '..' in value.split('/'):raise Refused('include_escape')
            result.append(value)
    return result

def source_records():
    todo=[SOURCE/'docker',SOURCE/'docker-default'];seen=set();result=[]
    while todo:
        p=todo.pop()
        if p in seen:continue
        seen.add(p)
        if len(seen)>64:raise Refused('include_bound')
        if not p.exists():
            if p.is_symlink():raise Refused('source_symlink')
            result.append({'path':str(p),'absent':True});continue
        for parent in [p,*p.parents]:
            s=parent.lstat()
            if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise Refused('source_trust')
            if any('posix_acl' in x for x in os.listxattr(parent,follow_symlinks=False)):raise Refused('source_acl')
        b=read(p,262144);text=b.decode('utf-8');includes=include_names(text)
        result.append({'path':str(p),'sha256':digest(b),'text':text,'includes':includes,
                       'effective_kernel_source_proven':False})
        todo.extend(SOURCE/x for x in includes)
    return result

def security_file(p,raw=False):
    if SECURITY not in p.resolve().parents:raise Refused('securityfs_escape')
    try:
        b=read(p,64*1024*1024 if raw else 262144)
        out={'path':str(p),'sha256':digest(b),'bytes':len(b)}
        if not raw:out['text']=b.decode('utf-8')
        return out
    except PermissionError:return {'path':str(p),'status':'EACCES'}

def collect():
    if os.geteuid()!=0:raise Refused('root_required')
    c=docker_get('/containers/'+CONTAINER+'/json');before=identity(c);pid=before[2]
    attr=read('/proc/%s/attr/current'%pid,4096).decode().strip()
    if attr!='docker-default (enforce)' or before[4]!='docker-default':raise Refused('profile_mapping')
    # Directories are kernel-generated. Only the one fixed profile may match.
    profiles=[p for p in (SECURITY/'policy/profiles').iterdir() if re.fullmatch(r'docker-default\.[0-9]+',p.name)]
    if len(profiles)!=1:raise Refused('profile_count')
    profile=profiles[0]
    if read(profile/'sha256').decode().strip()!=POLICY:raise Refused('policy_drift')
    try:sources=source_records()
    except (OSError,UnicodeError,Refused) as e:
        sources=[{'status':'SOURCE_EXPORT_LIMITED','error_class':type(e).__name__}]
    result={'container':CONTAINER,'image':IMAGE,'pid':pid,'attr_current':attr,
            'security_options':c['HostConfig'].get('SecurityOpt'),
            'docker_version':{k:v for k,v in docker_get('/version').items() if k in ('Version','ApiVersion','MinAPIVersion','GitCommit','Os','Arch')},
            'profile':[security_file(profile/n,n=='raw_data') for n in ('name','mode','sha256','raw_abi','raw_sha256','raw_data')],
            'sources':sources,'features':[]}
    entries=sorted((SECURITY/'features').rglob('*'))
    if len(entries)>1024:raise Refused('feature_bound')
    for p in entries:
        if p.is_symlink():raise Refused('feature_symlink')
        if p.is_file():result['features'].append(security_file(p))
    if identity(docker_get('/containers/'+CONTAINER+'/json'))!=before:raise Refused('container_race')
    if read('/proc/%s/attr/current'%pid,4096).decode().strip()!=attr:raise Refused('profile_race')
    if read(profile/'sha256').decode().strip()!=POLICY:raise Refused('policy_race')
    result['human_readable_effective_policy']='NOT_PROVEN_BY_RAW_BINARY_OR_DISK_SOURCE'
    result['further_general_collector_authorized']=False
    return result
