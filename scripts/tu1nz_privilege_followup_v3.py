#!/usr/bin/python3 -I
"""Read-only follow-up inventory v3. Unknown syntax is evidence, never authorization.
The only persistent writes are new evidence files under BASE. No installation.
"""
import datetime
from pathlib import Path
import hashlib
import grp
import pwd
import json
import os
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

VERSION = '3.0.0'
BASE = '/opt/tu1nz_repos/network-hardening-private-2026-09-22'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'}
UNITS = ('tu1nz-adult-public-s8-telegram.service', 'tu1nz-adult-public-s10-wms.service',
         'tu1nz-adult-public-s8-landing.service', 'tu1nz-adult-public-s7.service',
         't1nz-golden-snapshot.service', 't1nz-golden-snapshot.timer', 'tu1nz-doc.service')
TERMS = ('t1nz_create_golden.sh', 'upload_log.txt', 'pandoc', 'sudo mkdir', 'sudo chown', '/var/run/docker.sock', '/run/docker.sock')
KNOWN = {'chatops','root','ALL','NOPASSWD','PASSWD','NOSETENV','SETENV','Defaults','User_Alias','Runas_Alias','Host_Alias','Cmnd_Alias','sudo','admin','env_reset','mail_badpass','secure_path','use_pty','includedir','include'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_policy(data):
    """No arbitrary literals leave protected policy. Syntax skeleton + hashes."""
    result = []
    for n, line in enumerate(data.decode('utf8', 'replace').splitlines(), 1):
        v = line.strip()
        if not v or (v.startswith('#') and not v.startswith(('#include ', '#includedir '))):
            continue
        tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_-]*', v)
        result.append({'line': n, 'sha256': digest(line.encode()),
                       'known_tokens': [x for x in tokens if x in KNOWN],
                       'nopasswd': bool(re.search(r'\bNOPASSWD\s*:', v)),
                       'status': 'REQUIRES_SEMANTIC_REVIEW'})
    return result


def include_directive(line, parent):
    match = re.match(r'^\s*(?:@|#)(include|includedir)\s+(.+?)\s*$', line)
    if not match:
        return None
    words = shlex.split(match.group(2), comments=True)
    if len(words) != 1 or '\x00' in words[0] or '%' in words[0]:
        raise ValueError('unsupported_include')
    p = words[0]
    if not os.path.isabs(p):
        p = os.path.join(os.path.dirname(parent), p)
    return match.group(1), os.path.normpath(p)


def secure_read(path, limit=2*1024*1024):
    """Reject symlinks throughout ancestry and non-regular inputs, including races."""
    if not path.startswith('/') or '..' in path.split('/'):
        raise ValueError('path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = [p for p in path.split('/') if p]
        for part in parts[:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        f = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            s = os.fstat(f)
            if not stat.S_ISREG(s.st_mode) or s.st_size > limit:
                raise ValueError('file_type_or_size')
            data = b''
            while len(data) <= limit:
                chunk = os.read(f, min(65536, limit+1-len(data)))
                if not chunk: break
                data += chunk
            after = os.fstat(f)
            if len(data)>limit or (s.st_ino,s.st_mtime_ns,s.st_size)!=(after.st_ino,after.st_mtime_ns,after.st_size):
                raise ValueError('file_drift')
            return data
        finally: os.close(f)
    finally: os.close(fd)


def run(args, timeout=20, limit=1024*1024):
    """Capture streams separately, bounded in memory; never return raw stderr."""
    start=time.monotonic_ns(); p=None; sel=selectors.DefaultSelector()
    out=bytearray(); err=bytearray(); counts={'stdout':0,'stderr':0}; hashes={k:hashlib.sha256() for k in counts}
    timed=False; overflow=False
    try:
        p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           cwd='/',env=ENV,start_new_session=True)
        for key,stream in [('stdout',p.stdout),('stderr',p.stderr)]:
            os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,key)
        deadline=time.monotonic()+timeout
        while sel.get_map():
            if time.monotonic()>=deadline: timed=True;break
            for event,_ in sel.select(min(.1,max(0,deadline-time.monotonic()))):
                b=os.read(event.fileobj.fileno(),65536)
                if not b: sel.unregister(event.fileobj);continue
                key=event.data;counts[key]+=len(b);hashes[key].update(b)
                if key=='stdout' and len(out)<limit: out.extend(b[:limit-len(out)])
                if key=='stderr' and len(err)<limit: err.extend(b[:limit-len(err)])
                if counts[key]>limit: overflow=True;break
            if overflow:break
        if overflow or timed:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        try:p.wait(timeout=max(.01,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:timed=True
        return {'rc':p.returncode,'timeout':timed,'overflow':overflow,
                'stdout':{'bytes':counts['stdout'],'sha256':hashes['stdout'].hexdigest()},
                'stderr':{'bytes':counts['stderr'],'sha256':hashes['stderr'].hexdigest()},
                'start_ns':start,'end_ns':time.monotonic_ns()},bytes(out),bytes(err)
    except OSError as exc:
        return {'exception':type(exc).__name__,'timeout':False,'start_ns':start,'end_ns':time.monotonic_ns()},b'',b''
    finally:
        if p is not None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait()
            p.stdout.close();p.stderr.close()
        sel.close()


class Store:
    def __init__(self, base, commit, source_sha, uid=1001):
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in base.strip('/').split('/'):
                new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=new
            s=os.fstat(fd)
            if stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid not in (0,uid):raise ValueError('unsafe_base')
            self.name='privilege-v3-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
            os.mkdir(self.name,0o700,dir_fd=fd)
            self.fd=os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            if os.fstat(self.fd).st_uid != os.geteuid(): raise ValueError('output_owner')
            os.fchmod(self.fd,0o700)
        finally:os.close(fd)
        self.uid=uid;self.entries=[];self.path=base+'/'+self.name
        self.manifest={'version':VERSION,'expected_commit':commit,'script_sha256':source_sha,
                       'status':'INCOMPLETE','entries':self.entries}
        self.put('manifest.json',self.manifest)

    def put(self,name,value):
        if not re.fullmatch(r'[a-z0-9_-]+\.(?:json|bin)',name):raise ValueError('name')
        data=value if isinstance(value,bytes) else json.dumps(value,sort_keys=True).encode(); tmp='tmp-'+uuid.uuid4().hex
        oldmask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        fd=None
        try:
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
            os.fchmod(fd,0o600)
            with os.fdopen(os.dup(fd),'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
            os.rename(tmp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)
        finally:
            if fd is not None: os.close(fd)
            signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)
        return digest(data)

    def section(self,name,fn):
        start=time.monotonic_ns()
        try: value=fn();record={'status':'COLLECTED','data':value}
        except InterruptedError: raise
        except Exception as exc:record={'status':'ERROR','exception':type(exc).__name__}
        record.update(start_ns=start,end_ns=time.monotonic_ns())
        sha=self.put(name+'.json',record)
        self.entries.append({'file':name+'.json','sha256':sha,'status':record['status']})
        self.put('manifest.json',self.manifest)

    def close(self):
        # Fail-closed semantics: collected evidence is not a complete security proof.
        self.put('manifest.json',self.manifest)
        if os.geteuid()==0:
            for name in os.listdir(self.fd):
                os.chown(name,self.uid,self.uid,dir_fd=self.fd,follow_symlinks=False)
            os.fchown(self.fd,self.uid,self.uid)
        os.close(self.fd)


def verified_bytes(data, expected):
    if digest(data) != expected: raise ValueError('checksum_mismatch')
    return data


# v3 changes the evidence policy: exact raw bytes stay PRIVATE, never stdout/Git.
# The helper below replaces the metadata helper inherited in the standalone core.
class Interrupted(BaseException):
    pass


def stop(signum,frame):
    raise Interrupted()


class Collector:
    def __init__(self,store):
        self.store=store;self.serial=0;self.files={};self.errors=[];self.commands=[];self.acls={};self.extra_units=set()

    def raw(self,data):
        name='raw-'+str(self.serial).zfill(5)+'.bin';self.serial+=1
        sha=self.store.put(name,data)
        self.store.entries.append({'file':name,'sha256':sha,'status':'PRIVATE_RAW'})
        self.store.put('manifest.json',self.store.manifest)
        return {'file':name,'sha256':sha,'bytes':len(data)}

    def error(self,scope,exc):
        row={'scope':scope,'exception':type(exc).__name__}
        self.errors.append(row);self.store.put('errors.json',self.errors)
        return row

    def cmd(self,args,timeout=20,allowed_rc=(0,)):
        status,out,err=run(args,timeout=timeout,limit=8*1024*1024)
        status.update(argv=list(args),stdout_raw=self.raw(out),stderr_raw=self.raw(err))
        status['passed']=status.get('rc') in allowed_rc and not status.get('timeout') and not status.get('overflow') and not status.get('exception')
        if err:status['requires_stderr_review']=True
        self.commands.append(status)
        self.store.put('commands.json',self.commands)
        if not status['passed']:self.errors.append({'scope':'command','index':len(self.commands)-1})
        return status,out

    def capture(self,path):
        if path in self.files:return self.files[path]
        row={'requested_path':path};self.files[path]=row
        try:
            # Resolve and record each lexical path component. A changed target fails.
            canonical=str(Path(path).resolve(strict=True));row['canonical']=canonical
            row['ancestry']=[]
            seen=set()
            candidates=[path,canonical]
            for candidate in candidates:
                if len(candidates)>128:raise ValueError('symlink_chain_limit')
                current='/'
                for component in candidate.strip('/').split('/'):
                    current=os.path.join(current,component)
                    if current in seen:continue
                    seen.add(current);s=os.lstat(current)
                    meta={'path':current,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),
                          'device':s.st_dev,'inode':s.st_ino,'file_type':stat.S_IFMT(s.st_mode)}
                    if stat.S_ISLNK(s.st_mode):
                        meta['symlink_target']=os.readlink(current)
                        target=meta['symlink_target']
                        target=os.path.normpath(target if os.path.isabs(target) else os.path.join(os.path.dirname(current),target))
                        if target not in candidates:candidates.append(target)
                    if current not in self.acls:
                        self.cmd(('/usr/bin/getfacl','-n','-p','--',current))
                        self.acls[current]=self.commands[-1]['stdout_raw']
                    meta['acl_reference']=self.acls[current]
                    row['ancestry'].append(meta)
            s=os.lstat(canonical)
            if stat.S_ISREG(s.st_mode):
                data=secure_read(canonical,16*1024*1024);row['content']=self.raw(data)
                if data.startswith(b'#!'):
                    shebang=data.splitlines()[0][2:].decode('utf8','strict').strip()
                    row['shebang']=shebang
                    interpreter=shlex.split(shebang)[0]
                    if interpreter.startswith('/') and interpreter!=path:self.capture(interpreter)
            elif stat.S_ISDIR(s.st_mode):row['directory']=True
            else:row['special_file']=True
            _,acl=self.cmd(('/usr/bin/getfacl','-n','-p','--',canonical))
            row['acl_reference']=self.commands[-1]['stdout_raw']
            if str(Path(path).resolve(strict=True))!=canonical:raise ValueError('symlink_drift')
            final=os.lstat(canonical)
            if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)!=(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns):raise ValueError('file_drift')
        except Exception as exc:row['error']=self.error(path,exc)
        self.store.put('files.json',self.files)
        return row

    def bytes(self,path):
        row=self.capture(path)
        if row.get('error') or 'content' not in row:raise ValueError('uncaptured_source')
        ref=row['content'];fd=os.open(ref['file'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.store.fd)
        with os.fdopen(fd,'rb') as f:data=f.read()
        if digest(data)!=ref['sha256']:raise ValueError('evidence_drift')
        return data

    def sudo(self):
        active=set();visited=set();graph=[]
        def visit(path):
            canonical=str(Path(path).resolve(strict=True))
            if canonical in active:raise ValueError('include_cycle')
            if canonical in visited:return
            if len(visited)>=256:raise ValueError('include_limit')
            active.add(canonical);visited.add(canonical)
            data=self.bytes(path);row={'path':path,'canonical':canonical,'includes':[],'semantic_review_required':True};graph.append(row)
            for line in data.decode('utf8','strict').replace('\\\n','').splitlines():
                if re.match(r'^\s*[@#]include',line):
                    # sudo's %h expansion is the short host name; unknown expansions fail.
                    line=line.replace('%h',socket.gethostname().split('.')[0])
                    directive=include_directive(line,path)
                    if directive is None:raise ValueError('unparsed_include')
                    kind,target=directive;row['includes'].append({'kind':kind,'path':target});self.capture(target)
                    if kind=='includedir':
                        for name in sorted(os.listdir(target)):
                            if '.' not in name and not name.endswith('~'):visit(os.path.join(target,name))
                    else:visit(target)
            active.remove(canonical)
        try:visit('/etc/sudoers')
        finally:self.store.put('include-graph.json',graph)
        self.cmd(('/usr/sbin/visudo','-c','-f','/etc/sudoers'))
        self.cmd(('/usr/bin/sudo','-n','-ll','-U','chatops'))
        text=self.bytes('/etc/sudoers.d/trendwatch-restart').decode('utf8','strict')
        for path in re.findall(r'/[a-zA-Z0-9_./+-]+',text):
            if os.path.lexists(path):self.capture(path)
        for unit in re.findall(r'[a-zA-Z0-9_@.-]+\.(?:service|timer|socket|path)',text):self.extra_units.add(unit)
        words=shlex.split(text,comments=True)
        for i,word in enumerate(words[:-1]):
            if word in ('restart','try-restart','reload','start','stop'):
                unit=words[i+1].rstrip(',')
                if re.fullmatch('[a-zA-Z0-9_@.-]+',unit):self.extra_units.add(unit if '.' in unit else unit+'.service')

    def policies(self):
        for base in ('/etc/polkit-1','/usr/share/polkit-1/rules.d','/usr/local/share/polkit-1/rules.d',
                     '/var/lib/polkit-1/localauthority','/usr/share/polkit-1/actions'):
            if not os.path.exists(base):continue
            self.capture(base)
            for directory,dirs,files in os.walk(base,followlinks=False):
                for name in dirs:
                    if os.path.islink(os.path.join(directory,name)):
                        self.capture(os.path.join(directory,name));self.error('policy_symlink_directory',ValueError())
                for name in files:
                    if base.endswith('/actions') and 'packagekit' not in name.lower():continue
                    self.capture(os.path.join(directory,name))
        self.cmd(('/usr/bin/dpkg-query','-W','-f=${binary:Package} ${db:Status-Abbrev} ${Version}\n','polkitd','polkitd-pkla','packagekit'),allowed_rc=(0,1))
        self.cmd(('/usr/bin/dpkg-query','-L','polkitd'))
        self.cmd(('/usr/bin/dpkg-query','-L','polkitd-pkla'),allowed_rc=(0,1))
        self.cmd(('/usr/bin/systemctl','show','polkit.service','--no-pager','-p','ExecStart','-p','FragmentPath','-p','MainPID'))
        for p in ('/usr/lib/polkit-1/polkit-agent-helper-1','/usr/lib/polkit-1/polkitd','/usr/libexec/polkitd','/usr/lib/polkit-1/polkitd-pkla'):
            if os.path.exists(p):self.capture(p)

    def sessions(self):
        status,data=self.cmd(('/usr/bin/loginctl','show-user','1001','--no-pager','-p','Sessions'))
        for line in data.decode('ascii','strict').splitlines():
            if line.startswith('Sessions='):
                for ident in line.split('=',1)[1].split():
                    if not re.fullmatch('[a-zA-Z0-9]+',ident):raise ValueError('session_id')
                    args=['/usr/bin/loginctl','show-session',ident,'--no-pager']
                    for prop in ('Id','User','Remote','Active','State','Type','Class','Leader','Service','Seat'):args+=['-p',prop]
                    self.cmd(tuple(args))

    def auth(self):
        subject=globals().get('PINNED_SUBJECT','')
        if not re.fullmatch('[0-9]+,[0-9]+,1001',subject):raise ValueError('subject')
        pid,ticks,uid=subject.split(',')
        fields=dict(l.split(':',1) for l in open('/proc/'+pid+'/status') if ':' in l)
        if any(int(v)!=1001 for v in fields['Uid'].split()):raise ValueError('subject_uid')
        if open('/proc/'+pid+'/stat').read().rsplit(')',1)[1].split()[19]!=ticks:raise ValueError('subject_reused')
        data=self.bytes('/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy')
        root=ET.fromstring(data)
        for a in root.findall('action'):
            ident=a.get('id','')
            if not re.fullmatch('org\\.freedesktop\\.packagekit\\.[a-z-]+',ident):raise ValueError('action')
            # Only asks the policy daemon. Does NOT call the PackageKit action.
            self.cmd(('/usr/bin/pkcheck','--action-id',ident,'--process',subject),allowed_rc=(0,1))
        self.store.put('auth-subject.json',{'pid':int(pid),'start_ticks':ticks,'uid':int(uid),'simulated':False,'interactive':False})

    def units(self):
        self.cmd(('/usr/bin/ss','-lntup'))
        self.cmd(('/usr/bin/ss','-xapn'))
        queue=list(UNITS)+sorted(self.extra_units)+['trendwatch.service','trendwatch.timer','polkit.service']
        visited=set();records=[]
        properties=('Id','FragmentPath','SourcePath','DropInPaths','ExecStart','ExecStartPre','ExecStartPost','ExecStop',
                    'ExecReload','EnvironmentFiles','WorkingDirectory','RuntimeDirectory','StateDirectory','LogsDirectory',
                    'User','Group','SupplementaryGroups','MainPID','Requires','Wants','After','Before','PartOf','BindsTo',
                    'TriggeredBy','Triggers','ActiveState','SubState','TimeoutStopUSec','Restart','KillMode')
        while queue:
            unit=queue.pop(0)
            if unit in visited:continue
            if len(visited)>128:raise ValueError('unit_limit')
            visited.add(unit)
            if not re.fullmatch('[a-zA-Z0-9_.@-]+\\.(service|timer|socket|path)',unit):raise ValueError('unit_name')
            args=['/usr/bin/systemctl','show',unit,'--no-pager']
            for prop in properties:args+=['-p',prop]
            status,data=self.cmd(tuple(args));records.append({'unit':unit,'command_index':len(self.commands)-1})
            props=dict(l.split('=',1) for l in data.decode('utf8','strict').splitlines() if '=' in l)
            for key in ('Requires','Wants','After','Before','PartOf','BindsTo','TriggeredBy','Triggers'):
                for v in props.get(key,'').split():
                    if v.startswith(('tu1nz','t1nz','trendwatch')) and v.endswith(('.service','.timer','.socket','.path')):queue.append(v)
            for key in properties:
                if key not in ('FragmentPath','SourcePath','DropInPaths','EnvironmentFiles','WorkingDirectory','ExecStart','ExecStartPre','ExecStartPost','ExecStop','ExecReload'):continue
                for path in re.findall(r'(?<!\S)/[^\s;{}"\']+|(?<=path=)/[^\s;{}"\']+',props.get(key,'')):
                    path=path.rstrip(')')
                    if '\\' in path or '%' in path:self.error('unparsed_unit_path',ValueError());continue
                    self.capture(path)
            pid=props.get('MainPID','0')
            if pid.isdecimal() and int(pid)>0:
                for suffix in ('status','cgroup','stat','net/unix','net/tcp','net/tcp6'):
                    # Proc pseudo-files need dedicated bounded reads, not st_size-based drift checks.
                    try:
                        with open('/proc/'+pid+'/'+suffix,'rb') as f:raw=f.read(4*1024*1024)
                        ref=self.raw(raw);records[-1].setdefault('proc',{})[suffix]=ref
                    except OSError as exc:self.error('unit_proc',exc)
                try:
                    exe=os.readlink('/proc/'+pid+'/exe');self.capture(exe)
                    fds=[]
                    for fd in os.listdir('/proc/'+pid+'/fd'):
                        try:
                            value=os.readlink('/proc/'+pid+'/fd/'+fd)
                            if value.startswith('socket:['):fds.append({'fd':fd,'target':value})
                        except OSError:pass
                    records[-1]['socket_fds']=fds
                except OSError as exc:self.error('unit_exe',exc)
        self.store.put('units.json',records)

    def references(self):
        # Fixed source roots; content remains private, no execution of discovered files.
        matches=[]
        for base in ('/etc/systemd/system','/usr/local/bin','/etc/cron.d','/var/spool/cron/crontabs','/opt/tu1nz_repos/infra'):
            for directory,dirs,files in os.walk(base,followlinks=False):
                dirs[:]=[d for d in dirs if d not in ('.git','snapshots','node_modules','.venv','venv')]
                for name in files:
                    p=os.path.join(directory,name)
                    try:
                        target=str(Path(p).resolve(strict=True))
                        if not stat.S_ISREG(os.stat(target).st_mode):continue
                        data=secure_read(target,512*1024)
                        found=[term for term in TERMS+('trendwatch','docker.sock') if term.encode() in data]
                        if found:
                            self.capture(p);matches.append({'path':p,'terms':found})
                    except (OSError,ValueError) as exc:self.error('reference:'+p,exc)
        self.store.put('references.json',matches)
        for p in ('/etc/group','/etc/gshadow','/usr/local/bin/t1nz_create_golden.sh','/opt/tu1nz_repos/infra/t1nz_create_golden.sh',
                  '/usr/local/bin/monthly_sysstatus.sh','/usr/local/bin/trim_upload_log.sh','/usr/local/bin/trendwatch_post.sh',
                  '/usr/local/bin/tu1nz_doc_pipeline.py','/var/run/docker.sock'):
            if os.path.lexists(p):self.capture(p)
        rows=[]
        for pid in os.listdir('/proc'):
            if not pid.isdecimal():continue
            try:
                raw=open('/proc/'+pid+'/status','rb').read();f=dict(l.split(b':',1) for l in raw.splitlines() if b':' in l)
                if b'987' in f[b'Groups'].split() or b'1001' in f[b'Uid'].split():
                    rows.append({'pid':pid,'status':self.raw(raw),'cgroup':self.raw(open('/proc/'+pid+'/cgroup','rb').read())})
            except (OSError,KeyError):continue
        self.store.put('processes.json',rows)


def main():
    if len(sys.argv)!=1 or os.geteuid()!=0:return 3
    commit=globals().get('PINNED_COMMIT','');sha=globals().get('PINNED_SHA','')
    if not re.fullmatch('[0-9a-f]{40}',commit) or not re.fullmatch('[0-9a-f]{64}',sha):return 3
    os.environ.clear();os.environ.update(ENV);os.umask(0o077)
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,stop)
    store=None
    try:
        store=Store(BASE,commit,sha);c=Collector(store)
        for name in ('sudo','policies','sessions','auth','units','references'):
            store.section(name,getattr(c,name))
        store.manifest.update(collection_finished=True,review_required=True,issues=len(c.errors))
    except BaseException as exc:
        if store:store.manifest['exception']=type(exc).__name__
    finally:
        if store:
            hashes={}
            for name in os.listdir(store.fd):
                if name=='manifest.json' or name.startswith('tmp-'):continue
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=store.fd)
                with os.fdopen(fd,'rb') as f:hashes[name]=digest(f.read())
            store.manifest['file_hashes']=hashes
            store.close();print(json.dumps({'result_directory':store.path,'status':'INCOMPLETE','version':VERSION}))
    return 2 if store else 3


if __name__=='__main__':sys.exit(main())
