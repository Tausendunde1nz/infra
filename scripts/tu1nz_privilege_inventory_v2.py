#!/usr/bin/python3 -I
"""Read-only inventory v2. Unknown syntax is evidence, never authorization.
The only persistent writes are new evidence files under BASE. No installation.
"""
import datetime
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

VERSION = '2.0.0'
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
    out=bytearray(); counts={'stdout':0,'stderr':0}; hashes={k:hashlib.sha256() for k in counts}
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
                'start_ns':start,'end_ns':time.monotonic_ns()},bytes(out)
    except OSError as exc:
        return {'exception':type(exc).__name__,'timeout':False,'start_ns':start,'end_ns':time.monotonic_ns()},b''
    finally:
        if p is not None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait()
            p.stdout.close();p.stderr.close()
        sel.close()


def metadata(path):
    s=os.lstat(path)
    row={'path':path,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),
         'inode':s.st_ino,'device':s.st_dev,'symlink':stat.S_ISLNK(s.st_mode)}
    if row['symlink']: row['status']='SYMLINK_REQUIRES_REVIEW';return row
    status,data=run(('/usr/bin/getfacl','-n','-c','-P','-p','--',path))
    row['acl_command']=status
    row['acl']=[x for x in data.decode('ascii','replace').splitlines()
                if re.fullmatch(r'(?:default:)?(?:user|group|mask|other):[0-9]*:[rwx-]{3}(?:\s+#effective:[rwx-]{3})?',x)]
    if stat.S_ISREG(s.st_mode):row['sha256']=digest(secure_read(path))
    return row


class Store:
    def __init__(self, base, commit, source_sha, uid=1001):
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in base.strip('/').split('/'):
                new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=new
            s=os.fstat(fd)
            if stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid not in (0,uid):raise ValueError('unsafe_base')
            self.name='privilege-v2-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
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
        if not re.fullmatch(r'[a-z0-9_-]+\.json',name):raise ValueError('name')
        data=json.dumps(value,sort_keys=True).encode(); tmp='tmp-'+uuid.uuid4().hex
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


def sudo_graph():
    rows=[];seen=set();active=set()
    def visit(path):
        if path in active:raise ValueError('include_cycle')
        if path in seen:return
        if len(seen)>=256:raise ValueError('include_limit')
        active.add(path);seen.add(path)
        try:
            data=secure_read(path);row=metadata(path);row['policy']=safe_policy(data);row['includes']=[];row['parents']=[]
            parent=os.path.dirname(path)
            while parent!='/' and parent:
                row['parents'].append(metadata(parent));parent=os.path.dirname(parent)
            rows.append(row)
            # Logical continuation lines; unknown constructs remain in policy records.
            text=data.decode('utf8','strict').replace('\\\n','')
            for line in text.splitlines():
                directive=include_directive(line,path)
                if directive:
                    kind,target=directive;row['includes'].append({'kind':kind,'path':target})
                    if kind=='include':visit(target)
                    else:
                        row['includes'][-1]['metadata']=metadata(target)
                        if os.path.islink(target):raise ValueError('include_dir_symlink')
                        for name in sorted(os.listdir(target)):
                            if '.' not in name and not name.endswith('~'):visit(os.path.join(target,name))
        except Exception as exc:rows.append({'path':path,'error':type(exc).__name__})
        finally:active.discard(path)
    visit('/etc/sudoers')
    return rows


def policy_inventory():
    rows=[]
    for base in ('/etc/polkit-1','/usr/share/polkit-1/rules.d','/var/lib/polkit-1/localauthority','/etc/polkit-1/localauthority'):
        if not os.path.exists(base):continue
        for directory,dirs,files in os.walk(base,followlinks=False):
            for name in sorted(files):
                p=os.path.join(directory,name)
                try:
                    data=secure_read(p);row=metadata(p)
                    # No JavaScript evaluation, only fixed lexical flags; never a proof of effect.
                    row['features']={v:(v.encode() in data) for v in ('PackageKit','packagekit','subject.active','subject.local','sudo','chatops','polkit.Result.YES','polkit.Result.NO')}
                    row['semantic_status']='UNREVIEWED';rows.append(row)
                except Exception as exc:rows.append({'path':p,'error':type(exc).__name__})
    for directory in ('/usr/share/polkit-1/actions','/usr/local/share/polkit-1/actions'):
        if not os.path.isdir(directory):continue
        for name in sorted(os.listdir(directory)):
            if 'packagekit' not in name.lower():continue
            path=os.path.join(directory,name);data=secure_read(path);root=ET.fromstring(data)
            actions=[]
            for a in root.findall('action'):
                ident=a.get('id','')
                if not re.fullmatch(r'org\.freedesktop\.packagekit\.[a-z-]+',ident):raise ValueError('action_id')
                defaults={}
                for node in a.findall('defaults/*'):
                    if node.tag not in ('allow_any','allow_active','allow_inactive') or node.text not in ('yes','no','auth_self','auth_self_keep','auth_admin','auth_admin_keep'):raise ValueError('action_defaults')
                    defaults[node.tag]=node.text
                actions.append({'id':ident,'defaults':defaults})
            rows.append({'path':path,'sha256':digest(data),'actions':actions})
    return rows


def fixed_command(args, parser):
    status,data=run(args)
    try:status['parsed_stdout']=parser(data)
    except Exception as exc:status['parser_error']=type(exc).__name__
    return status


def property_parser(data):
    rows=[]
    for line in data.decode('utf8','strict').splitlines():
        if '=' not in line:continue
        key,value=line.split('=',1)
        if key in ('Environment','EnvironmentFiles','ExecStart','ExecStop'):
            rows.append({'property':key,'sha256':digest(value.encode())});continue
        # unit identifiers, paths, users and state only; unknown free text is hashed.
        if re.fullmatch(r'[A-Za-z0-9_./:@+\- ]*',value):rows.append({'property':key,'value':value})
        else:rows.append({'property':key,'sha256':digest(value.encode())})
    return rows


def identities_and_targets():
    user=pwd.getpwnam('chatops')
    result={'uid':user.pw_uid,'gid':user.pw_gid,
            'groups':[{'name':g.gr_name,'gid':g.gr_gid,'members':g.gr_mem} for g in grp.getgrall()
                      if 'chatops' in g.gr_mem or g.gr_gid==user.pw_gid], 'targets':[]}
    for path in ('/etc/group','/etc/gshadow','/var/run/docker.sock',
                 '/usr/local/bin/t1nz_create_golden.sh','/opt/tu1nz_repos/infra/t1nz_create_golden.sh',
                 '/usr/local/bin/tu1nz_doc_pipeline.py','/usr/local/bin/tu1nz_doc_auto.sh',
                 '/usr/local/bin/tu1nz_doc_update.sh','/opt/docs/upload_log.txt'):
        try: result['targets'].append(metadata(path))
        except Exception as exc:result['targets'].append({'path':path,'error':type(exc).__name__})
    return result


def processes():
    rows=[]
    for pid in os.listdir('/proc'):
        if not pid.isdecimal():continue
        try:
            data=open('/proc/'+pid+'/status').read()
            fields=dict(l.split(':',1) for l in data.splitlines() if ':' in l)
            gids=[int(v) for v in fields['Groups'].split()]
            uids=[int(v) for v in fields['Uid'].split()]
            if 1001 not in uids and 987 not in gids:continue
            cgroup=open('/proc/'+pid+'/cgroup').read()
            units=re.findall(r'[a-zA-Z0-9_@.\-]+\.service',cgroup)
            fds=[]
            try:
                for f in os.listdir('/proc/'+pid+'/fd'):
                    try:
                        target=os.readlink('/proc/'+pid+'/fd/'+f)
                        if re.fullmatch(r'socket:\[[0-9]+\]',target):fds.append(target)
                    except OSError:pass
            except OSError:pass
            rows.append({'pid':int(pid),'uids':uids,'gids':[int(v) for v in fields['Gid'].split()],
                         'groups':gids,'units':units,'socket_inodes':fds,
                         'start_ticks':open('/proc/'+pid+'/stat').read().rsplit(')',1)[1].split()[19]})
        except (OSError,KeyError,ValueError):rows.append({'pid':int(pid),'status':'RACE_OR_UNREADABLE'})
    return rows


def sessions():
    status,data=run(('/usr/bin/loginctl','show-user','1001','--no-pager','-p','Sessions','-p','State','-p','Linger'))
    rows=[{'user_query':status,'properties':property_parser(data)}]
    for line in data.decode('ascii','replace').splitlines():
        if line.startswith('Sessions='):
            for ident in line.split('=',1)[1].split():
                if not re.fullmatch('[a-zA-Z0-9]+',ident):raise ValueError('session_id')
                rows.append(fixed_command(('/usr/bin/loginctl','show-session',ident,'--no-pager',
                                           '--property=Id,User,Active,Remote,State,Type,Class,Leader,Service'),property_parser))
    return rows


def references():
    rows=[];count=0
    for base in ('/etc/systemd/system','/usr/local/bin','/etc/cron.d','/var/spool/cron/crontabs','/opt/tu1nz_repos/infra'):
        for directory,dirs,files in os.walk(base,followlinks=False):
            dirs[:]=[d for d in dirs if d not in ('.git','node_modules','venv','.venv') and not os.path.islink(os.path.join(directory,d))]
            for name in files:
                path=os.path.join(directory,name);count+=1
                if count>20000:raise ValueError('scan_limit')
                try:
                    data=secure_read(path,512*1024)
                    hits={term:[i for i,line in enumerate(data.splitlines(),1) if term.encode() in line] for term in TERMS if term.encode() in data}
                    if hits:rows.append({'metadata':metadata(path),'matches':hits})
                except (OSError,ValueError) as exc:rows.append({'path':path,'error':type(exc).__name__})
    return rows


def interrupt(signum,frame):raise InterruptedError('signal')


def main():
    # Expected commit is supplied by the separately pinned bootstrap, not arbitrary CLI.
    if len(sys.argv)!=1 or os.geteuid()!=0:return 3
    commit=globals().get('PINNED_COMMIT','');source_sha=globals().get('PINNED_SHA','')
    if not re.fullmatch('[0-9a-f]{40}',commit) or not re.fullmatch('[0-9a-f]{64}',source_sha):return 3
    os.environ.clear();os.environ.update(ENV);os.umask(0o077)
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,interrupt)
    store=None
    try:
        store=Store(BASE,commit,source_sha)
        store.section('sudo-includes',sudo_graph)
        store.section('visudo',lambda:fixed_command(('/usr/sbin/visudo','-c','-f','/etc/sudoers'),lambda b:{'output_sha256':digest(b)}))
        store.section('effective-sudo',lambda:fixed_command(('/usr/bin/sudo','-n','-l','-U','chatops'),safe_policy))
        store.section('polkit',policy_inventory)
        store.section('identities-targets',identities_and_targets)
        store.section('processes',processes)
        store.section('sessions',sessions)
        for n,unit in enumerate(UNITS):
            store.section('unit-'+str(n),lambda unit=unit:fixed_command(('/usr/bin/systemctl','show',unit,'--no-pager','--property=Id,User,Group,SupplementaryGroups,MainPID,ActiveState,SubState,FragmentPath,DropInPaths,ExecStart,Requires,Wants,After,Before,PartOf,BindsTo,Restart,KillMode,TimeoutStopUSec'),property_parser))
        store.section('references',references)
        store.manifest['collection_finished']=True
        store.manifest['review_required']=True
    except BaseException as exc:
        if store:store.manifest['exception']=type(exc).__name__
    finally:
        if store:
            store.close();print(json.dumps({'result_directory':store.path,'status':'INCOMPLETE','version':VERSION}))
    return 2 if store else 3


if __name__=='__main__':sys.exit(main())
