#!/usr/bin/python3 -I
"""Root trust evidence v5. Read-only configuration queries, never activation.
Only new root-private evidence is written. No script evaluation, service action,
network request, journal payload, commandline or environment-value export.
Docker inspect is restricted to security metadata. Always INCOMPLETE pending
semantic graph review. Exit 2 evidence collected, 3 unsafe initialization.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time

BASE = Path('/var/lib/tu1nz-root-trust-v51')
FILES = (
 '/etc/crontab', '/var/spool/cron/crontabs/root', '/var/spool/cron/crontabs/chatops',
 '/usr/local/bin/aide_daily.sh', '/usr/local/bin/backup_notify.sh',
 '/usr/local/bin/doku_agent_health.sh', '/usr/local/bin/tu1nz-ape-notify-core',
 '/usr/local/bin/tw_youtube_live.sh', '/usr/local/bin/trendwatch_post.sh',
 '/usr/local/bin/trendwatch_fetch.sh', '/usr/local/bin/tw_affiliate.sh',
 '/usr/local/bin/tu1nz_sync_all.sh', '/etc/systemd/system/tu1nz_agentmode.service',
)
TREES = ('/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly',
         '/etc/cron.monthly', '/var/spool/cron/crontabs')
TERMS = ('/opt/trendwatch/', 'today_title.txt', 'today_live_title.txt',
         'tw_youtube_live.sh', 'trendwatch_post.sh', '/var/log/tausendunde1nz',
         '/var/lib/tausendunde1nz', '/opt/tu1nz_repos')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def summary(data):
    text = data.decode('utf-8', errors='replace')
    result = {'bytes': len(data), 'sha256': sha(data), 'references': [], 'write_syntax_lines': [], 'literal_path_metadata': []}
    for n, line in enumerate(text.splitlines(), 1):
        matched = [term for term in TERMS if term in line]
        if matched:
            result['references'].append({'line': n, 'known_terms': matched})
        if re.search(r'\b(?:tee|mkdir|chown|chmod|install)\b|>>?|write_text|write_bytes|appendFile|writeFile', line):
            result['write_syntax_lines'].append(n)
    # Only literal absolute filesystem paths, never URL/query/credential values.
    paths = sorted(set(re.findall(r'(?<![A-Za-z0-9:/])/(?:usr/local|opt|var/log|var/lib|etc|run)/[A-Za-z0-9_./-]+', text)))
    for path in paths[:128]:
        if len(path) > 240:
            continue
        try:
            s = os.lstat(path)
            item = {'path': path, 'uid': s.st_uid, 'gid': s.st_gid,
                    'mode': oct(stat.S_IMODE(s.st_mode)), 'symlink': stat.S_ISLNK(s.st_mode)}
            if hasattr(os, 'listxattr') and not item['symlink']:
                item['acls'] = {a: os.getxattr(path, a, follow_symlinks=False).hex()
                                for a in os.listxattr(path, follow_symlinks=False) if 'posix_acl' in a}
            result['literal_path_metadata'].append(item)
        except FileNotFoundError:
            result['literal_path_metadata'].append({'path': path, 'absent': True})
        except OSError as exc:
            result['literal_path_metadata'].append({'path': path, 'error_class': type(exc).__name__})
    # Never include source lines, messages, environment values or command output.
    return result


def protected_directory(path, create=False):
    path = Path(path)
    current = Path('/')
    for part in path.parts[1:]:
        current = current / part
        try:
            s = current.lstat()
        except FileNotFoundError:
            if not create or current != path:
                raise
            current.mkdir(mode=0o700)
            s = current.lstat()
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or
                stat.S_IMODE(s.st_mode) & 0o022):
            raise ValueError('untrusted_output_ancestor')
        if hasattr(os, 'listxattr') and any('posix_acl' in x for x in os.listxattr(current)):
            raise ValueError('output_acl')
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('output_mode')


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.hashes = {}
        self.entries = []

    def write(self, name, data):
        if not re.fullmatch(r'[a-z0-9.-]+', name):
            raise ValueError('output_name')
        temporary = self.directory / ('.tmp-' + secrets.token_hex(16))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            target = self.directory / name
            if target.exists() or target.is_symlink():
                raise ValueError('output_exists')
            os.rename(temporary, target)
            dfd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            self.hashes[name] = sha(data)
        finally:
            if temporary.exists():
                temporary.unlink()

    def section(self, name, action):
        start = time.monotonic_ns()
        try:
            result = action()
            entry = {'section': name, 'status': 'OK', 'result': result}
        except BaseException as exc:
            entry = {'section': name, 'status': 'INCOMPLETE', 'exception_class': type(exc).__name__}
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            if 'entry' in locals():
                entry['start_monotonic_ns'] = start
                entry['end_monotonic_ns'] = time.monotonic_ns()
                try:
                    self.write('section-' + name + '.json', json.dumps(entry, sort_keys=True).encode())
                except Exception as failure:
                    entry = {'section':name,'status':'INCOMPLETE',
                             'persistence_error_class':type(failure).__name__,
                             'start_monotonic_ns':start,'end_monotonic_ns':time.monotonic_ns()}
                self.entries.append(entry)
        return entry


# Collection is NOT a semantic proof. Every parsed execution source remains
# REVIEW_REQUIRED until its dynamic and transitive edges are reviewed.
import pwd
import grp
import struct
import selectors

ROOTS = {
 'systemd': ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late','/etc/systemd/system-generators','/usr/lib/systemd/system-generators'),
 'cron': ('/etc/crontab','/etc/cron.d','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly','/etc/cron.monthly','/var/spool/cron/crontabs'),
 'at-anacron': ('/etc/anacrontab','/var/spool/cron/atjobs','/var/spool/cron/atspool'),
 'sudo': ('/etc/sudoers','/etc/sudoers.d'),
 'polkit': ('/etc/polkit-1','/usr/share/polkit-1/rules.d','/usr/share/polkit-1/actions','/var/lib/polkit-1/localauthority'),
 'logrotate': ('/etc/logrotate.conf','/etc/logrotate.d'),
 'package-hooks': ('/etc/apt/apt.conf','/etc/apt/apt.conf.d','/etc/dpkg','/var/lib/dpkg/info'),
 'network-hooks': ('/etc/network','/etc/networkd-dispatcher','/usr/lib/networkd-dispatcher','/etc/NetworkManager/dispatcher.d','/etc/ppp','/etc/dhcp','/etc/udev/rules.d','/usr/lib/udev/rules.d'),
 'boot-shutdown': ('/etc/rc.local','/etc/init.d','/etc/rc0.d','/etc/rc1.d','/etc/rc2.d','/etc/rc3.d','/etc/rc4.d','/etc/rc5.d','/etc/rc6.d','/etc/rcS.d','/usr/lib/systemd/system-shutdown'),
 'local-programs': ('/usr/local/bin','/usr/local/sbin'),
 'docker': ('/etc/docker','/run/docker.sock'),
 'runtime-resolution': ('/etc/ld.so.preload','/etc/ld.so.conf','/etc/ld.so.conf.d','/etc/environment','/etc/profile','/etc/profile.d','/etc/systemd/system.conf','/etc/systemd/system.conf.d'),
 'additional-hooks': ('/etc/kernel','/etc/initramfs-tools','/etc/tmpfiles.d','/usr/lib/tmpfiles.d','/etc/dbus-1/system.d','/usr/share/dbus-1/system-services','/etc/pam.d','/etc/security','/etc/default/cron'),
 'doc-job': ('/usr/local/bin/build_system_doc.sh','/usr/local/bin/check_system_doc.sh','/opt/tu1nz_repos/docs/system_manifest/render_kapitel3.sh','/opt/Tausendunde1nz/_Doku','/opt/docs/upload_log.txt'),
}
MAX_FILES=30000
MAX_BYTES=300_000_000
UNIT_PROPS=('Id','User','Group','SupplementaryGroups','DynamicUser','ExecStart','ExecStartPre','ExecStartPost','ExecStop','ExecStopPost','ExecReload','EnvironmentFiles','WorkingDirectory','RootDirectory','RootImage','FragmentPath','DropInPaths','Requires','Wants','Triggers','TriggeredBy','SourcePath','CapabilityBoundingSet','AmbientCapabilities','NoNewPrivileges','ReadWritePaths','BindPaths','BindReadOnlyPaths','LoadState','ActiveState','SubState','MainPID')


def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)


def strict_read(path, limit=2_000_000):
    """Walk directory descriptors without following links; detect inode/metadata drift."""
    if not os.path.isabs(path) or '..' in Path(path).parts: raise ValueError('absolute_path')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    ancestry=[]
    try:
        for part in Path(path).parts[1:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            ancestry.append((os.dup(fd),part,identity(os.fstat(nxt))))
            os.close(fd);fd=nxt
        f=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            first=os.fstat(f)
            if not stat.S_ISREG(first.st_mode) or first.st_size>limit:raise ValueError('type_or_size')
            data=bytearray()
            while len(data)<=limit:
                chunk=os.read(f,min(65536,limit+1-len(data)))
                if not chunk:break
                data.extend(chunk)
            if len(data)>limit or identity(first)!=identity(os.fstat(f)) or identity(first)!=identity(os.stat(Path(path).name,dir_fd=fd,follow_symlinks=False)):raise ValueError('file_changed')
            for parent,name,expected in ancestry:
                if identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=expected:raise ValueError('ancestor_changed')
            return bytes(data)
        finally:os.close(f)
    finally:
        os.close(fd)
        for parent,_,_ in ancestry:os.close(parent)


def acl_entries(raw):
    if len(raw)<4 or struct.unpack('<I',raw[:4])[0]!=2 or (len(raw)-4)%8:raise ValueError('acl_format')
    result=[]
    for off in range(4,len(raw),8):
        tag,perm,ident=struct.unpack('<HHI',raw[off:off+8])
        if tag not in (1,2,4,8,16,32) or perm>7:raise ValueError('acl_entry')
        result.append({'tag':tag,'permissions':perm,'id':ident})
    return result


def access_bits(s, uid, gids, acl):
    if not acl:
        return ((s.st_mode>>6)&7) if s.st_uid==uid else ((s.st_mode>>3)&7) if s.st_gid in gids else s.st_mode&7
    def single(tag):
        v=[x['permissions'] for x in acl if x['tag']==tag]
        if len(v)!=1:raise ValueError('acl_required_entry')
        return v[0]
    if s.st_uid==uid:return single(1)
    mask=single(16)
    named=[x['permissions'] for x in acl if x['tag']==2 and x['id']==uid]
    if len(named)>1:raise ValueError('acl_duplicate')
    if named:return named[0]&mask
    groups=([single(4)] if s.st_gid in gids else [])+[x['permissions'] for x in acl if x['tag']==8 and x['id'] in gids]
    if groups:
        value=0
        for g in groups:value|=g
        return value&mask
    return single(32)


def component(path, uid, gids):
    s=os.lstat(path);link=stat.S_ISLNK(s.st_mode)
    attrs={}
    if not link:
        for name in os.listxattr(path,follow_symlinks=False):
            if name in ('system.posix_acl_access','system.posix_acl_default'):
                attrs[name]=acl_entries(os.getxattr(path,name,follow_symlinks=False))
    bits=7 if link else access_bits(s,uid,gids,attrs.get('system.posix_acl_access',[]))
    r={'path':path,'identity':identity(s),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'acl':attrs,'symlink':link,'nlink':s.st_nlink,'chatops_write_bit':bool(bits&2),'chatops_search_bit':bool(bits&1)}
    if link:
        r['target']=os.readlink(path)
        r['link_sha256']=sha(os.fsencode(r['target']))
    # Directories have inode/ctime identity; content checksums apply only to regular files.
    return r


def components(path,uid,gids):
    out=[component('/',uid,gids)];p=Path('/')
    for name in Path(path).parts[1:]:
        p=p/name;out.append(component(str(p),uid,gids))
        if out[-1]['symlink']:break
    return out


def safe_symlink(path,expected,uid,gids):
    """Only the explicit original link gets an EXPECTED_SAFE result."""
    try:
        before=components(path,uid,gids)
        if before[-1]['path']!=path or not before[-1]['symlink']:return {'classification':'REVIEW_REQUIRED'}
        if before[-1]['uid']!=0:return {'classification':'UNSAFE_SYMLINK','components':before}
        canonical=os.path.realpath(path,strict=True)
        if canonical!=expected:return {'classification':'UNSAFE_SYMLINK','components':before}
        target=components(expected,uid,gids)
        if any(x['symlink'] or x['uid']!=0 or x['chatops_write_bit'] or int(x['mode'],8)&0o022 for x in before[:-1]+target):
            return {'classification':'UNSAFE_SYMLINK','components':before,'target_components':target}
        data=strict_read(expected)
        if before!=components(path,uid,gids) or target!=components(expected,uid,gids):raise ValueError('symlink_changed')
        return {'classification':'EXPECTED_SAFE_SYMLINK','components':before,'target_components':target,'target_sha256':sha(data),'canonical':canonical}
    except FileNotFoundError:return {'classification':'MISSING_TARGET'}
    except (OSError,ValueError):return {'classification':'REVIEW_REQUIRED'}


def bounded_command(args,timeout=20,limit=8_000_000):
    # Fixed read-only commands only. No shell or descendant execution requested.
    proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,cwd='/',start_new_session=True)
    streams=selectors.DefaultSelector();out=bytearray();err=bytearray();deadline=time.monotonic()+timeout
    try:
        for f,target in ((proc.stdout,out),(proc.stderr,err)):
            os.set_blocking(f.fileno(),False);streams.register(f,selectors.EVENT_READ,target)
        while streams.get_map():
            if time.monotonic()>=deadline:raise TimeoutError('command_timeout')
            for event,_ in streams.select(.05):
                b=os.read(event.fileobj.fileno(),65536)
                if not b:streams.unregister(event.fileobj)
                else:event.data.extend(b)
                if len(out)+len(err)>limit:raise ValueError('command_overflow')
        rc=proc.wait(timeout=max(.001,deadline-time.monotonic()))
        if rc or err:raise ValueError('command_failed')
        return bytes(out)
    finally:
        if proc.poll() is None:
            # The unreaped leader reserves its PID/PGID; only this query group.
            os.killpg(proc.pid,signal.SIGKILL)
            proc.wait(timeout=5)
        proc.stdout.close();proc.stderr.close();streams.close()


def journal_counts(data):
    counts={key:0 for key in ('build_system_doc.sh','check_system_doc.sh','trendwatch_post.sh')}
    records=0
    for line in data.splitlines():
        if not line:continue
        row=json.loads(line)
        if not isinstance(row,dict) or not isinstance(row.get('MESSAGE',''),str):raise ValueError('journal_schema')
        records+=1
        for key in counts:
            if key in row.get('MESSAGE',''):counts[key]+=1
    return {'records':records,'known_command_mentions':counts,'limitation':'Mentions do not prove successful completion; no messages retained.'}


class Collector:
    def __init__(self,store):
        self.store=store;self.nodes={};self.edges=[];self.categories=[];self.total=0
        u=pwd.getpwnam('chatops');self.uid=u.pw_uid;self.gids=set(os.getgrouplist('chatops',u.pw_gid));self.queue=[]
    def identities(self):
        return {'chatops_uid':self.uid,'chatops_gids':sorted(self.gids),
                'groups':[{'name':g.gr_name,'gid':g.gr_gid,'members':g.gr_mem} for g in grp.getgrall()],
                'users':[{'name':u.pw_name,'uid':u.pw_uid,'gid':u.pw_gid,'shell':u.pw_shell} for u in pwd.getpwall()]}
    def record(self,path,category):
        if path in self.nodes:return
        if len(self.nodes)>=MAX_FILES:raise ValueError('file_budget')
        row={'path':path,'category':category,'classification':'REVIEW_REQUIRED'};self.nodes[path]=row
        try:
            chain=components(path,self.uid,self.gids);row['components']=chain
            canonical=os.path.realpath(path,strict=True)
            # Resolve links as metadata; read only a separately checked canonical absolute file.
            final=components(canonical,self.uid,self.gids);row['canonical_components']=final
            if any(c['symlink'] for c in final):raise ValueError('canonical_link_race')
            row['canonical']=canonical
            row['chatops_writable_component']=any(c['chatops_write_bit'] for c in final)
            s=os.lstat(canonical)
            if stat.S_ISREG(s.st_mode):
                if s.st_size>2_000_000:raise ValueError('oversized_input')
                data=strict_read(canonical)
                if chain!=components(path,self.uid,self.gids) or final!=components(canonical,self.uid,self.gids):raise ValueError('path_changed')
                self.total+=len(data)
                if self.total>MAX_BYTES:raise ValueError('byte_budget')
                name='source-%05d.bin'%len(self.nodes);self.store.write(name,data);row.update(sha256=sha(data),private_source=name)
                # Lexical candidates only, no claim that absent literals close the graph.
                if b'\0' not in data:
                    candidates=set(re.findall(rb'(?<![A-Za-z0-9:/])/(?:etc|opt|usr|var|run|bin|sbin|lib|home|root)/[A-Za-z0-9_./+-]+',data))
                    for raw in sorted(candidates):
                        p=raw.decode('ascii');self.edges.append({'from':path,'to':p,'kind':'LITERAL_CANDIDATE','classification':'REVIEW_REQUIRED'})
                        if len(p)<512 and '..' not in Path(p).parts and p not in self.nodes and len(self.queue)<MAX_FILES:self.queue.append(p)
                    row['dynamic_resolution']='REVIEW_REQUIRED'
                    row['features']={label:bool(re.search(pattern,data,re.M)) for label,pattern in {
                        'source':rb'(^|[;\n])\s*(source|\.)\s',
                        'python_import':rb'(^|[;\n])\s*(from|import)\s',
                        'node_module':rb'\b(require|import)\s*[(]',
                        'relative_or_path_command':rb'(^|[;\n])\s*[a-zA-Z_][a-zA-Z0-9_-]*\s',
                        'glob_or_variable':rb'[$*?]',
                        'write':rb'>>?|write_text|write_bytes|writeFile|\btee\b',
                    }.items()}
        except FileNotFoundError:row['classification']='NOT_PRESENT'
        except (OSError,ValueError) as e:row['error_class']=type(e).__name__;row['classification']='REVIEW_REQUIRED'
    def tree(self,base,category):
        try:s=os.lstat(base)
        except FileNotFoundError:self.record(base,category);return
        self.record(base,category)
        if not stat.S_ISDIR(s.st_mode):return
        def failed(e):raise e
        for directory,dirs,files in os.walk(base,followlinks=False,onerror=failed):
            dirs.sort();files.sort()
            for name in dirs+files:
                # Package payload checksums/file lists are not executable maintainer hooks.
                if base=='/var/lib/dpkg/info' and not name.endswith(('.preinst','.postinst','.prerm','.postrm','.config','.triggers')):continue
                self.record(os.path.join(directory,name),category)
    def category(self,name,roots):
        for root in roots:self.tree(root,name)
        return {'classification':'REVIEW_REQUIRED','roots':list(roots),'node_count':len(self.nodes)}
    def units(self):
        listed=bounded_command(['/usr/bin/systemctl','list-unit-files','--no-pager','--no-legend'])
        active=bounded_command(['/usr/bin/systemctl','list-units','--all','--plain','--no-pager','--no-legend'])
        self.store.write('unit-files.bin',listed);self.store.write('loaded-units.bin',active)
        units=set();public=[]
        for line in (listed+b'\n'+active).decode().splitlines():
            words=line.split()
            if words and re.fullmatch(r'[A-Za-z0-9_.@:\\+-]+\.(?:service|timer|path|socket|mount|automount|scope|target)',words[0]):units.add(words[0])
        for n,unit in enumerate(sorted(units)):
            try:
                data=bounded_command(['/usr/bin/systemctl','show',unit,'--no-pager','--property='+','.join(UNIT_PROPS)])
            except (OSError,ValueError,TimeoutError) as exc:
                self.edges.append({'from':unit,'kind':'SYSTEMD_QUERY_FAILED','classification':'REVIEW_REQUIRED','error_class':type(exc).__name__})
                continue
            name='unit-%05d.bin'%n;self.store.write(name,data)
            item={'unit':unit,'source_sha256':sha(data),'classification':'REVIEW_REQUIRED','properties':{},'executables':[]}
            for line in data.decode().splitlines():
                key,sep,value=line.partition('=')
                if not sep:continue
                if key.startswith('Exec'):
                    item['properties'][key+'_sha256']=sha(value.encode())
                    for path in re.findall(r'path=(/[A-Za-z0-9_./+-]+)',value):
                        item['executables'].append(path);self.record(path,'effective-executable')
                elif key in UNIT_PROPS:item['properties'][key]=value
            public.append(item)
            self.edges.append({'from':unit,'to':name,'kind':'SYSTEMD_EFFECTIVE_PROPERTIES','classification':'REVIEW_REQUIRED'})
            for line in data.decode().splitlines():
                if line.startswith(('FragmentPath=','SourcePath=')):
                    p=line.split('=',1)[1]
                    if p.startswith('/'):self.record(p,'effective-unit')
        return {'unit_count':len(units),'classification':'REVIEW_REQUIRED','units':public}
    def docker(self):
        ids=bounded_command(['/usr/bin/docker','ps','-aq','--no-trunc']).decode().split()
        if any(not re.fullmatch('[a-f0-9]{64}',x) for x in ids):raise ValueError('container_id')
        out=[]
        for ident in ids:
            data=json.loads(bounded_command(['/usr/bin/docker','inspect',ident]))[0]
            h=data['HostConfig'];c=data['Config']
            row={'id':ident,'name':data['Name'],'image':data['Image'],'user':c.get('User'),'privileged':h.get('Privileged'),'cap_add':h.get('CapAdd'),'pid_mode':h.get('PidMode'),'userns_mode':h.get('UsernsMode'),'security_opt':h.get('SecurityOpt'),'mounts':data.get('Mounts'),'classification':'REVIEW_REQUIRED'}
            # Arguments/Env can contain secrets; archive only the allowlisted row.
            out.append(row)
            for mount in row['mounts']:
                p=mount.get('Source','')
                if p.startswith('/'):self.record(p,'docker-host-mount')
        self.store.write('docker-security.json',json.dumps(out,sort_keys=True).encode())
        return {'count':len(out),'classification':'REVIEW_REQUIRED','observations':out}
    def processes(self):
        out=[]
        for path in sorted(Path('/proc').iterdir()):
            if not path.name.isdecimal():continue
            try:
                fields=dict(x.split(':',1) for x in (path/'status').read_text().splitlines() if ':' in x)
                uid=int(fields['Uid'].split()[1]);groups=[int(x) for x in fields['Groups'].split()];caps=int(fields['CapEff'],16)
                if uid!=0 and not caps and grp.getgrnam('docker').gr_gid not in groups:continue
                start=(path/'stat').read_text().rsplit(')',1)[1].split()[19]
                r={'pid':int(path.name),'start_ticks':start,'uid':uid,'groups':groups,'cap_eff':caps,'classification':'REVIEW_REQUIRED'}
                for label in ('exe','cwd','root'):
                    try:r[label]=os.readlink(path/label)
                    except OSError:r[label]='UNREADABLE'
                # Only descriptor metadata, never file payloads/cmdline/environment.
                r['writable_descriptors']=[]
                descriptors=list((path/'fd').iterdir());r['descriptor_count']=len(descriptors);r['descriptor_truncated']=len(descriptors)>4096
                for fdpath in descriptors[:4096]:
                    try:
                        target=os.readlink(fdpath)
                        flags=next(int(line.split()[1],8) for line in (path/'fdinfo'/fdpath.name).read_text().splitlines() if line.startswith('flags:'))
                        if flags & os.O_ACCMODE not in (os.O_WRONLY,os.O_RDWR) or not target.startswith('/'):continue
                        entry={'fd':fdpath.name,'target':target,'classification':'REVIEW_REQUIRED'}
                        try:entry['components']=components(target,self.uid,self.gids)
                        except (OSError,ValueError) as exc:entry['error_class']=type(exc).__name__
                        r['writable_descriptors'].append(entry)
                    except (OSError,ValueError,StopIteration):r['descriptor_race_or_error']=True
                cg=(path/'cgroup').read_bytes();r['cgroup_sha256']=sha(cg)
                r['units']=re.findall(r'[A-Za-z0-9_.@-]+\.service',cg.decode('ascii','replace'))
                if start!=(path/'stat').read_text().rsplit(')',1)[1].split()[19]:raise ValueError('pid_changed')
                out.append(r)
            except (OSError,ValueError,KeyError):out.append({'pid':int(path.name),'classification':'REVIEW_REQUIRED','error':'RACE_OR_ACCESS'})
        self.store.write('processes.json',json.dumps(out,sort_keys=True).encode())
        return {'count':len(out),'classification':'REVIEW_REQUIRED','observations':out}
    def graph(self):
        return {'schema':1,'status':'INCOMPLETE','activation_ready':False,'nodes':list(self.nodes.values()),'edges':self.edges,'limitations':['Lexical candidates do not resolve shell/Python/Node dynamic execution or imports.','Docker privilege remains an independent host-control edge.','All entrypoint semantics require review; no node is automatically SAFE.','Missing evidence is never permission.']}


def main():
    if len(sys.argv)!=1 or os.getuid()!=0 or os.geteuid()!=0:return 3
    source=globals().get('_VERIFIED_SOURCE_SHA256','')
    if not re.fullmatch('[a-f0-9]{64}',source):return 3
    os.environ.clear();os.environ.update(ENV);os.umask(0o077)
    try:
        protected_directory(BASE,create=True)
        directory=BASE/('run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(8))
        directory.mkdir(mode=0o700);protected_directory(directory);store=Store(directory)
    except Exception:return 3
    def interrupted(*_):raise KeyboardInterrupt()
    signal.signal(signal.SIGINT,interrupted);signal.signal(signal.SIGTERM,interrupted)
    completed=False;c=None;collection_error=None
    try:
        c=Collector(store)
        store.section('identities',c.identities)
        for name,roots in ROOTS.items():store.section(name,lambda n=name,r=roots:c.category(n,r))
        store.section('systemd-effective',c.units)
        store.section('docker-security',c.docker)
        store.section('process-identities',c.processes)
        end=datetime.datetime.now(datetime.timezone.utc)
        for day in range(7):
            until=end-datetime.timedelta(days=day);since=until-datetime.timedelta(days=1)
            args=['/usr/bin/journalctl','--no-pager','-o','json','-u','cron.service','--since',since.isoformat(),'--until',until.isoformat()]
            store.section('cron-journal-'+str(day),lambda a=args:journal_counts(bounded_command(a)))
        store.section('expected-symlink',lambda:safe_symlink('/etc/cron.d/system_summary','/etc/cron.daily/system_summary',c.uid,c.gids))
        # Bounded candidate collection; every unresolved queue remains in graph.
        for path in list(dict.fromkeys(c.queue)):
            if len(c.nodes)>=MAX_FILES:break
            c.record(path,'transitive-candidate')
        completed=True
    except BaseException as exc:collection_error=type(exc).__name__
    finally:
        if c:store.write('graph.json',json.dumps(c.graph(),sort_keys=True).encode())
        manifest={'version':'5.1.0','source_sha256':source,'status':'INCOMPLETE','collection_finished':completed,'collection_error_class':collection_error,'activation_ready':False,'file_hashes':store.hashes.copy(),'sections':store.entries}
        payload=json.dumps(manifest,sort_keys=True).encode();store.write('manifest.json',payload)
        # No raw sources, commandlines, env values or full graph exported to terminal.
        print(json.dumps({'directory':str(directory),'manifest_sha256':sha(payload),'status':'INCOMPLETE','collection_finished':completed,'collection_error_class':collection_error,'sections':store.entries,'graph_nodes':len(c.nodes) if c else 0,'graph':c.graph() if c else None}))
    return 2

if __name__=='__main__':raise SystemExit(main())
