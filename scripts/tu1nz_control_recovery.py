"""Native, create-only Control source recovery. No S12 or service operation.

Existing files are never chmod'ed, renamed, overwritten or removed. A signed
grant is bound to this non-dumpable process/session and held input digest.
Only the separately spent trusted-client slot can sign it. A lost process or
reply cannot mint a replacement session grant; host pathname absence is NOT
an unspent-slot proof. Privileged kernel administrators remain explicit TCB.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import subprocess
import time

import tu1nz_control_recovery_contract as c
from tu1nz_s8_historical_kernel import ReadLeases, ext4
from tu1nz_s8_admission_channel import protect_process
from tu1nz_s8_historical_objects import ObjectStore, object_read, resolve_head, config_safe

GETFLAGS=0x80086601
SETFLAGS=0x40086602
IMMUTABLE=0x10
PHYSICAL_LAYOUT_FLAGS=0x1000|0x80000  # ext4 htree/extent layout, not protection flags
WRITE_SIGNAL=signal.SIGRTMIN+6 if hasattr(signal,'SIGRTMIN') else None


class NamespaceFence:
    """Watch before exclusive creation; never accept move/delete/name reuse.

    Our finite construction only creates and changes attributes of NEW
    objects. A move/delete/overflow invalidates it, even if names are restored.
    Check after opening each newly created directory and BEFORE changing its
    metadata, so a replacement cannot be adopted/normalised as our object.
    """
    def __init__(self,parent):
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.events=self.libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
        c.require(self.events>=0,'OUTPUT_WATCH_RED')
        self.failed=False;self.chain=ancestors(parent);self.parent=parent
        try:
            for path in self.chain:self.watch(path)
        except BaseException:
            os.close(self.events);self.events=None;raise
    def watch(self,path):
        c.require(self.libc.inotify_add_watch(self.events,os.fsencode(path),0x00000ec0)>=0,
                  'OUTPUT_WATCH_RED')
    def check(self):
        c.require(not self.failed and self.events is not None,'OUTPUT_FENCE_LOST')
        try:
            try:raw=os.read(self.events,65536)
            except BlockingIOError:raw=b''
            c.require(not raw and ancestors(self.parent)==self.chain,'OUTPUT_NAMESPACE_CHANGED')
        except BaseException:self.failed=True;raise
    def close(self,result):
        if self.events is not None:
            close_all([self.events],result);self.events=None


def flags(fd):
    return struct.unpack('I',fcntl.ioctl(fd,GETFLAGS,struct.pack('I',0)))[0]


def set_flags(fd,value):
    fcntl.ioctl(fd,SETFLAGS,struct.pack('I',value))
    c.require(flags(fd)==value,'FLAGS_RED')


def metadata(fd, path=None):
    st=os.fstat(fd) if fd is not None else path.lstat()
    names=os.listxattr(fd if fd is not None else path,**({} if fd is not None else {'follow_symlinks':False}))
    attrs={name:base64.b64encode(os.getxattr(fd if fd is not None else path,name,
        **({} if fd is not None else {'follow_symlinks':False}))).decode() for name in sorted(names)}
    fsx=None
    if fd is not None:
        fields=struct.unpack('=5I8s',fcntl.ioctl(fd,0x801c581f,bytes(28)))
        fsx=dict(xflags=fields[0],extsize=fields[1],nextents=fields[2],projid=fields[3],cowextsize=fields[4])
        # Project-quota IDs/hints are not xattrs or SETFLAGS. No silently
        # incomplete metadata restore: this version supports ONLY zero IDs/
        # hints. Preserve the raw observation; a future nonzero profile needs
        # its own contract, not normalisation or a historical drift assertion.
        c.require(fsx['projid']==0 and fsx['extsize']==0 and fsx['cowextsize']==0,
                  'UNSUPPORTED_PROJECT_OR_ALLOCATION_PROFILE')
    return dict(device=st.st_dev,inode=st.st_ino,type=stat.S_IFMT(st.st_mode),mode=stat.S_IMODE(st.st_mode),
        uid=st.st_uid,gid=st.st_gid,nlink=st.st_nlink,size=st.st_size,mtime_ns=st.st_mtime_ns,
        ctime_ns=st.st_ctime_ns,attrs=attrs,flags=flags(fd) if fd is not None else None,fsx=fsx)


def existing(path):
    return os.path.lexists(path)


def identity(path):
    st=path.lstat();c.require(stat.S_ISDIR(st.st_mode) and not path.is_symlink(),'ANCESTOR_RED')
    return st.st_dev,st.st_ino


def ancestors(path):
    paths=[Path('/'),*reversed(path.parents[:-1]),path]
    return {str(p):list(identity(p)) for p in paths}


def close_all(descriptors, result):
    for fd in reversed(descriptors):
        try:os.close(fd)
        except BaseException as e:result['cleanup'].append(c.failure(e))


def restore_profile(fd, record):
    """Only on an exclusively created owned restore-test inode, never historical."""
    os.fchown(fd,record['uid'],record['gid']);os.fchmod(fd,record['mode'])
    for name in os.listxattr(fd):
        if name not in record['attrs']:os.removexattr(fd,name)
    for name,data in record['attrs'].items():os.setxattr(fd,name,base64.b64decode(data,validate=True))
    os.utime(fd,ns=(record['mtime_ns'],record['mtime_ns']))
    # Inodes, ctime, allocation, extent/htree layout cannot be restored by a
    # logical copy. Preserve raw observations; require all other flags exactly.
    set_flags(fd,(flags(fd)&PHYSICAL_LAYOUT_FLAGS)|(record['flags']&~PHYSICAL_LAYOUT_FLAGS))


class Snapshot:
    """Whole live Control tree, index and opaque extras; held inode/read leases.

    Unknown write-capable DAC/ACL is not trusted: actual kernel exclusion plus
    all directory/ancestor watches is required. No original Git subprocess.
    External hardlinks, mounts, special files and unstable inventory deny.
    """
    def __init__(self,root,*,reserve=64):
        self.root=Path(root);self.nodes={};self.fds={};self.failed=False;self.lease_fds={}
        self.leases=None;self.old_limit=resource.getrlimit(resource.RLIMIT_NOFILE)
        self.original_fds=set(os.listdir('/proc/self/fd'))
        self.chain=ancestors(self.root);self.bytes=0
        try:
            census=[];pending=[self.root];seen=set();device=self.root.lstat().st_dev
            while pending:
                path=pending.pop();st=path.lstat()
                c.require(st.st_dev==device and len(census)<c.MAX_NODES,'INVENTORY_BOUND_OR_MOUNT')
                census.append(path)
                if stat.S_ISDIR(st.st_mode):
                    c.require((st.st_dev,st.st_ino) not in seen,'DIRECTORY_ALIAS');seen.add((st.st_dev,st.st_ino))
                    pending.extend(sorted(path.iterdir(),reverse=True))
                elif stat.S_ISREG(st.st_mode):self.bytes+=st.st_size
                else:c.require(stat.S_ISLNK(st.st_mode),'SPECIAL_OBJECT')
            required=4*len(census)+len(self.chain)+len(self.original_fds)+reserve
            c.require(required<=self.old_limit[1] and self.bytes<=c.MAX_BYTES,'CAPACITY_RED')
            if required>self.old_limit[0]:resource.setrlimit(resource.RLIMIT_NOFILE,(required,self.old_limit[1]))
            self.leases=ReadLeases()
            self.descriptors=[]
            for p in self.chain:
                fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                self.descriptors.append(fd)
                c.require(self.leases.libc.inotify_add_watch(self.leases.events,
                    os.fsencode('/proc/self/fd/'+str(fd)),0x00000fce)>=0,'WATCH_RED')
            links={}
            for path in sorted(census,key=lambda p:(len(p.parts),str(p))):
                name=str(path.relative_to(self.root));st=path.lstat()
                if stat.S_ISLNK(st.st_mode):
                    record=metadata(None,path);record['link']=os.readlink(path)
                else:
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
                    self.descriptors.append(fd);self.fds[name]=fd;ext4(fd)
                    if stat.S_ISREG(st.st_mode):
                        key=(st.st_dev,st.st_ino)
                        if key not in links:self.leases.acquire(fd);self.lease_fds[key]=fd
                        links.setdefault(key,[]).append(name)
                    else:
                        c.require(self.leases.libc.inotify_add_watch(self.leases.events,
                            os.fsencode('/proc/self/fd/'+str(fd)),0x00000fce)>=0,'WATCH_RED')
                    record=metadata(fd)
                    c.require((record['device'],record['inode'])==(st.st_dev,st.st_ino),'INPUT_CHANGED')
                self.nodes[name]=record
            for names in links.values():
                c.require(all(self.nodes[n]['nlink']==len(names) for n in names),'EXTERNAL_HARDLINK')
                for name in names:self.nodes[name]['hardlink_group']=min(names)
            self.check()
        except BaseException as error:
            self.failed=True
            result={'cleanup':[]};self.close(result)
            error._control_cleanup=result['cleanup']
            raise

    def check(self):
        c.require(not self.failed and self.leases is not None,'PROTECTION_LOST')
        try:
            self.leases.check();c.require(ancestors(self.root)==self.chain,'ANCESTOR_CHANGED')
            for name,expected in self.nodes.items():
                path=self.root/name;fd=self.fds.get(name)
                observed=metadata(fd,path)
                if expected['type']==stat.S_IFLNK:observed['link']=os.readlink(path)
                for key in ('hardlink_group','sha256'):observed.pop(key,None)
                want={k:v for k,v in expected.items() if k not in ('hardlink_group','sha256')}
                c.require(observed==want,'INPUT_CHANGED')
                st=path.lstat();c.require((st.st_dev,st.st_ino)==(expected['device'],expected['inode']),'INPUT_CHANGED')
            self.leases.check()
        except BaseException:self.failed=True;raise

    def data(self,name):
        self.leases.remaining();record=self.nodes[name];c.require(record['type']==stat.S_IFREG,'INPUT_NOT_REGULAR')
        self.leases._check_descriptor(self.lease_fds[(record['device'],record['inode'])])
        fd=self.fds[name];raw=bytearray();size=record['size']
        for offset in range(0,size,1024*1024):
            self.leases.remaining();part=os.pread(fd,min(1024*1024,size-offset),offset)
            c.require(len(part)==min(1024*1024,size-offset),'INPUT_SHORT_READ');raw.extend(part)
        self.leases.remaining();self.leases._check_descriptor(self.lease_fds[(record['device'],record['inode'])])
        c.require(metadata(fd)=={k:v for k,v in record.items() if k not in ('hardlink_group','sha256')},'INPUT_CHANGED')
        self.nodes[name]['sha256']=c.digest(raw)
        return bytes(raw)

    def close(self,result):
        self.failed=True
        if self.leases is not None:
            try:self.leases.close()
            except BaseException as e:result['cleanup'].append(c.failure(e))
            self.leases=None
        close_all(getattr(self,'descriptors',[]),result);self.descriptors=[]
        try:resource.setrlimit(resource.RLIMIT_NOFILE,self.old_limit)
        except BaseException as e:result['cleanup'].append(c.failure(e))
        result['fd_limit_restored']=resource.getrlimit(resource.RLIMIT_NOFILE)==self.old_limit
        result['fd_baseline_restored']=set(os.listdir('/proc/self/fd'))==self.original_fds


class GitView:
    def __init__(self,snapshot):
        self.snapshot=snapshot;self.root=snapshot.root/'.git.s12-1-recovery';self.leases=snapshot.leases
        self.rows=[(snapshot.root/name,record) for name,record in snapshot.nodes.items()
                   if name.startswith('.git.s12-1-recovery/')]
        self.failed=False
    def check(self):self.snapshot.check()
    def has(self,leaf):return '.git.s12-1-recovery/'+leaf in self.snapshot.nodes
    def input_descriptor(self,leaf):
        self.leases.remaining();name='.git.s12-1-recovery/'+leaf
        c.require(name in self.snapshot.fds and self.snapshot.nodes[name]['type']==stat.S_IFREG,'GIT_INPUT_MISSING')
        record=self.snapshot.nodes[name]
        self.leases._check_descriptor(self.snapshot.lease_fds[(record['device'],record['inode'])])
        return self.snapshot.fds[name],self.snapshot.nodes[name]['size']
    def read(self,leaf):return self.snapshot.data('.git.s12-1-recovery/'+leaf)


def source_binding(snapshot,layout):
    view=GitView(snapshot);config_safe(view)
    c.require(resolve_head(view)==layout.old_commit,'HISTORICAL_HEAD_RED')
    index=c.index_entries(view.read('index'));c.require(index,'INDEX_INCOMPLETE');deltas=0
    with ObjectStore(view) as objects:
        kind,raw=object_read(objects,layout.old_commit)
        c.require(kind==b'commit' and raw.startswith(b'tree '+layout.old_tree.encode()+b'\n'),'HISTORICAL_TREE_RED')
        checked={}
        def tree(object_id,active):
            c.require(object_id not in active and len(active)<64 and len(checked)<c.MAX_NODES,
                      'HISTORICAL_TREE_BOUND_OR_CYCLE')
            if object_id in checked:
                c.require(checked[object_id]=='tree','HISTORICAL_TREE_RED');return
            kind,raw=object_read(objects,object_id);c.require(kind==b'tree','HISTORICAL_TREE_RED')
            for mode,_,child in c.tree_entries(raw,historical=True):
                if mode=='40000':tree(child,active|{object_id})
                else:
                    c.require(checked.get(child,'blob')=='blob','HISTORICAL_TREE_RED')
                    if child not in checked:
                        c.require(len(checked)<c.MAX_NODES,'HISTORICAL_TREE_BOUND_OR_CYCLE')
                        kind,_=object_read(objects,child);c.require(kind==b'blob','HISTORICAL_TREE_RED')
                        checked[child]='blob'
            checked[object_id]='tree'
        tree(layout.old_tree,set())
        for path,entry in index.items():
            c.require(path in snapshot.nodes,'WORKTREE_INCOMPLETE')
            kind,_=object_read(objects,entry['oid']);c.require(kind==b'blob','INDEX_OBJECT_RED')
            record=snapshot.nodes[path]
            if entry['mode']==0o120000:
                c.require(record['type']==stat.S_IFLNK,'WORKTREE_TYPE_RED');raw=record['link'].encode()
            else:
                c.require(record['type']==stat.S_IFREG,'WORKTREE_TYPE_RED');raw=snapshot.data(path)
            deltas+=c.oid('blob',raw)!=entry['oid']
    sections={};section=None
    for line in view.read('config').decode().splitlines():
        line=line.strip()
        if line.startswith('['):section=line
        elif section=='[remote "origin"]' and '=' in line:
            key,value=map(str.strip,line.split('=',1))
            if key.lower()=='url':sections['origin']=value
    origin=sections.get('origin','').removesuffix('.git')
    if origin.startswith('git@github.com:'):origin='https://github.com/'+origin[len('git@github.com:'):]
    c.require(origin in c.ROOT_ORIGINS,'HISTORICAL_ORIGIN_UNREGISTERED')
    snapshot.check()
    return {'origin':origin,'commit':layout.old_commit,'tree':layout.old_tree,
            'index_sha256':c.digest(view.read('index')),'index_entries':len(index),
            'validated_head_tree_objects':len(checked),
            'preserved_worktree_index_deltas':deltas}


class OwnedTree:
    """O_EXCL-only construction, held write leases; no pathname replacement.

    Root/namespace writers can inject objects: exclusive creation then fails,
    or final exact identity/inventory comparison fails. Nothing foreign is
    unlinked/overwritten. A sealed inode cannot be exchanged by capless writers.
    """
    def __init__(self,root,fence=None):
        self.root=Path(root);self.records={};self.descriptors=[];self.fence=fence
        self.root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        self.descriptors.append(self.root_fd);self.records['.']=metadata(self.root_fd)
        if fence is not None:
            try:fence.watch('/proc/self/fd/'+str(self.root_fd));fence.check()
            except BaseException as error:
                result={'cleanup':[]};close_all([self.root_fd],result)
                error._control_cleanup=result['cleanup'];self.descriptors=[];raise

    def refresh(self,name):
        record=self.records[name];fd=self.root_fd if name=='.' else record['fd']
        self.records[name]={**record,**metadata(fd)}

    def directory(self,name):
        if name in ('','.'):return self.root_fd
        if name in self.records:return self.records[name]['fd']
        parent,_,leaf=name.rpartition('/');parent_fd=self.directory(parent)
        os.mkdir(leaf,0o700,dir_fd=parent_fd)
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
        self.descriptors.append(fd)
        if self.fence is not None:
            self.fence.watch('/proc/self/fd/'+str(fd));self.fence.check()
        os.fchown(fd,0,1001);os.fchmod(fd,0o750)
        record=metadata(fd);record['fd']=fd;self.records[name]=record
        os.fsync(parent_fd);return fd

    def file(self,name,raw,mode=0o600,profile=None):
        parent,_,leaf=name.rpartition('/');parent_fd=self.directory(parent)
        # Fill an anonymous inode before publication: a capless namespace
        # writer cannot hardlink a partially written named output into history.
        fd=os.open('.',os.O_TMPFILE|os.O_RDWR|os.O_CLOEXEC,0o600,dir_fd=parent_fd)
        self.descriptors.append(fd)
        c.require(WRITE_SIGNAL is not None and WRITE_SIGNAL not in signal.sigpending(),'WRITE_SIGNAL_RED')
        c.require(signal.getsignal(WRITE_SIGNAL)==signal.SIG_DFL,'WRITE_SIGNAL_COLLISION')
        signal.pthread_sigmask(signal.SIG_BLOCK,{WRITE_SIGNAL})
        fcntl.fcntl(fd,fcntl.F_SETSIG,WRITE_SIGNAL)
        fcntl.fcntl(fd,15,struct.pack('ii',0,__import__('threading').get_native_id()))
        fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_WRLCK)
        offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:offset+1024*1024])
        os.fsync(fd)
        if profile is None:
            os.fchown(fd,0,1001);os.fchmod(fd,mode)
            for attr in os.listxattr(fd):os.removexattr(fd,attr)
        else:restore_profile(fd,profile)
        c.require(WRITE_SIGNAL not in signal.sigpending() and
                  fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_WRLCK,'OWNED_WRITE_LEASE_LOST')
        c.require(os.pread(fd,len(raw),0)==raw,'OUTPUT_READBACK_RED')
        c.require(os.fstat(fd).st_nlink==0,'OUTPUT_ALIAS_RED')
        libc=ctypes.CDLL(None,use_errno=True)
        libc.linkat.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_int]
        libc.linkat.restype=ctypes.c_int
        if libc.linkat(fd,b'',parent_fd,os.fsencode(leaf),0x1000)!=0:
            raise OSError(ctypes.get_errno(),'CONTROL_RECOVERY_EXCLUSIVE_LINK_RED')
        c.require(os.fstat(fd).st_nlink==1,'OUTPUT_ALIAS_RED')
        if profile is None:set_flags(fd,flags(fd)|IMMUTABLE)
        c.require(os.fstat(fd).st_nlink==1,'OUTPUT_ALIAS_RED')
        st=os.stat(leaf,dir_fd=parent_fd,follow_symlinks=False)
        c.require((st.st_dev,st.st_ino)==(os.fstat(fd).st_dev,os.fstat(fd).st_ino),'OUTPUT_CHANGED')
        self.records[name]={**metadata(fd),'fd':fd,'sha256':c.digest(raw)}
        os.fsync(parent_fd)
        fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
        # Immutable constructed files are stable; restore-test profiles remain
        # protected by the surrounding private transaction, checked again below.
        return fd

    def check(self):
        if self.fence is not None:self.fence.check()
        wanted={name for name in self.records if name!='.'};actual=set()
        pending=[self.root]
        while pending:
            path=pending.pop()
            for child in path.iterdir():
                name=str(child.relative_to(self.root));actual.add(name)
                record=self.records.get(name);c.require(record is not None,'FOREIGN_OUTPUT')
                st=child.lstat();c.require((st.st_dev,st.st_ino)==(record['device'],record['inode']),'OUTPUT_CHANGED')
                if stat.S_ISDIR(st.st_mode):pending.append(child)
                elif stat.S_ISREG(st.st_mode):
                    c.require(c.digest(os.pread(record['fd'],record['size'],0))==record['sha256'],'OUTPUT_CHANGED')
                else:c.require(record.get('type')==stat.S_IFLNK and os.readlink(child)==record['link'],'FOREIGN_OUTPUT')
        c.require(actual==wanted,'OUTPUT_INCOMPLETE')
        for name,record in self.records.items():
            if record['type']!=stat.S_IFLNK:
                fd=self.root_fd if name=='.' else record['fd']
                # Directory timestamps/nlinks evolve through our exclusive
                # child creation. Security metadata and identity never do.
                fields=('device','inode','type','mode','uid','gid','attrs')
                observed=metadata(fd)
                c.require(all(observed[k]==record[k] for k in fields),'OUTPUT_METADATA_CHANGED')
                # New ext4 directories acquire htree/extent allocation during
                # our exclusive construction. Protection flags must NOT drift.
                mask=PHYSICAL_LAYOUT_FLAGS if record['type']==stat.S_IFDIR else 0
                c.require((observed['flags']&~mask)==(record['flags']&~mask),'OUTPUT_METADATA_CHANGED')
        if self.fence is not None:self.fence.check()

    def seal(self,*,directory_mode=0o550,gid=1001):
        self.check()
        for name,record in sorted(self.records.items(),key=lambda item:len(Path(item[0]).parts),reverse=True):
            fd=self.root_fd if name=='.' else record['fd']
            if record['type']==stat.S_IFDIR:
                os.fchown(fd,0,gid);os.fchmod(fd,directory_mode)
                for attr in os.listxattr(fd):os.removexattr(fd,attr)
                set_flags(fd,flags(fd)|IMMUTABLE);os.fsync(fd)
                self.refresh(name)
        self.check()

    def close(self,result):close_all(self.descriptors,result);self.descriptors=[]


class Session:
    """Process-local one-use latch; signed grants cannot survive process death."""
    def __init__(self,layout,capsule):
        native_prerequisites(layout);protect_process()
        self.used=False;self.layout=layout;self.capsule=capsule;self.snapshot=None
        self.fd_baseline=fd_state()
        self.nonce=os.urandom(32).hex();self.pid=os.getpid()
        self.body={'schema':c.SCHEMA+'_GRANT','slot':c.SLOT,'host':layout.host,
            'boot_sha256':c.digest(Path('/proc/sys/kernel/random/boot_id').read_bytes()),
            'pid':self.pid,'nonce':self.nonce,'target':capsule.target,'capsule_sha256':capsule.sha256,
            'ancestors':ancestors(layout.historical),
            'anchor_ancestors':ancestors(layout.anchor.parent),
            'historical_root':list(layout.pin),'historical_guard':list(layout.guard_pin),
            'quarantined_git':list(layout.quarantine_pin)}

    def consume(self,grant,public_key):
        c.require(not self.used,'SESSION_ALREADY_CONSUMED');self.used=True
        c.require(os.getpid()==self.pid and grant['body']==self.body,'GRANT_BINDING_RED')
        verify_signature(public_key,c.canonical(grant['body']),base64.b64decode(grant['signature'],validate=True))
        c.require(ancestors(self.layout.historical)==self.body['ancestors'],'ANCESTOR_CHANGED')
        c.require(ancestors(self.layout.anchor.parent)==self.body['anchor_ancestors'],'ANCHOR_ANCESTOR_CHANGED')


def verify_signature(key,body,signature):
    """All verifier inputs sealed memfds; no mutable paths/helper configuration."""
    descriptors=[]
    try:
        for name,raw in (('public',key),('body',body),('signature',signature)):
            fd=os.memfd_create('control-recovery-'+name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            descriptors.append(fd);os.write(fd,raw);os.lseek(fd,0,os.SEEK_SET)
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        pub,data,sig=descriptors
        result=subprocess.run(['/usr/bin/openssl','pkeyutl','-verify','-pubin','-inkey','/proc/self/fd/'+str(pub),
            '-rawin','-in','/proc/self/fd/'+str(data),'-sigfile','/proc/self/fd/'+str(sig)],
            pass_fds=tuple(descriptors),capture_output=True,timeout=5,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
        c.require(result.returncode==0,'GRANT_SIGNATURE_RED')
    finally:
        result={'cleanup':[]};close_all(descriptors,result)
        c.require(not result['cleanup'],'SIGNATURE_CLEANUP_RED')


def fd_state():
    result={}
    for name in os.listdir('/proc/self/fd'):
        try:
            fd=int(name);st=os.fstat(fd)
            result[name]=(st.st_dev,st.st_ino,st.st_mode,fcntl.fcntl(fd,fcntl.F_GETFD))
        except OSError as error:
            if error.errno!=9:raise
    return result


def preserved_state(layout):
    records={}
    for path in layout.preserved:
        if not existing(path):records[str(path)]={'absent':True};continue
        st=path.lstat();c.require(not path.is_symlink(),'PRESERVED_SYMLINK')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            records[str(path)]=metadata(fd)
            if stat.S_ISREG(st.st_mode):
                c.require(st.st_size<=c.MAX_OBJECT,'PRESERVED_BOUND')
                records[str(path)]['sha256']=c.digest(os.pread(fd,st.st_size,0))
        finally:os.close(fd)
    return records


def native_prerequisites(layout):
    c.require(os.uname().sysname=='Linux' and os.geteuid()==0,'NATIVE_ROOT_REQUIRED')
    cap=int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                 if line.startswith('CapEff:')),16)
    c.require(all(cap&(1<<bit) for bit in (0,1,2,3,9,28)),'KERNEL_CAPABILITY_REQUIRED')
    c.require(c.digest(Path('/etc/machine-id').read_bytes())==layout.host,'HOST_BINDING_RED')
    c.require(identity(layout.historical)==layout.pin and identity(layout.historical/'.git')==layout.guard_pin
              and identity(layout.historical/'.git.s12-1-recovery')==layout.quarantine_pin,'R6_OBJECT_BINDING_RED')
    c.require(stat.S_IMODE((layout.historical/'.git').lstat().st_mode)==0,'GUARD_RED')
    c.require(Path('/proc/sys/fs/leases-enable').read_text().strip()=='1','KERNEL_LEASES_DISABLED')
    if layout.historical==c.HISTORICAL:
        for path,uid,gid,mode in ((layout.historical,0,1001,0o2550),
                (layout.historical/'.git',0,0,0),
                (layout.historical/'.git.s12-1-recovery',0,0,0o700)):
            st=path.lstat()
            c.require((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(uid,gid,mode)
                      and not os.listxattr(path),'R6_METADATA_BINDING_RED')
    c.require(not existing(layout.anchor),'EXISTING_ANCHOR_NO_TAKEOVER_OR_REPLAY')


class PreservedFence:
    """Fixed preservation objects only, never another general history reader."""
    def __init__(self,layout,leases):
        self.layout=layout;self.leases=leases;self.fds=[];self.rows={};self.absent=[];self.application=None
    def open(self):
        layout,leases=self.layout,self.leases
        parents=set()
        for path in layout.preserved:
            parents.update(ancestors(path.parent))
            if not existing(path):self.absent.append(path);continue
            c.require(not path.is_symlink(),'PRESERVED_SYMLINK')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);self.fds.append(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):leases.acquire(fd)
            else:c.require(leases.libc.inotify_add_watch(leases.events,
                os.fsencode('/proc/self/fd/'+str(fd)),0x00000fce)>=0,'WATCH_RED')
            self.rows[path]=(fd,metadata(fd))
        for path in parents:
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(fd)
            c.require(leases.libc.inotify_add_watch(leases.events,
                os.fsencode('/proc/self/fd/'+str(fd)),0x00000fce)>=0,'WATCH_RED')
        # A preservation census, NOT another historical HEAD/Tree reader or
        # Application backup/recovery. All bytes remain only in original files;
        # hashes never enter the public release or public result.
        self.application=Snapshot(layout.preserved[0])
        for name,record in self.application.nodes.items():
            if record['type']==stat.S_IFREG:self.application.data(name)
        self.check()

    def check(self):
        self.leases.check()
        if self.application is not None:self.application.check()
        for path,(fd,expected) in self.rows.items():
            c.require(metadata(fd)==expected and (path.lstat().st_dev,path.lstat().st_ino)==
                      (expected['device'],expected['inode']),'PRESERVED_CHANGED')
            if expected['type']==stat.S_IFREG:
                c.require(expected['size']<=c.MAX_OBJECT,'PRESERVED_BOUND')
                raw=os.pread(fd,expected['size'],0)
                c.require(len(raw)==expected['size'],'PRESERVED_SHORT_READ')
                pinned=(self.layout.evidence_hashes or {}).get(str(path))
                if pinned is not None:c.require(c.digest(raw)==pinned,'PRESERVED_EVIDENCE_RED')
        c.require(not any(existing(p) for p in self.absent),'PRESERVED_MARKER_CHANGED')
        self.leases.check()

    def close(self,result):
        self.close_application(result)
        close_all(self.fds,result);self.fds=[]

    def close_application(self,result):
        if self.application is not None:self.application.close(result);self.application=None


def consumer_read_check(root,capsule):
    """Real intended numeric UID/GID, no source-index refresh or global config."""
    def drop():
        os.setgroups([1001]);os.setgid(1001);os.setuid(1001)
    # Git config is explicitly disabled; do NOT force a fictitious HOME for
    # the unchanged governance tool. Its actual UID1001 instruction/global
    # Control context must be independently protected/accepted before dispatch.
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C',
         'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
         'GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0','PYTHONDONTWRITEBYTECODE':'1',
         'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'safe.directory','GIT_CONFIG_VALUE_0':str(root)}
    base=['/usr/bin/git','--no-optional-locks','-c','core.fsmonitor=false',
          '-c','core.hooksPath=/dev/null','-c','safe.directory='+str(root),'-C',str(root)]
    def execute(argv):
        result=subprocess.run(argv,cwd=root,env=env,preexec_fn=drop,capture_output=True,timeout=10)
        c.require(result.returncode==0,'CONSUMER_READ_RED');return result.stdout
    commit=execute(base+['rev-parse','HEAD']).decode().strip()
    tree=execute(base+['rev-parse','HEAD^{tree}']).decode().strip()
    c.require((commit,tree)==(capsule.target['commit'],capsule.target['tree']),'CONSUMER_BINDING_RED')
    c.require(execute(base+['status','--porcelain=v1','--untracked-files=all'])==b'','CONSUMER_WORKTREE_RED')
    execute(base+['fsck','--strict'])
    proof={'uid':1001,'gid':1001,'git_readonly':'GREEN','commit':commit,'tree':tree,
           'productive_rc5_index_binding':'OPEN_NOT_CHANGED','deployment':'NOT_AUTHORIZED'}
    if 'governance/preflight.py' in capsule.files:
        output=execute(['/usr/bin/python3','-I','-B',str(root/'governance/preflight.py'),'--cwd',str(root)])
        c.require(b'GOVERNANCE_V1_1_ACTIVE' in output,'CONSUMER_GOVERNANCE_RED')
        proof['governance']='GREEN_CURRENT_NEW_CWD_ONLY'
    else:proof['governance']='UNAVAILABLE_SYNTHETIC_TARGET_ONLY'
    return proof


def recover_view(layout,capsule,session,grant,public_key,*,boundary=lambda phase:None):
    """One finite, create-only transition. A failure never retries or restores old data."""
    out={'schema':c.SCHEMA+'_RESULT','accepted':False,'primary':None,'abort':None,'cleanup':[],
         'historical_mutated':False,'consumer_activation':False,'slot_consumed':False,
         'rollback':'NOT_REQUIRED_HISTORICAL_UNMODIFIED','automatic_retry':False,'phase':'PRECONDITIONS'}
    trees=[];before=None;fence=None;namespace=None
    def step(phase):out['phase']=phase;boundary(phase)
    try:
        native_prerequisites(layout);session.consume(grant,public_key)
        before=preserved_state(layout);step('BEFORE_CLAIM')
        namespace=NamespaceFence(layout.anchor.parent)
        os.mkdir(layout.anchor,0o700);out['slot_consumed']=True
        anchor=OwnedTree(layout.anchor,namespace);trees.append(anchor)
        for name in ('backup','restore-test','release','journal'):anchor.directory(name)
        for name in ('backup/data','restore-test/tree'):anchor.directory(name)
        for name in ('backup','restore-test'):
            fd=anchor.records[name]['fd'];os.fchown(fd,0,0);os.fchmod(fd,0)
            for attr in os.listxattr(fd):os.removexattr(fd,attr)
            set_flags(fd,flags(fd)|IMMUTABLE);os.fsync(fd)
            anchor.refresh(name)
        anchor.file('claim.json',c.canonical(session.body))
        os.fchown(anchor.root_fd,0,1001);os.fchmod(anchor.root_fd,0o550)
        for attr in os.listxattr(anchor.root_fd):os.removexattr(anchor.root_fd,attr)
        set_flags(anchor.root_fd,flags(anchor.root_fd)|IMMUTABLE);os.fsync(anchor.root_fd)
        anchor.refresh('.')
        step('CLAIM_DURABLE')
        c.require(ancestors(layout.historical)==session.body['ancestors'] and
                  ancestors(layout.anchor.parent)==session.body['anchor_ancestors'],'ANCESTOR_CHANGED')
        snapshot=Snapshot(layout.historical,reserve=2*len(capsule.release_files())+64)
        session.snapshot=snapshot
        fence=PreservedFence(layout,snapshot.leases);fence.open()
        source=source_binding(snapshot,layout);out['source']=source
        free=os.statvfs(layout.anchor)
        c.require(free.f_bavail*free.f_frsize>=3*snapshot.bytes+2*len(capsule.raw)+1024*1024
                  and free.f_favail>=3*len(snapshot.nodes)+2*len(capsule.release_files())+128,'BACKUP_CAPACITY_RED')
        backup=OwnedTree(layout.anchor/'backup/data',namespace);trees.append(backup)
        for name,record in snapshot.nodes.items():
            if record['type']==stat.S_IFREG:
                raw=snapshot.data(name)
                blob=c.digest(raw)
                if blob not in backup.records:backup.file(blob,raw,0)
        manifest=c.canonical(snapshot.nodes);backup.file('manifest.json',manifest,0)
        backup.check();snapshot.check();step('BACKUP_READBACK')
        restore=OwnedTree(layout.anchor/'restore-test/tree',namespace);trees.append(restore)
        parsed=json.loads(os.pread(backup.records['manifest.json']['fd'],len(manifest),0))
        c.require(c.canonical(parsed)==manifest,'BACKUP_MANIFEST_RED')
        def backup_data(name):
            record=parsed[name];blob=record['sha256'];c.require(blob in backup.records,'BACKUP_MISSING')
            raw=os.pread(backup.records[blob]['fd'],record['size'],0)
            c.require(len(raw)==record['size'] and c.digest(raw)==blob,'BACKUP_CORRUPT')
            return raw
        groups={}
        for name,record in sorted(snapshot.nodes.items(),key=lambda item:(len(Path(item[0]).parts),item[0])):
            if name=='.':continue
            if record['type']==stat.S_IFDIR:restore.directory(name)
            elif record['type']==stat.S_IFREG:
                # Hardlink groups are reconstructed before flags are restored.
                if record['hardlink_group'] in groups:
                    parent,_,leaf=name.rpartition('/');parent_fd=restore.directory(parent)
                    os.link(groups[record['hardlink_group']],leaf,src_dir_fd=restore.root_fd,
                            dst_dir_fd=parent_fd,follow_symlinks=False)
                    fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent_fd);restore.descriptors.append(fd)
                    restore.records[name]={**metadata(fd),'fd':fd,'sha256':record['sha256']}
                else:
                    profile={**record,'flags':record['flags']&~(IMMUTABLE|0x20)}
                    restore.file(name,backup_data(name),profile=profile)
                    groups[record['hardlink_group']]=name
            else:
                parent,_,leaf=name.rpartition('/');fd=restore.directory(parent)
                os.symlink(record['link'],leaf,dir_fd=fd)
                path=restore.root/name
                os.chown(path,record['uid'],record['gid'],follow_symlinks=False)
                os.utime(path,ns=(record['mtime_ns'],record['mtime_ns']),follow_symlinks=False)
                for attr in os.listxattr(path,follow_symlinks=False):
                    if attr not in record['attrs']:os.removexattr(path,attr,follow_symlinks=False)
                for attr,value in record['attrs'].items():os.setxattr(path,attr,base64.b64decode(value),follow_symlinks=False)
                restore.records[name]={**metadata(None,path),'link':record['link']}
        # Metadata reconstruction must be ordered after child creation/linking.
        for name,record in sorted(snapshot.nodes.items(),key=lambda item:len(Path(item[0]).parts),reverse=True):
            if record['type']!=stat.S_IFLNK:
                fd=restore.root_fd if name=='.' else restore.records[name]['fd']
                restore_profile(fd,record)
                restore.refresh(name)
                observed=metadata(fd)
                fields=('type','mode','uid','gid','mtime_ns','attrs')
                c.require(all(observed[k]==record[k] for k in fields),'RESTORE_METADATA_RED')
                c.require((observed['flags']&~PHYSICAL_LAYOUT_FLAGS)==(record['flags']&~PHYSICAL_LAYOUT_FLAGS),
                          'RESTORE_FLAGS_RED')
                if record['type']==stat.S_IFREG:
                    c.require(observed['nlink']==record['nlink'] and os.pread(fd,record['size'],0)==backup_data(name),
                              'RESTORE_DATA_OR_LINKS_RED')
        restore.check();snapshot.check();step('RESTORE_TESTED')
        backup.seal(directory_mode=0,gid=0)
        target=OwnedTree(layout.anchor/'release',namespace);trees.append(target)
        for name,(raw,mode) in capsule.release_files().items():target.file(name,raw,mode)
        target.directory('.git/refs')
        target.seal();snapshot.check();step('RELEASE_SEALED')
        out['consumer']=consumer_read_check(layout.anchor/'release',capsule)
        c.require(preserved_state(layout)==before,'PRESERVED_CHANGED')
        c.require(ancestors(layout.anchor.parent)==session.body['anchor_ancestors'],'ANCHOR_ANCESTOR_CHANGED')
        journal=OwnedTree(layout.anchor/'journal',namespace);trees.append(journal)
        receipt={'schema':c.SCHEMA+'_PREPARED_PENDING_CLEANUP','slot':c.SLOT,'target':capsule.target,
                 'capsule_sha256':capsule.sha256,'backup_manifest_sha256':c.digest(manifest),
                 'source':source,'host':layout.host,'grant_sha256':c.digest(c.canonical(grant)),
                 'ancestors':session.body['anchor_ancestors'],'historical_mutated':False,
                 'anchor_identity':list(identity(layout.anchor)),
                 'release_manifest':{name:{'sha256':c.digest(raw),'mode':mode}
                                     for name,(raw,mode) in capsule.release_files().items()},
                 'control_path':str(layout.anchor/'release'),'consumers_rebound':False,
                 'host_consumer_governance_deployment_acceptance':'OPEN_REQUIRED_SEPARATELY'}
        journal.file('prepared.json',c.canonical(receipt));snapshot.check();journal.check()
        target.check();backup.check();restore.check();namespace.check()
        fence.check()
        step('RECEIPT_WRITTEN');out['receipt']=receipt
    except BaseException as error:
        out['primary']=c.failure(error)
        out['cleanup'].extend(getattr(error,'_control_cleanup',[]))
        # No restore/delete/namespace "repair". Retain even partial owned paths.
        if out['slot_consumed'] and existing(layout.anchor/'journal'):
            try:
                denied=OwnedTree(layout.anchor/'journal',namespace);trees.append(denied)
                denied.file('denied.json',c.canonical({'schema':c.SCHEMA+'_DENIED','slot':c.SLOT,
                    'primary':out['primary'],'retry_allowed':False}))
            except BaseException as secondary:out['abort']=c.failure(secondary)
    finally:
        if fence is not None:
            try:fence.check()
            except BaseException as error:
                if out['primary'] is None:out['primary']=c.failure(error)
                else:out['cleanup'].append(c.failure(error))
            fence.close_application(out)
        if session.snapshot is not None:
            try:session.snapshot.check()
            except BaseException as error:
                if out['primary'] is None:out['primary']=c.failure(error)
                else:out['cleanup'].append(c.failure(error))
            session.snapshot.close(out)
        if fence is not None:fence.close(out)
        for tree in reversed(trees):
            try:tree.close(out)
            except BaseException as secondary:out['cleanup'].append(c.failure(secondary))
        current=fd_state()
        if namespace is not None:current.pop(str(namespace.events),None)
        out['fd_baseline_restored']=current==session.fd_baseline
        if before is not None:
            try:c.require(preserved_state(layout)==before,'PRESERVED_CHANGED')
            except BaseException as error:out['cleanup'].append(c.failure(error))
    green=(out['primary'] is None and out['abort'] is None and not out['cleanup'] and
           out.get('fd_limit_restored') is True and out.get('fd_baseline_restored') is True)
    if green:
        final=None
        try:
            c.require(ancestors(layout.anchor.parent)==session.body['anchor_ancestors'],'ANCHOR_ANCESTOR_CHANGED')
            final=OwnedTree(layout.anchor/'journal',namespace)
            # Existing journal entries are not adopted by OwnedTree. This
            # finite final append does not invoke its whole-new-tree checker.
            final.file('completion.json',c.canonical({'schema':c.SCHEMA+'_CLEANUP_COMPLETED',
                'slot':c.SLOT,'prepared_sha256':c.digest(c.canonical(out['receipt'])),
                'anchor_identity':list(identity(layout.anchor)),'fd_limit_restored':True,
                'consumer_activation':False,'historical_mutated':False}))
            step('COMPLETION_WRITTEN')
            verify_completed_view(layout,capsule,grant,public_key)
            namespace.check()
        except BaseException as error:out['cleanup'].append(c.failure(error))
        finally:
            if final is not None:final.close(out)
        current=fd_state()
        if namespace is not None:current.pop(str(namespace.events),None)
        out['fd_baseline_restored']=current==session.fd_baseline
        out['accepted']=not out['cleanup'] and out['fd_baseline_restored']
    if namespace is not None:
        namespace.close(out)
        out['fd_baseline_restored']=fd_state()==session.fd_baseline
        out['accepted']=out['accepted'] and not out['cleanup'] and out['fd_baseline_restored']
    # A subsequent acceptance probe additionally requires the complete pair,
    # no denied/failure record, signatures and CURRENT immutable tree checks.
    return out


def verify_completed_view(layout,capsule,grant,public_key):
    """A current read-only check; not a new recovery or renewed permission.

    Host pair alone is not a success: the trusted client must also have the
    independently received final clean result and its non-revoked acceptance.
    A missing/lost reply remains UNKNOWN, even if this pair looks complete.
    """
    verify_signature(public_key,c.canonical(grant['body']),base64.b64decode(grant['signature'],validate=True))
    root=layout.anchor
    c.require(ancestors(root.parent)==grant['body']['anchor_ancestors'],'ANCHOR_ANCESTOR_CHANGED')
    for name in ('denied.json','failed.json','revoked.json'):
        c.require(not existing(root/'journal'/name),'VIEW_DENIED_OR_REVOKED')
    c.require({p.name for p in (root/'journal').iterdir()}=={'prepared.json','completion.json'},
              'FOREIGN_OUTPUT')
    def read_sealed(path,mode,gid):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=metadata(fd);c.require(before['type']==stat.S_IFREG and before['uid']==0 and
                before['gid']==gid and before['mode']==mode and not before['attrs'] and
                before['flags']&IMMUTABLE and before['nlink']==1,'VIEW_SEAL_RED')
            raw=os.pread(fd,before['size'],0)
            c.require(len(raw)==before['size'] and metadata(fd)==before and
                (path.lstat().st_dev,path.lstat().st_ino)==(before['device'],before['inode']),'VIEW_CHANGED')
            return raw
        finally:os.close(fd)
    claim=json.loads(read_sealed(root/'claim.json',0o600,1001))
    prepared_raw=read_sealed(root/'journal/prepared.json',0o600,1001)
    receipt=json.loads(prepared_raw);completion=json.loads(read_sealed(root/'journal/completion.json',0o600,1001))
    c.require(claim==grant['body'] and receipt['target']==capsule.target and receipt['capsule_sha256']==capsule.sha256
        and receipt['grant_sha256']==c.digest(c.canonical(grant)) and receipt['slot']==c.SLOT
        and receipt['anchor_identity']==list(identity(root)) and completion['slot']==c.SLOT
        and completion['prepared_sha256']==c.digest(prepared_raw)
        and completion['anchor_identity']==receipt['anchor_identity'],'COMPLETION_BINDING_RED')
    files=capsule.release_files();expected_dirs={'.git/refs','.'}
    for name in files:
        expected_dirs.update(str(p) for p in Path(name).parents if str(p)!='.')
    actual_files=set();actual_dirs={'.'}
    pending=[root/'release']
    while pending:
        parent=pending.pop();fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            m=metadata(fd);c.require(m['uid']==0 and m['gid']==1001 and m['mode']==0o550 and
                not m['attrs'] and m['flags']&IMMUTABLE,'VIEW_SEAL_RED')
        finally:os.close(fd)
        for child in parent.iterdir():
            name=str(child.relative_to(root/'release'));st=child.lstat()
            if stat.S_ISDIR(st.st_mode):actual_dirs.add(name);pending.append(child)
            else:
                c.require(name in files,'FOREIGN_OUTPUT');raw,mode=files[name]
                c.require(read_sealed(child,mode,1001)==raw,'VIEW_CONTENT_RED');actual_files.add(name)
    c.require(actual_files==set(files) and actual_dirs==expected_dirs,'VIEW_INVENTORY_RED')
    c.require(ancestors(root.parent)==grant['body']['anchor_ancestors'],'ANCHOR_ANCESTOR_CHANGED')
    return {'prepared_sha256':c.digest(prepared_raw),'target':capsule.target,'slot':c.SLOT}
