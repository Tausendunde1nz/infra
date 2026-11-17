"""Finite Mac file-restore primitive for the approved Rev4 private backup.

Import is inert; no CLI, Host connection, arbitrary restore destination, source
repair or production restore. The reviewed caller must supply the fixed private
backup directory FD, authenticated finite manifest and hash-verified bytes.
This supports only the observed plain POSIX profile, not Linux ACL conversion.
Actual foreign ownership requires a real privileged local process; no emulation.
"""
import ctypes
import errno
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import time

PHYSICAL_FLAGS = 0x80000 | 0x1000  # existing Linux restore contract, not copied
FIELDS = frozenset(('device','inode','uid','gid','mode','type','nlink','size',
                    'mtime_ns','ctime_ns','atime_ns','attrs','flags'))
MAX_BYTES = 32*1024*1024
MAX_OBJECTS = 128
OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Denied(RuntimeError):
    """Fixed codes only; never disclose a private path or file content."""


def need(value, code):
    if not value:raise Denied(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def profile(manifest, blobs, expected_paths):
    """All validation precedes the first mkdir. Scope is independently bound.

    Exact filenames/88-object membership are the caller's reviewed Scope gate.
    This second boundary cannot turn a member into a symlink, special file,
    executable, privileged mode, Linux ACL, or relative traversal.
    """
    need(type(manifest) is dict and type(blobs) is dict and type(expected_paths) is list and
         len(expected_paths) == len(set(expected_paths)) and
         0 < len(manifest) <= MAX_OBJECTS and set(manifest) == set(expected_paths), 'FILE_RESTORE_SET')
    total = 0; used = set()
    for path,row in manifest.items():
        p = PurePosixPath(path)
        need(type(path) is str and p.is_absolute() and path == str(p) and path != '/' and
             not path.startswith('//') and
             '..' not in p.parts and len(p.parts) <= 14 and
             all(re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',part) for part in p.parts[1:]), 'FILE_RESTORE_PATH')
        need(type(row) is dict and set(row) == {'sha256','metadata'} and
             type(row['metadata']) is dict and set(row['metadata']) == FIELDS, 'FILE_RESTORE_SCHEMA')
        m = row['metadata']
        need(all(type(m[k]) is int and 0 <= m[k] < 2**63 for k in FIELDS-{'attrs'}) and
             m['type'] in (stat.S_IFREG,stat.S_IFDIR) and m['attrs'] == {} and
             not m['flags'] & ~PHYSICAL_FLAGS and m['mode'] <= 0o777 and
             m['uid'] < 2**31 and m['gid'] < 2**31, 'FILE_RESTORE_UNSUPPORTED_METADATA')
        if m['type'] == stat.S_IFREG:
            need(not m['mode'] & 0o111 and m['nlink'] == 1 and
                 type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                 'FILE_RESTORE_REGULAR_PROFILE')
            raw = blobs.get(row['sha256'])
            need(type(raw) is bytes and len(raw) == m['size'] and sha(raw) == row['sha256'],
                 'FILE_RESTORE_BACKUP_BYTES')
            used.add(row['sha256']);total += len(raw)
        else:
            need(row['sha256'] is None, 'FILE_RESTORE_DIRECTORY_PROFILE')
        for parent in p.parents:
            if str(parent) in manifest:
                need(manifest[str(parent)]['metadata']['type'] == stat.S_IFDIR, 'FILE_RESTORE_PARENT_TYPE')
    need(set(blobs) == used and total <= MAX_BYTES, 'FILE_RESTORE_VOLUME')
    return total


class NativeMac:
    def __init__(self):
        need(sys.platform == 'darwin', 'FILE_RESTORE_MAC_REQUIRED')
        self.lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        P=ctypes.c_void_p;I=ctypes.c_int;S=ctypes.c_char_p
        for name,args,result in (
                ('acl_get_fd_np',[I,I],P),('acl_valid',[P],I),('acl_get_entry',[P,I,ctypes.POINTER(P)],I),
                ('flistxattr',[I,P,ctypes.c_size_t,I],ctypes.c_ssize_t),
                ('acl_free',[P],I),('renameatx_np',[I,S,I,S,ctypes.c_uint],I)):
            fn=getattr(self.lib,name);fn.argtypes=args;fn.restype=result

    def no_acl(self,fd):
        os.fstat(fd);ctypes.set_errno(0)
        acl=self.lib.acl_get_fd_np(fd,0x100)  # ACL_TYPE_EXTENDED, SDK sys/acl.h
        if not acl and ctypes.get_errno()==errno.ENOENT:
            # Apple's acl_get_fd_np -> filesec_get_property(FILESEC_ACL):
            # ENOENT is an absent ACL property on this existing held fd.
            # No EACCES/EINVAL/ENOTSUP error is accepted as empty.
            # apple-oss-distributions/Libc/{posix1e/acl_file.c,gen/filesec.c}
            os.fstat(fd);return
        need(bool(acl),'FILE_RESTORE_ACL_UNREADABLE')
        try:
            need(self.lib.acl_valid(acl)==0,'FILE_RESTORE_ACL_INVALID')
            entry=ctypes.c_void_p();ctypes.set_errno(0)
            result=self.lib.acl_get_entry(acl,0,ctypes.byref(entry))  # ACL_FIRST_ENTRY
            need(result==-1 and ctypes.get_errno()==errno.EINVAL and not entry,
                 'FILE_RESTORE_MAC_ACL_NOT_EMPTY')
        finally:self.lib.acl_free(acl)

    def plain(self,fd):
        self.no_acl(fd)
        need(self.lib.flistxattr(fd,None,0,0)==0 and os.fstat(fd).st_flags==0,
             'FILE_RESTORE_MAC_ATTRIBUTES')

    def rename(self,fd,source,target):
        need(self.lib.renameatx_np(fd,source,fd,target,4)==0, 'FILE_RESTORE_EXCLUSIVE_RENAME')
        os.fsync(fd)


def restore_private_files(parent_fd, manifest, blobs, expected_paths, *, deadline):
    """Real restore under a create-only 'file-restore' child of a held FD.

    Own test copies are removed only after full readback, rename/return and
    identity-checked enumeration. The empty entry directory stays occupied.
    A failed/unclear run retains its artifacts; it is never retried under
    another name. Backups/receipts are never removed.
    """
    total=profile(manifest,blobs,expected_paths);native=NativeMac()
    p=os.fstat(parent_fd)
    need(stat.S_ISDIR(p.st_mode) and stat.S_IMODE(p.st_mode)==0o700 and
         (os.geteuid()==0 or p.st_uid==os.geteuid()),'FILE_RESTORE_PRIVATE_PARENT')
    native.plain(parent_fd)
    handles={};edges=[];container=None;tree=None
    def live():need(time.monotonic()<deadline,'FILE_RESTORE_DEADLINE')
    def identity(s):return s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode)
    def linked(parent,name,fd):
        need(identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity(os.fstat(fd)),
             'FILE_RESTORE_OBJECT_REPLACED')
    def directory(parent,name):
        live();os.mkdir(name,0o700,dir_fd=parent)
        fd=os.open(name,OPEN|os.O_DIRECTORY,dir_fd=parent);edges.append((parent,name,fd,True))
        linked(parent,name,fd);native.plain(fd);return fd
    try:
        live();container=directory(parent_fd,'file-restore')
        tree=directory(container,'tree');handles['/']=tree
        all_dirs=set()
        for path,row in manifest.items():
            pp=PurePosixPath(path)
            all_dirs.update(str(p) for p in pp.parents if str(p)!='/')
            if row['metadata']['type']==stat.S_IFDIR:all_dirs.add(path)
        need(len(all_dirs)+len(manifest)<=192,'FILE_RESTORE_FD_BOUND')
        for path in sorted(all_dirs,key=lambda p:(p.count('/'),p)):
            pp=PurePosixPath(path);handles[path]=directory(handles[str(pp.parent)],pp.name)
        for path,row in sorted(manifest.items()):
            live();m=row['metadata']
            if m['type']!=stat.S_IFREG:continue
            pp=PurePosixPath(path);parent=handles[str(pp.parent)]
            fd=os.open(pp.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            edges.append((parent,pp.name,fd,False));handles[path]=fd;native.plain(fd)
            raw=blobs[row['sha256']];offset=0
            while offset<len(raw):live();offset+=os.write(fd,raw[offset:offset+65536])
            os.fsync(fd);linked(parent,pp.name,fd)
        # Apply directory times last, once no entries are being created.
        for path,row in sorted(manifest.items(),key=lambda item:(item[0].count('/'),item[0]),reverse=True):
            live();fd=handles[path];m=row['metadata']
            os.fchown(fd,m['uid'],m['gid']);os.fchmod(fd,m['mode'])
            os.utime(fd,ns=(m['atime_ns'],m['mtime_ns']));os.fsync(fd)
        observations={}
        for path,row in sorted(manifest.items()):
            live();fd=handles[path];s=os.fstat(fd);m=row['metadata'];native.plain(fd)
            need((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),stat.S_IFMT(s.st_mode),s.st_mtime_ns)==
                 tuple(m[k] for k in ('uid','gid','mode','type','mtime_ns')),'FILE_RESTORE_METADATA_READBACK')
            if m['type']==stat.S_IFREG:
                raw=os.pread(fd,m['size']+1,0)
                need(len(raw)==m['size'] and sha(raw)==row['sha256'] and s.st_nlink==1,
                     'FILE_RESTORE_CONTENT_READBACK')
            observations[path]={'device':s.st_dev,'inode':s.st_ino,'ctime_ns':s.st_ctime_ns,
                                'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),
                                'mtime_ns':s.st_mtime_ns,'sha256':row['sha256']}
        for parent,name,fd,_ in edges:linked(parent,name,fd)
        native.rename(container,b'tree',b'tree-return');linked(container,'tree-return',tree)
        native.rename(container,b'tree-return',b'tree');linked(container,'tree',tree)
        # No glob or recursive deletion: only the exact created inode/name set.
        for parent,name,fd,isdir in reversed(edges[1:]):
            live();linked(parent,name,fd)
            if isdir:
                need(os.listdir(fd)==[],'FILE_RESTORE_CLEANUP_FOREIGN_ENTRY')
                os.rmdir(name,dir_fd=parent)
            else:os.unlink(name,dir_fd=parent)
            os.fsync(parent)
        linked(parent_fd,'file-restore',container)
        need(os.listdir(container)==[],'FILE_RESTORE_CLEANUP_FOREIGN_ENTRY')
        return {'schema':'TU1NZ_REV4_MAC_FILE_RESTORE_V1','objects':len(manifest),'bytes':total,
                'observations':observations,'actual_ownership':True,'empty_acl_xattrs':True,
                'physical_linux_layout_not_recreated':True,'historical_inode_ctime_not_recreated':True,
                'rename_return':True,'own_test_cleanup':True,'empty_entry_retained':True,
                'production_restore':False}
    finally:
        for _,_,fd,_ in reversed(edges):os.close(fd)
