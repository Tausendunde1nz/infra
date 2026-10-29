"""Single-writer native guard for a NEW empty append-only journal directory.

No existing/historical directory may be adopted. No broad root/descendant
exemption. Permission events authorize only the constructing thread during
this guard's lifetime. All other opens are denied and invalidate the operation.
There is deliberately no mutation, signal, tracing or process-pause API here.
"""
from __future__ import annotations

import array
import ctypes
import fcntl
import os
from pathlib import Path
import select
import struct
import sys
import threading

from tu1nz_s8_execution_contract import ContractError, close_descriptors, close_preserving, descriptor_scope, failure_record, protected, require


EVENT=struct.Struct("=IBBHQii")
RESPONSE=struct.Struct("=iI")
GET_FLAGS=0x80086601
SET_FLAGS=0x40086602
APPEND=0x20
IMMUTABLE=0x10
FAN_CLASS_NOTIF = 0
FAN_CLOEXEC = 0x1
FAN_NONBLOCK = 0x2
FAN_REPORT_TID = 0x100
FAN_REPORT_FID = 0x200


def inode_fid(fd):
    """Kernel FSID + opaque file handle, never a pathname/stat substitute.

    Deliberately bounded Linux LP64 ABI. Unsupported filesystems/kernels are
    platform HOLD, not permission to fall back to a dev/inode approximation.
    No open_by_handle_at, new privilege, or handle-based mutation is used.
    """
    require(sys.platform == "linux" and os.uname().machine in ("x86_64", "aarch64")
            and ctypes.sizeof(ctypes.c_long) == 8,
            "METADATA_FID_ABI_REQUIRED")
    libc = ctypes.CDLL(None, use_errno=True)
    fs = ctypes.create_string_buffer(120)  # Linux LP64 struct statfs
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.fstatfs.restype = ctypes.c_int
    require(libc.fstatfs(fd, fs) == 0, "METADATA_FSID_REQUIRED")
    fsid = fs.raw[56:64]
    require(any(fsid), "METADATA_FSID_REQUIRED")
    handle = ctypes.create_string_buffer(8 + 128)
    struct.pack_into("=Ii", handle, 0, 128, 0)
    mount = ctypes.c_int()
    libc.name_to_handle_at.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    libc.name_to_handle_at.restype = ctypes.c_int
    # AT_EMPTY_PATH | AT_HANDLE_FID (comparison-only identity, Linux >=6.5).
    require(libc.name_to_handle_at(fd, b"", handle, ctypes.byref(mount), 0x1200) == 0,
            "METADATA_FILE_HANDLE_REQUIRED")
    size, kind = struct.unpack_from("=Ii", handle.raw)
    require(0 < size <= 128 and kind > 0 and kind != 255, "METADATA_FILE_HANDLE_RED")
    return fsid, kind, handle.raw[8:8 + size]


def metadata_events(payload):
    """Strict FAN_REPORT_FID/TID records; no event filtering or attribution guess."""
    require(bool(payload), "METADATA_QUEUE_LOST")
    offset = 0
    while offset < len(payload):
        require(len(payload) - offset >= EVENT.size, "METADATA_EVENT_RED")
        length, version, reserved, meta, mask, fd, tid = EVENT.unpack_from(payload, offset)
        require(version == 3 and reserved == 0 and meta == EVENT.size
                and meta + 20 < length <= len(payload) - offset
                and fd == -1 and mask in (4, 0x40000004) and tid > 0,
                "METADATA_EVENT_RED")
        start = offset + meta
        info, pad, size = struct.unpack_from("=BBH", payload, start)
        count, kind = struct.unpack_from("=Ii", payload, start + 12)
        require(info == 1 and pad == 0 and size == length - meta == ((20 + count + 3) & ~3)
                and 0 < count <= 128 and kind > 0 and kind != 255
                and any(payload[start + 4:start + 12])
                and not any(payload[start + 20 + count:offset + length]), "METADATA_FID_EVENT_RED")
        yield tid, (payload[start + 4:start + 12], kind,
                    payload[start + 20:start + 20 + count])
        offset += length


class MetadataWitness:
    """Continuous ATTRIB responsibility, separately from OPEN_PERM/namespace.

    `children=False` protects only the exact marked inode. `selected=True`
    additionally protects one fresh child bound before the first queue read;
    unrelated siblings retain the parent witness's existing ignored semantics.
    Otherwise every child ATTRIB is fatal unless in the exact flag transaction.
    """
    def __init__(self, directory, *, children=True, selected=False):
        self.fd = None
        self.owner = os.getpid(), threading.get_native_id()
        self.failed = False
        self.pending = None
        self.children = children
        self.selected, self.bound = selected, not selected
        self.targets = {inode_fid(directory)}
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        libc.fanotify_init.restype = ctypes.c_int
        try:
            # NOTIF | CLOEXEC | NONBLOCK | REPORT_TID | REPORT_FID.
            self.fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK |
                                        FAN_REPORT_TID | FAN_REPORT_FID, os.O_RDONLY | os.O_CLOEXEC)
            require(self.fd >= 0, "METADATA_FANOTIFY_REQUIRED")
            libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                          ctypes.c_int, ctypes.c_char_p]
            libc.fanotify_mark.restype = ctypes.c_int
            require(libc.fanotify_mark(self.fd, 0x9, 4 | 0x40000000 |
                    (0x08000000 if children else 0), -100,
                    os.fsencode("/proc/self/fd/" + str(directory))) == 0,
                    "METADATA_MARK_REQUIRED")
        except BaseException as error:
            close_preserving(error, self)
            raise

    def identity_check(self):
        require(not self.failed and self.fd is not None and self.fd >= 0
                and self.owner == (os.getpid(), threading.get_native_id()), "METADATA_WITNESS_LOST")

    def bind(self, fd):
        self.identity_check()
        require(self.selected and not self.bound and self.pending is None,
                "METADATA_BINDING_RED")
        self.targets.add(inode_fid(fd))
        self.bound = True
        self.check()  # Includes events queued since BEFORE mkdir, not just now.

    def check(self):
        try:
            self.identity_check()
            require(self.bound, "METADATA_BINDING_REQUIRED")
            while True:
                try: payload = os.read(self.fd, 65536)
                except BlockingIOError: break
                for tid, fid in metadata_events(payload):
                    if self.selected and fid not in self.targets:
                        continue  # Valid, non-selected sibling, never unknown data.
                    require(self.pending is not None and tid == self.owner[1]
                            and fid == self.pending[0], "JOURNAL_METADATA_EVENT_RED")
                    self.pending[1] += 1
        except BaseException:
            self.failed = True
            raise

    def begin(self, fd):
        require(self.pending is None, "METADATA_TRANSITION_REENTRY")
        self.check()  # Every queued event classified BEFORE authorization.
        fid = inode_fid(fd)
        require(not (self.selected or not self.children) or fid in self.targets,
                "METADATA_TRANSITION_OBJECT_RED")
        self.pending = [fid, 0]

    def finish(self):
        self.check()
        require(self.pending is not None and self.pending[1] > 0,
                "METADATA_TRANSITION_NOT_OBSERVED")
        self.pending = None  # No enduring owner/TID/ATTRIB exemption.

    def close(self):
        self.failed = True
        self.pending = None
        fd, self.fd = self.fd, None
        close_descriptors(None, fd)


def inode_flags(fd):
    value=array.array("L",[0]);fcntl.ioctl(fd,GET_FLAGS,value,True)
    return value[0]


def add_inode_protection(fd, flag, *, observers=()):
    require(flag in (APPEND,IMMUTABLE),"JOURNAL_FLAG_RED")
    old=inode_flags(fd)
    require(not old & flag,"JOURNAL_ALREADY_PROTECTED")
    try:
        require(len({id(observer) for observer in observers}) == len(observers),
                "METADATA_DUPLICATE_OBSERVER")
        for observer in observers: observer.begin(fd)
        # This is the entire authorized same-thread mutation, not a callback.
        fcntl.ioctl(fd,SET_FLAGS,array.array("L",[old|flag]))
        require(inode_flags(fd)==old|flag,"JOURNAL_FLAG_RED")
        os.fsync(fd)
        for observer in observers: observer.finish()
    except BaseException:
        for observer in observers: observer.failed = True
        raise


class NewJournalFence:
    """Must be acquired before any regular file can be created in this root.

    An append-only directory prevents removal/rebinding of a spent filename,
    including an empty record after SIGKILL. Fully written records additionally
    require immutable inodes AND closure/exclusion of every writable handle.
    A kernel administrator capable of removing those protections is outside the
    file-writer threat model; no such reset is part of this protocol.
    """
    def __init__(self,root:Path, *, directory_mode=0o700):
        require(os.geteuid()==0,"PRIVILEGED_JOURNAL_GUARD_REQUIRED")
        require(directory_mode in (0o700, 0o755), "JOURNAL_DIRECTORY_MODE_RED")
        self.directory_mode = directory_mode
        libc=ctypes.CDLL(None,use_errno=True)
        # Deny same-UID descriptor/memory inspection unless the caller holds
        # privileged ptrace authority (part of the explicit kernel TCB).
        require(libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0,
                "PROCESS_HANDLE_PROTECTION_RED")
        protected(root,directory=True,mode=directory_mode)
        self.root=root
        self.directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.identity=None
        self.owner_tid=threading.get_native_id()
        self.owner_pid=os.getpid()
        self.fd=None;self.events=None;self.thread=None;self.metadata=None
        self.failure=False;self.foreign=False;self.stop=threading.Event()
        self.consumer_error=None
        try:
            self.identity=(os.fstat(self.directory).st_dev,os.fstat(self.directory).st_ino)
            require(inode_flags(self.directory)&APPEND,"APPEND_ONLY_DIRECTORY_REQUIRED")
            require(not any(root.iterdir()),"NEW_EMPTY_JOURNAL_REQUIRED")
            self.metadata = MetadataWitness(self.directory)
            libc=ctypes.CDLL(None,use_errno=True)
            libc.fanotify_init.argtypes=[ctypes.c_uint,ctypes.c_uint]
            libc.fanotify_init.restype=ctypes.c_int
            # FAN_CLASS_CONTENT | CLOEXEC | NONBLOCK | REPORT_TID.
            self.fd=libc.fanotify_init(0x107,os.O_RDONLY|os.O_CLOEXEC)
            require(self.fd>=0,"FANOTIFY_REQUIRED")
            libc.fanotify_mark.argtypes=[ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_int,ctypes.c_char_p]
            libc.fanotify_mark.restype=ctypes.c_int
            # ONDIR also covers the synchronous directory liveness probe.
            marked=libc.fanotify_mark(self.fd,0x9,0x48010000,-100,os.fsencode(root))
            require(marked==0,"FANOTIFY_MARK_ERRNO_"+str(ctypes.get_errno()))
            libc.inotify_init1.argtypes=[ctypes.c_int];libc.inotify_init1.restype=ctypes.c_int
            self.events=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
            require(self.events>=0,"INOTIFY_REQUIRED")
            libc.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32]
            libc.inotify_add_watch.restype=ctypes.c_int
            # ATTRIB is continuously classified by the FID/TID witness above;
            # namespace changes/watch loss still belong to this original queue.
            require(libc.inotify_add_watch(self.events,os.fsencode(root),0x00000ec0)>=0,
                    "INOTIFY_REQUIRED")
            self.thread=threading.Thread(target=self._serve,name="s8-journal-guard",daemon=True)
            self.thread.start()
            require(not any(root.iterdir()),"NEW_EMPTY_JOURNAL_REQUIRED")
            self.check()
        except BaseException as error:
            close_preserving(error, self)
            raise

    def _serve(self):
        try:
            while not self.stop.is_set():
                if not select.select([self.fd],[],[],.05)[0]:continue
                payload=os.read(self.fd,1024*1024);offset=0
                while offset<len(payload):
                    require(len(payload)-offset>=EVENT.size,"FANOTIFY_EVENT_RED")
                    length,version,_,meta,mask,fd,tid=EVENT.unpack_from(payload,offset)
                    require(version==3 and EVENT.size<=meta<=length<=len(payload)-offset
                            and fd>=0 and mask&0x10000 and not mask&0x4000,"FANOTIFY_EVENT_RED")
                    offset+=length
                    with descriptor_scope(fd):
                        allowed=tid==self.owner_tid and os.getpid()==self.owner_pid
                        if not allowed:self.foreign=True
                        require(os.write(self.fd,RESPONSE.pack(fd,1 if allowed else 2))==RESPONSE.size,
                                "FANOTIFY_RESPONSE_RED")
        except BaseException as error:
            self.consumer_error=error
            self.failure=True
            # A dead consumer must not leave permission requests blocked. The
            # failure latch precedes close; callers cannot publish authority
            # after the release. Existing partial records remain consuming.
            descriptor=self.fd
            self.fd=None
            close_descriptors(error, descriptor)

    def check(self):
        require(os.getpid()==self.owner_pid and threading.get_native_id()==self.owner_tid,
                "JOURNAL_WRITER_IDENTITY_RED")
        if self.consumer_error is not None: raise self.consumer_error
        # Our own marked-directory open is a synchronous permission round trip.
        # It ensures the consumer is alive; it never authorizes a foreign open.
        require(self.thread is not None and self.thread.is_alive() and not self.failure,
                "JOURNAL_GUARD_LOST")
        probe=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        with descriptor_scope(probe):
            m=protected(self.root,directory=True,mode=self.directory_mode)
            require((m.st_dev,m.st_ino)==self.identity==
                    (os.fstat(probe).st_dev,os.fstat(probe).st_ino)
                    and inode_flags(probe)&APPEND,"JOURNAL_IDENTITY_RED")
        require(not self.failure and not self.foreign,"JOURNAL_FOREIGN_OPEN_RED")
        try:events=os.read(self.events,65536)
        except BlockingIOError:events=b""
        require(not events,"JOURNAL_METADATA_EVENT_RED")
        self.metadata.check()

    def close(self):
        # No successful-close receipt here: the canonical caller must first
        # prove every record sealed and all writable descriptors closed.
        self.stop.set()
        errors = []
        try:
            if self.thread is not None:
                self.thread.join(timeout=2)
                require(not self.thread.is_alive(),"JOURNAL_GUARD_CLEANUP_RED")
        except BaseException as error:
            self.failure = True
            errors.append(failure_record(error))
        metadata, self.metadata = getattr(self, "metadata", None), None
        try:
            if metadata is not None: metadata.close()
        except BaseException as error: errors.append(failure_record(error))
        for name in ("fd","events","directory"):
            descriptor=getattr(self,name,None)
            if descriptor is not None and descriptor>=0:
                setattr(self,name,None)
                try: os.close(descriptor)
                except BaseException as error:
                    self.failure = True
                    errors.append(failure_record(error))
        if errors:
            error = ContractError("S8_EXECUTION_JOURNAL_GUARD_CLEANUP_RED")
            error._s8_cleanup_errors = errors
            raise error
