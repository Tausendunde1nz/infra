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
import threading

from tu1nz_s8_execution_contract import ContractError, close_preserving, failure_record, protected, require


EVENT=struct.Struct("=IBBHQii")
RESPONSE=struct.Struct("=iI")
GET_FLAGS=0x80086601
SET_FLAGS=0x40086602
APPEND=0x20
IMMUTABLE=0x10


def inode_flags(fd):
    value=array.array("L",[0]);fcntl.ioctl(fd,GET_FLAGS,value,True)
    return value[0]


def add_inode_protection(fd, flag):
    require(flag in (APPEND,IMMUTABLE),"JOURNAL_FLAG_RED")
    old=inode_flags(fd)
    require(not old & flag,"JOURNAL_ALREADY_PROTECTED")
    fcntl.ioctl(fd,SET_FLAGS,array.array("L",[old|flag]))
    require(inode_flags(fd)==old|flag,"JOURNAL_FLAG_RED")
    os.fsync(fd)


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
        self.identity=(os.fstat(self.directory).st_dev,os.fstat(self.directory).st_ino)
        self.owner_tid=threading.get_native_id()
        self.owner_pid=os.getpid()
        self.fd=None;self.events=None;self.thread=None
        self.failure=False;self.foreign=False;self.stop=threading.Event()
        try:
            require(inode_flags(self.directory)&APPEND,"APPEND_ONLY_DIRECTORY_REQUIRED")
            require(not any(root.iterdir()),"NEW_EMPTY_JOURNAL_REQUIRED")
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
            # There are no authorized chmod/chown/rename/delete operations.
            require(libc.inotify_add_watch(self.events,os.fsencode(root),0x00000ec4)>=0,
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
                    try:
                        allowed=tid==self.owner_tid and os.getpid()==self.owner_pid
                        if not allowed:self.foreign=True
                        require(os.write(self.fd,RESPONSE.pack(fd,1 if allowed else 2))==RESPONSE.size,
                                "FANOTIFY_RESPONSE_RED")
                    finally:os.close(fd)
        except BaseException:
            self.failure=True
            # A dead consumer must not leave permission requests blocked. The
            # failure latch precedes close; callers cannot publish authority
            # after the release. Existing partial records remain consuming.
            descriptor=self.fd
            self.fd=None
            if descriptor is not None and descriptor>=0:
                os.close(descriptor)

    def check(self):
        require(os.getpid()==self.owner_pid and threading.get_native_id()==self.owner_tid,
                "JOURNAL_WRITER_IDENTITY_RED")
        # Our own marked-directory open is a synchronous permission round trip.
        # It ensures the consumer is alive; it never authorizes a foreign open.
        require(self.thread is not None and self.thread.is_alive() and not self.failure,
                "JOURNAL_GUARD_LOST")
        probe=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            m=protected(self.root,directory=True,mode=self.directory_mode)
            require((m.st_dev,m.st_ino)==self.identity==
                    (os.fstat(probe).st_dev,os.fstat(probe).st_ino)
                    and inode_flags(probe)&APPEND,"JOURNAL_IDENTITY_RED")
        finally:os.close(probe)
        require(not self.failure and not self.foreign,"JOURNAL_FOREIGN_OPEN_RED")
        try:events=os.read(self.events,65536)
        except BlockingIOError:events=b""
        require(not events,"JOURNAL_METADATA_EVENT_RED")

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
