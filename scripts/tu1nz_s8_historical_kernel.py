"""ext4 kernel exclusion of retained writable handles during capture.

An inode flag alone is not handle revocation. Leases are acquired once per
descriptor, never reacquired after failure/break. The containing whole-tree
inotify/ancestry witness detects namespace/metadata mutation. This changes no inode flags,
database lease, process state or admission marker. Kernel administrators who
can clear flags, replace mounts, modify the kernel/raw device or inspect the
reader are the same explicit TCB as the existing sealed stock, not a UID-zero
repository-writer exemption. Ordinary UID-zero and ACL writers are fenced.
"""
import ctypes
import fcntl
import os
import signal
import stat
import struct
import threading
import time

import tu1nz_s8_execution_contract as c
from tu1nz_s8_admission_channel import protect_process

EXT4 = 0xef53
LEASE_SIGNAL = signal.SIGRTMIN + 3 if hasattr(signal, 'SIGRTMIN') else None


def ext4(fd):
    """No overlay/NFS lease or inode-flag equivalence is inferred."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.fstatfs.restype = ctypes.c_int
    value = ctypes.create_string_buffer(256)
    c.require(libc.fstatfs(fd, value) == 0 and
              ctypes.c_long.from_buffer(value).value == EXT4, 'HISTORICAL_EXT4_REQUIRED')


class ReadLeases:
    """Thread-directed reserved signal; final proof also requires GETLEASE.

    The owned Python thread keeps this reserved real-time signal blocked until
    process exit. It is intentionally not unblocked during cleanup: delayed
    break notifications must not become an unhandled post-cleanup signal.
    Foreign/pending signals, owner changes, a break or expiry deny acceptance.
    Fork/thread handoff cannot reuse a witness. No signal is sent to a writer.
    """
    def __init__(self, *, deadline=None):
        c.require(os.uname().sysname == 'Linux' and LEASE_SIGNAL is not None,
                  'HISTORICAL_KERNEL_REQUIRED')
        self.owner = (os.getpid(), threading.get_native_id())
        self.descriptors = []
        self.events = None
        self.deadline = min(time.monotonic()+30, deadline) if deadline is not None else time.monotonic()+30
        self.failed = False
        c.require(signal.getsignal(LEASE_SIGNAL) == signal.SIG_DFL,
                  'HISTORICAL_SIGNAL_COLLISION')
        signal.pthread_sigmask(signal.SIG_BLOCK, {LEASE_SIGNAL})
        try:
            protect_process()
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.libc.inotify_init1.argtypes = [ctypes.c_int]
            self.libc.inotify_init1.restype = ctypes.c_int
            self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            self.libc.inotify_add_watch.restype = ctypes.c_int
            self.events = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            c.require(self.events >= 0, 'HISTORICAL_WATCH_REQUIRED')
            self.check()
        except BaseException as error:
            c.close_preserving(error, self)
            raise

    def remaining(self):
        self._alive()
        return min(15, self.deadline-time.monotonic())

    def _alive(self):
        try:
            c.require(not self.failed and self.events is not None and
                      self.owner == (os.getpid(), threading.get_native_id()), 'HISTORICAL_LEASE_WITNESS_LOST')
            c.require(time.monotonic() < self.deadline, 'HISTORICAL_CAPTURE_TIMEOUT')
            c.require(LEASE_SIGNAL not in signal.sigpending(), 'HISTORICAL_LEASE_BREAK')
            try: event = os.read(self.events, 65536)
            except BlockingIOError: event = b''
            c.require(not event, 'HISTORICAL_READ_CHANGED')
        except BaseException:
            self.failed = True
            raise

    def acquire(self, fd):
        self._alive()
        c.require(stat.S_ISREG(os.fstat(fd).st_mode) and fd not in self.descriptors,
                  'HISTORICAL_LEASE_DESCRIPTOR_RED')
        ext4(fd)
        watch = self.libc.inotify_add_watch(self.events, os.fsencode('/proc/self/fd/'+str(fd)), 0x00000fce)
        c.require(watch >= 0, 'HISTORICAL_WATCH_REQUIRED')
        # F_SETOWN_EX/F_OWNER_TID prevents notifications going to other guard
        # threads. The native lease setup preserves an already configured owner.
        fcntl.fcntl(fd, fcntl.F_SETSIG, LEASE_SIGNAL)
        fcntl.fcntl(fd, 15, struct.pack('ii', 0, self.owner[1]))
        try:
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        except OSError as error:
            self.failed = True
            denied = c.ContractError('S8_EXECUTION_HISTORICAL_WRITER_EXCLUSION_UNAVAILABLE')
            denied._s8_read_failure = c.failure_record(error)
            raise denied from None
        self.descriptors.append(fd)  # ownership is recorded before later checks
        self._check_descriptor(fd)
        self._alive()

    def _check_descriptor(self, fd):
        owner = fcntl.fcntl(fd, 16, struct.pack('ii', 0, 0))
        c.require(struct.unpack('ii', owner) == (0, self.owner[1]) and
                  fcntl.fcntl(fd, fcntl.F_GETSIG) == LEASE_SIGNAL and
                  fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK,
                  'HISTORICAL_LEASE_BREAK')

    def check(self):
        self._alive()
        try:
            for fd in self.descriptors:
                self._check_descriptor(fd)
            self._alive()
        except BaseException:
            self.failed = True
            raise

    def close(self):
        # The containing witness owns/closes the descriptors once. Merely
        # clearing this list must never remove inode protections or mint proof.
        self.failed = True
        self.descriptors = []
        fd, self.events = self.events, None
        c.close_descriptors(None, fd)

    def __enter__(self): return self

    def __exit__(self, kind, value, trace):
        if value is not None:
            c.close_preserving(value, self)
            return False
        try: self.check()
        except BaseException as error:
            c.close_preserving(error, self)
            raise
        self.close()
