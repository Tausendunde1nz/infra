"""Bounded historical Git reads; no checkout, index, config or object writes.

Current read eligibility and a continuously watched read interval do not
establish historical owner/inode continuity or authorize any historical writer.
Only the pinned commit/tree objects are attested, not the live worktree.
"""
import ctypes
from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import stat

import tu1nz_s8_execution_contract as c
import tu1nz_s8_path_policy as p
from tu1nz_s8_journal_fence import inode_flags
from tu1nz_s8_historical_kernel import ReadLeases, ext4
from tu1nz_s8_historical_objects import ObjectStore, config_safe, resolve_head, object_read


def unavailable(error):
    """Translate access/IO failures without relabelling them as drift."""
    result = c.ContractError('S8_EXECUTION_HISTORICAL_READ_UNAVAILABLE')
    result._s8_read_failure = c.failure_record(error)
    for name in ('_s8_cleanup_errors', '_s8_abort_error'):
        if hasattr(error, name): setattr(result, name, getattr(error, name))
    return result


def node_metadata(path, *, descriptor=None, directory_watch=None):
    """Read-only Git descendants: no effective non-owner write, no unknown ACL.

    This is not an exemption for an arbitrary repository or an ACL writer.
    The caller must already hold the exact, root-owned historical ancestry.
    Defaults are observed, not exercised. File hardlinks/symlinks are denied.
    """
    m = path.lstat()
    # The legacy permission-only predicate remains a negative regression.
    # The actual R4 reader supplies its held inode plus the active whole-tree
    # witness. A regular inode requires a kernel read lease; directories must
    # already be watched before enumeration. ACLs are observed, not altered.
    if descriptor is not None:
        ext4(descriptor)
        c.require(c.fingerprint(m) == c.fingerprint(os.fstat(descriptor)), 'HISTORICAL_READ_CHANGED')
        if stat.S_ISREG(m.st_mode):
            c.require(fcntl.fcntl(descriptor, fcntl.F_GETLEASE) == fcntl.F_RDLCK, 'HISTORICAL_LEASE_BREAK')
        else:
            c.require(type(directory_watch) is int and directory_watch >= 0,
                      'HISTORICAL_WATCH_REQUIRED')
    c.require((m.st_uid == 0 or (descriptor is not None and stat.S_ISDIR(m.st_mode) and m.st_uid == 1001))
              and m.st_gid in (0, 1001)
              and (stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode))
              and (stat.S_ISDIR(m.st_mode) or m.st_nlink == 1)
              and (descriptor is not None or not m.st_mode & 0o022), 'HISTORICAL_UNSAFE_METADATA')
    names = set(os.listxattr(path, follow_symlinks=False))
    c.require(names <= {p.ACCESS, p.DEFAULT} and
              (stat.S_ISDIR(m.st_mode) or p.DEFAULT not in names), 'HISTORICAL_UNSAFE_XATTR')
    if p.ACCESS in names:
        # Only the already evidenced named UID/GID layout; permissions must
        # agree with the kernel DAC mask and deny effective non-owner writes.
        access = ((1, (m.st_mode >> 6) & 7, p.UNDEFINED), *p.GIT_ACCESS[1:4],
                  (16, (m.st_mode >> 3) & 7, p.UNDEFINED), (32, m.st_mode & 7, p.UNDEFINED))
        if descriptor is None: p.no_nonowner_write(access)
        c.require(os.getxattr(path, p.ACCESS, follow_symlinks=False) == p.acl_bytes(access),
                  'HISTORICAL_UNSAFE_ACL')
    if p.DEFAULT in names:
        c.require(os.getxattr(path, p.DEFAULT, follow_symlinks=False) == p.acl_bytes(p.REPOSITORY_DEFAULT),
                  'HISTORICAL_UNSAFE_DEFAULT_ACL')
    return c.fingerprint(m)


class GitReadWitness:
    """Watch every existing Git inode before use, fail on any write/exchange.

    Watches include files (including existing FDs/hardlink-side changes), not
    just parent directories. Missing/overflowed events and interruption deny
    the result; nothing is resumed, normalized or journalled on the host.
    """
    def __init__(self, root, *, deadline=None):
        self.root, self.rows, self.fd = Path(root), [], None
        self.descriptors, self.leases, self.device = [], None, None
        self.watches = {}
        self.failed = False
        self.owner = os.getpid()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        try:
            self.leases = ReadLeases(deadline=deadline)
            self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            c.require(self.fd >= 0, 'HISTORICAL_WATCH_REQUIRED')
            pending = [self.root]
            while pending:
                path = pending.pop()
                self.leases.remaining()
                c.require(len(self.rows) < 65536, 'HISTORICAL_READ_BOUND')
                before = c.fingerprint(path.lstat())
                m = path.lstat()
                c.require((stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode))
                          and (stat.S_ISDIR(m.st_mode) or m.st_nlink == 1), 'HISTORICAL_UNSAFE_METADATA')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                if path.is_dir(): flags |= os.O_DIRECTORY
                descriptor = os.open(path, flags)
                self.descriptors.append(descriptor)
                c.require(c.fingerprint(os.fstat(descriptor)) == before, 'HISTORICAL_READ_CHANGED')
                ext4(descriptor)
                c.require(not inode_flags(descriptor) & ~(0x80000 | 0x1000 | 0x20 | 0x10),
                          'HISTORICAL_UNSAFE_FLAGS')
                self.device = self.device or before[0]
                c.require(before[0] == self.device, 'HISTORICAL_FILESYSTEM_CHANGED')
                if stat.S_ISREG(os.fstat(descriptor).st_mode): self.leases.acquire(descriptor)
                watch = libc.inotify_add_watch(self.fd, os.fsencode('/proc/self/fd/'+str(descriptor)), 0x00000fce)
                c.require(watch >= 0, 'HISTORICAL_WATCH_REQUIRED')
                if path == self.root:
                    c.require(c.fingerprint(p.historical_metadata(path)) == before, 'HISTORICAL_READ_CHANGED')
                else:
                    c.require(node_metadata(path, descriptor=descriptor, directory_watch=watch) == before,
                              'HISTORICAL_READ_CHANGED')
                self.rows.append((path, before))
                self.watches[descriptor] = watch
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    names = os.listdir(descriptor)
                    c.require(len(names) <= 65536, 'HISTORICAL_READ_BOUND')
                    pending.extend(path/name for name in names)
            self.check()
        except BaseException as error:
            c.close_preserving(error, self)
            raise

    def check(self):
        try:
            self._check()
        except BaseException:
            self.failed = True
            raise

    def _check(self):
        c.require(not self.failed and self.fd is not None and self.owner == os.getpid(), 'HISTORICAL_WITNESS_LOST')
        c.require(len(self.rows) == len(self.descriptors), 'HISTORICAL_WITNESS_LOST')
        self.leases.check()
        for (path, expected), descriptor in zip(self.rows, self.descriptors):
            c.require(not inode_flags(descriptor) & ~(0x80000 | 0x1000 | 0x20 | 0x10),
                      'HISTORICAL_UNSAFE_FLAGS')
            c.require(c.fingerprint(os.fstat(descriptor)) == expected, 'HISTORICAL_READ_CHANGED')
            actual = c.fingerprint(p.historical_metadata(path)) if path == self.root else node_metadata(
                path, descriptor=descriptor, directory_watch=self.watches[descriptor])
            c.require(actual == expected, 'HISTORICAL_READ_CHANGED')
        try: event = os.read(self.fd, 65536)
        except BlockingIOError: event = b''
        c.require(not event, 'HISTORICAL_READ_CHANGED')
        self.leases.check()

    def read(self, leaf):
        fd,size = self.input_descriptor(leaf)
        c.require(0 < size <= 65536, 'HISTORICAL_INPUT_UNAVAILABLE')
        value = os.pread(fd,size,0)
        c.require(len(value) == size, 'HISTORICAL_READ_UNAVAILABLE')
        self.check()
        return value

    def has(self, leaf):
        return any(path == self.root/leaf for path,_ in self.rows)

    def input_descriptor(self, leaf):
        c.require(not self.failed and self.fd is not None and self.owner == os.getpid(), 'HISTORICAL_WITNESS_LOST')
        self.leases.check()
        for (path,expected),fd in zip(self.rows,self.descriptors):
            if path == self.root/leaf:
                c.require(stat.S_ISREG(expected[5]) and c.fingerprint(os.fstat(fd)) == expected,
                          'HISTORICAL_INPUT_UNAVAILABLE')
                return fd,expected[2]
        raise c.ContractError('S8_EXECUTION_HISTORICAL_READ_UNAVAILABLE')

    def close(self):
        self.failed = True
        descriptors, self.descriptors = self.descriptors, []
        fd, self.fd = self.fd, None
        try:
            if self.leases is not None: self.leases.close()
        except BaseException as error:
            c.close_descriptors(error, fd, *reversed(descriptors))
            raise
        c.close_descriptors(None, fd, *reversed(descriptors))

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


def git_config_safe(witness):
    """No config includes, promisor fetching, alternate/worktree object roots.

    Unknown indirection is unavailable/unsafe, never proof of content drift.
    Only ordinary local repository settings are needed by these read commands.
    """
    for name in ('commondir', 'config.worktree', 'shallow', 'info/grafts',
                 'objects/info/alternates', 'objects/info/http-alternates'):
        c.require(not os.path.lexists(witness.root/name), 'HISTORICAL_UNSAFE_INDIRECTION')
    c.require(not any(path.name.endswith('.promisor') for path, _ in witness.rows),
              'HISTORICAL_UNSAFE_INDIRECTION')
    config_safe(witness)


def repository(root, expected, *, capture=None):
    """Attest fixed HEAD, raw commit/tree object identities, and read interval.

    No physical inode predecessor or whole live-worktree equality is inferred.
    Missing bindings/access/object data is not a proven historical mutation.
    """
    root = Path(root)
    c.require(type(expected) is tuple and len(expected) == 2 and
              all(c.hex_value(value, 40) for value in expected), 'HISTORICAL_BINDING_UNAVAILABLE')
    try:
        with ExitStack() as owned:
            scope = owned if capture is None else capture
            ancestry = scope.enter_context(p.PathChain(root, leaf='.git', historical=True))
            guard = p.historical_metadata(root/'.git')
            real_git = root/'.git.s12-1-recovery'
            chain = scope.enter_context(p.PathChain(real_git, historical=True))
            witness = scope.enter_context(GitReadWitness(real_git, deadline=getattr(scope,'_s8_deadline',None)))
            git_config_safe(witness)
            head = resolve_head(witness)
            c.require(head == expected[0], 'HISTORICAL_CONTENT_RED')
            with ObjectStore(witness) as store:
                for oid,kind in zip(expected,(b'commit',b'tree')):
                    actual,payload = object_read(store,oid)
                    c.require(actual == kind and bool(payload), 'HISTORICAL_CONTENT_RED')
                    if kind == b'commit':
                        c.require(payload.startswith(b'tree '+expected[1].encode()+b'\n'), 'HISTORICAL_CONTENT_RED')
                    witness.check(); chain.check(); ancestry.check()
            c.require(c.fingerprint(p.historical_metadata(root/'.git')) == c.fingerprint(guard),
                      'HISTORICAL_READ_CHANGED')
            return dict(commit=head, tree=expected[1], guard=list(c.fingerprint(guard)))
    except (OSError, UnicodeError) as error:
        raise unavailable(error) from None
