"""Bounded historical Git reads; no checkout, index, config or object writes.

Current read eligibility and a continuously watched read interval do not
establish historical owner/inode continuity or authorize any historical writer.
Only the pinned commit/tree objects are attested, not the live worktree.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import subprocess

import tu1nz_s8_execution_contract as c
import tu1nz_s8_path_policy as p
from tu1nz_s8_journal_fence import inode_flags


def unavailable(error):
    """Translate access/IO failures without relabelling them as drift."""
    result = c.ContractError('S8_EXECUTION_HISTORICAL_READ_UNAVAILABLE')
    result._s8_read_failure = c.failure_record(error)
    for name in ('_s8_cleanup_errors', '_s8_abort_error'):
        if hasattr(error, name): setattr(result, name, getattr(error, name))
    return result


def node_metadata(path):
    """Read-only Git descendants: no effective non-owner write, no unknown ACL.

    This is not an exemption for an arbitrary repository or an ACL writer.
    The caller must already hold the exact, root-owned historical ancestry.
    Defaults are observed, not exercised. File hardlinks/symlinks are denied.
    """
    m = path.lstat()
    c.require(m.st_uid == 0 and m.st_gid in (0, 1001)
              and (stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode))
              and (stat.S_ISDIR(m.st_mode) or m.st_nlink == 1)
              and not m.st_mode & 0o022, 'HISTORICAL_UNSAFE_METADATA')
    names = set(os.listxattr(path, follow_symlinks=False))
    c.require(names <= {p.ACCESS, p.DEFAULT} and
              (stat.S_ISDIR(m.st_mode) or p.DEFAULT not in names), 'HISTORICAL_UNSAFE_XATTR')
    if p.ACCESS in names:
        # Only the already evidenced named UID/GID layout; permissions must
        # agree with the kernel DAC mask and deny effective non-owner writes.
        access = ((1, (m.st_mode >> 6) & 7, p.UNDEFINED), *p.GIT_ACCESS[1:4],
                  (16, (m.st_mode >> 3) & 7, p.UNDEFINED), (32, m.st_mode & 7, p.UNDEFINED))
        p.no_nonowner_write(access)
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
    def __init__(self, root):
        self.root, self.rows, self.fd = Path(root), [], None
        self.owner = os.getpid()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        try:
            self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            c.require(self.fd >= 0, 'HISTORICAL_WATCH_REQUIRED')
            pending = [self.root]
            while pending:
                path = pending.pop()
                c.require(len(self.rows) < 65536, 'HISTORICAL_READ_BOUND')
                if path == self.root:
                    before = c.fingerprint(p.historical_metadata(path))
                else:
                    before = node_metadata(path)
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                if path.is_dir(): flags |= os.O_DIRECTORY
                descriptor = os.open(path, flags)
                with c.descriptor_scope(descriptor):
                    c.require(c.fingerprint(os.fstat(descriptor)) == before, 'HISTORICAL_READ_CHANGED')
                    c.require(not inode_flags(descriptor) & ~(0x80000 | 0x1000 | 0x20 | 0x10),
                              'HISTORICAL_UNSAFE_FLAGS')
                    watch = libc.inotify_add_watch(self.fd, os.fsencode('/proc/self/fd/'+str(descriptor)), 0x00000fce)
                    c.require(watch >= 0, 'HISTORICAL_WATCH_REQUIRED')
                    self.rows.append((path, before))
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        names = os.listdir(descriptor)
                        c.require(len(names) <= 65536, 'HISTORICAL_READ_BOUND')
                        pending.extend(path/name for name in names)
            self.check()
        except BaseException as error:
            c.close_preserving(error, self)
            raise

    def check(self):
        c.require(self.fd is not None and self.owner == os.getpid(), 'HISTORICAL_WITNESS_LOST')
        for path, expected in self.rows:
            actual = c.fingerprint(p.historical_metadata(path)) if path == self.root else node_metadata(path)
            c.require(actual == expected, 'HISTORICAL_READ_CHANGED')
        try: event = os.read(self.fd, 65536)
        except BlockingIOError: event = b''
        c.require(not event, 'HISTORICAL_READ_CHANGED')

    def read(self, leaf):
        path = self.root/leaf
        expected = next((value for node, value in self.rows if node == path), None)
        c.require(expected is not None and stat.S_ISREG(expected[5])
                  and 0 < expected[2] <= 65536, 'HISTORICAL_INPUT_UNAVAILABLE')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with c.descriptor_scope(fd):
            c.require(c.fingerprint(os.fstat(fd)) == expected, 'HISTORICAL_READ_CHANGED')
            value = bytearray()
            while len(value) < expected[2]:
                part = os.read(fd, expected[2]-len(value))
                c.require(bool(part), 'HISTORICAL_READ_UNAVAILABLE')
                value.extend(part)
            c.require(c.fingerprint(os.fstat(fd)) == expected, 'HISTORICAL_READ_CHANGED')
        self.check()
        return bytes(value)

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            with c.descriptor_scope(fd): pass

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


def git_read(args, *, input=None):
    # Never inherit provider credentials, Git config injection, hooks, replace
    # refs or an allowed remote transport. No output/errors are put in evidence.
    env = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C', GIT_OPTIONAL_LOCKS='0',
        GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
        GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='')
    try:
        result = subprocess.run(['/usr/bin/git', '--no-optional-locks', *args], input=input,
            capture_output=True, timeout=15, env=env)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise unavailable(error) from None
    c.require(result.returncode == 0, 'HISTORICAL_READ_UNAVAILABLE')
    return result.stdout


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
    raw = git_read(['config', '--no-includes', '--file', '/dev/stdin', '--null', '--list'],
                   input=witness.read('config'))
    for row in raw.split(b'\0'):
        if not row: continue
        key, sep, value = row.partition(b'\n')
        ordinary = key in {b'core.repositoryformatversion', b'core.filemode', b'core.bare',
            b'core.logallrefupdates', b'core.ignorecase', b'core.precomposeunicode'}
        reference = (key.startswith(b'remote.') and key.endswith((b'.url', b'.fetch'))) or \
                    (key.startswith(b'branch.') and key.endswith((b'.remote', b'.merge')))
        c.require(sep and (ordinary or reference), 'HISTORICAL_UNSAFE_CONFIG')
        if key == b'core.repositoryformatversion': c.require(value == b'0', 'HISTORICAL_UNSAFE_CONFIG')
        if key == b'core.bare': c.require(value == b'false', 'HISTORICAL_UNSAFE_CONFIG')
    witness.check()


def repository(root, expected):
    """Attest fixed HEAD, raw commit/tree object identities, and read interval.

    No physical inode predecessor or whole live-worktree equality is inferred.
    Missing bindings/access/object data is not a proven historical mutation.
    """
    root = Path(root)
    c.require(type(expected) is tuple and len(expected) == 2 and
              all(c.hex_value(value, 40) for value in expected), 'HISTORICAL_BINDING_UNAVAILABLE')
    try:
        with p.PathChain(root, leaf='.git', historical=True) as ancestry:
            guard = p.historical_metadata(root/'.git')
            real_git = root/'.git.s12-1-recovery'
            with p.PathChain(real_git, historical=True) as chain, GitReadWitness(real_git) as witness:
                git_config_safe(witness)
                args = ['-c', 'safe.directory='+str(root), '-c', 'core.fsmonitor=false',
                        '-c', 'core.hooksPath=/dev/null', '--git-dir='+str(real_git), '--work-tree='+str(root)]
                pair = tuple(git_read([*args, 'rev-parse', '--verify', ref]).strip().decode('ascii')
                             for ref in ('HEAD', 'HEAD^{tree}'))
                c.require(pair == expected, 'HISTORICAL_CONTENT_RED')
                for oid, kind in zip(expected, ('commit', 'tree')):
                    size = git_read([*args, 'cat-file', '-s', oid]).strip()
                    c.require(size.isdigit() and len(size) <= 8 and 0 < int(size) <= 4*1024*1024,
                              'HISTORICAL_OBJECT_BOUND')
                    witness.check(); chain.check(); ancestry.check()
                    payload = git_read([*args, 'cat-file', kind, oid])
                    c.require(len(payload) == int(size), 'HISTORICAL_READ_CHANGED')
                    digest = hashlib.sha1(kind.encode()+b' '+str(len(payload)).encode()+b'\0'+payload).hexdigest()
                    c.require(digest == oid, 'HISTORICAL_CONTENT_RED')
                    if kind == 'commit':
                        c.require(payload.startswith(b'tree '+expected[1].encode()+b'\n'), 'HISTORICAL_CONTENT_RED')
                    witness.check(); chain.check(); ancestry.check()
                c.require(c.fingerprint(p.historical_metadata(root/'.git')) == c.fingerprint(guard),
                          'HISTORICAL_READ_CHANGED')
            return dict(commit=pair[0], tree=pair[1], guard=list(c.fingerprint(guard)))
    except (OSError, UnicodeError) as error:
        raise unavailable(error) from None
