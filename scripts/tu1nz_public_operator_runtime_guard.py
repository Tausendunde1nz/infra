"""Current protected runtime reading, not historical metadata provenance.

Expected bytes come from the independently bound release/reference artifact.
Tracked Application bytes are additionally checked against canonical local Git
by the client. No current server hash can manufacture that reference. Defaults
are read eligibility only, never a creation or normalization permission.
"""
import base64
import ctypes
import fcntl
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import time

import tu1nz_public_operator_io as io

ROOT = '/opt/tu1nz_repos/adult-publishing-core'
APP_PIN = ('93555d8a141caf8ace33522f9340d30bfc47d2bb', '1e8a644115127818f394b6f9d24f31826e04ecba')
EXCLUDED = {'.git', '.git.s12-1-recovery'}
DEFAULT_SHA = 'ee5723ea29015f2982fcbef933358c14995db738d69bf15e3ad6d3718b8e4617'
# Offline schema/reference tooling may import on the Mac. Absence here never
# admits a runtime read: the constructor explicitly requires native Linux.
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, 'O_NOATIME', 0)


def metadata(entry, fd):
    s = os.fstat(fd); attrs = {}
    for name in os.listxattr(fd):
        raw = os.getxattr(fd, name)
        io.require(len(raw) <= 65536, 'RUNTIME_ATTRIBUTE_BOUND')
        if name == 'system.posix_acl_default':
            io.require(stat.S_ISDIR(s.st_mode) and io.sha(raw) == DEFAULT_SHA, 'RUNTIME_DEFAULT_PROFILE_UNKNOWN')
        elif name == 'system.posix_acl_access': entry.acl(raw)
        else: io.require(name.startswith('user.'), 'RUNTIME_SECURITY_ATTRIBUTE_UNKNOWN')
        attrs[name] = base64.b64encode(raw).decode()
    mask = 0o002 if 'system.posix_acl_access' in attrs else 0o022
    flags = struct.unpack('I', fcntl.ioctl(fd, entry.F_GETFLAGS, struct.pack('I', 0)))[0]
    io.require(s.st_uid == 0 and not s.st_mode & mask and not s.st_mode & 0o4000 and
               (stat.S_ISDIR(s.st_mode) or not s.st_mode & 0o2000) and
               not flags & ~(entry.PHYSICAL_FLAGS | 0x10 | 0x20), 'RUNTIME_EFFECTIVE_WRITER_OR_FLAGS')
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns, attrs, flags)


def writer_task(root, targets, deadline):
    """Measure one task's own file table, including unshared non-leaders."""
    raw = (root/'stat').read_text(); tick = raw[raw.rfind(')')+2:].split()[19]
    descriptors = {}; count = 0
    # Keep the directory stream alive while reading its entries. In our own
    # task that stream is itself an FD; closing it before stat would fabricate
    # an unreadable descriptor. No disappearing foreign FD is silently skipped.
    with os.scandir(root/'fd') as entries:
        for entry in entries:
            count += 1
            io.require(count <= 8192 and time.monotonic() < deadline, 'WRITER_DESCRIPTOR_BOUND_OR_DEADLINE')
            s = entry.stat(follow_symlinks=True)
            if (s.st_dev, s.st_ino) in targets:
                info = dict(x.split(':', 1) for x in (root/'fdinfo'/entry.name).read_text().splitlines() if ':' in x)
                access = int(info['flags'].strip(), 8) & os.O_ACCMODE
                io.require(access == os.O_RDONLY, 'EXISTING_SOURCE_WRITABLE_FD')
                again = (root/'fd'/entry.name).stat()  # not DirEntry's cached stat
                io.require((s.st_dev, s.st_ino) == (again.st_dev, again.st_ino), 'WRITER_DESCRIPTOR_CHANGED')
                descriptors[entry.name] = (s.st_dev, s.st_ino, access)
    mappings = []
    with (root/'maps').open() as source: raw = source.read(8*1024*1024+1)
    io.require(len(raw) <= 8*1024*1024, 'WRITER_MAPPING_BOUND')
    for line in raw.splitlines():
        v = line.split(None, 5); major, minor = (int(n, 16) for n in v[3].split(':'))
        if (os.makedev(major, minor), int(v[4])) in targets:
            io.require(not (v[1][1] == 'w' and v[1][3] == 's'), 'EXISTING_SOURCE_SHARED_WRITABLE_MAPPING')
            mappings.append(tuple(v[:5]))
    again = (root/'stat').read_text()
    io.require(again[again.rfind(')')+2:].split()[19] == tick, 'WRITER_SUBJECT_CHANGED')
    return tick, descriptors, mappings


def writer_check(targets, deadline):
    """Actual existing FD/shared-mapping write authority, including TCB actors.

    A private COW data mapping cannot write back to its source file. It is not
    called absence of writable process memory. The stricter Site owner guard
    remains unchanged and independently checks ALL82 leased files.
    """
    pids = [n for n in os.listdir('/proc') if n.isdecimal()]
    io.require(len(pids) <= 8192, 'WRITER_PROCESS_BOUND')
    tasks_seen = 0
    for name in pids:
        io.require(time.monotonic() < deadline, 'WRITER_SCAN_DEADLINE')
        root = Path('/proc')/name
        try:
            fields = dict(x.split(':', 1) for x in (root/'status').read_text().splitlines() if ':' in x)
            raw = (root/'stat').read_text(); tick = raw[raw.rfind(')')+2:].split()[19]
        except (FileNotFoundError, ProcessLookupError): continue  # exited before admission
        except PermissionError: raise io.Hold('PUBLIC_OPERATOR_WRITER_VIEW_UNKNOWN') from None
        try:
            if fields.get('Kthread', '').strip() == '1': continue
            task_root = root/'task'; names = sorted(os.listdir(task_root))
            tasks_seen += len(names)
            io.require(name in names and 1 <= len(names) <= 8192 and tasks_seen <= 32768 and
                       all(n.isdecimal() for n in names), 'WRITER_THREAD_BOUND_OR_SET_UNKNOWN')
            before = {n: writer_task(task_root/n, targets, deadline) for n in names}
            io.require(sorted(os.listdir(task_root)) == names, 'WRITER_THREAD_SET_CHANGED')
            for n in names:
                io.require(writer_task(task_root/n, targets, deadline) == before[n], 'WRITER_THREAD_VIEW_CHANGED')
            io.require(sorted(os.listdir(task_root)) == names, 'WRITER_THREAD_SET_CHANGED')
            again = (root/'stat').read_text()
            io.require(again[again.rfind(')')+2:].split()[19] == tick, 'WRITER_SUBJECT_CHANGED')
        except (OSError, ValueError, KeyError, IndexError):
            raise io.Hold('PUBLIC_OPERATOR_WRITER_VIEW_UNKNOWN') from None


class RuntimeFence:
    def __init__(self, reference, paths, origins, *, python_binary, deadline):
        io.require(sys.platform == 'linux' and hasattr(os, 'O_NOATIME'), 'RUNTIME_NATIVE_LINUX_REQUIRED')
        io.require(set(reference) == {'schema', 'commit', 'tree', 'origin_sha256', 'objects'} and
                   reference['schema'] == 'TU1NZ_PUBLIC_RUNTIME_REFERENCE_V1' and
                   (reference['commit'], reference['tree']) == APP_PIN and reference['origin_sha256'] in origins,
                   'AUTHENTIC_RUNTIME_REFERENCE_REQUIRED')
        self.expected, self.paths, self.deadline = reference['objects'], paths, deadline
        self.events = self.fd = self.root_before = None; self.identities = {}; self.files = set(); self.broken = False
        self.bytes = 0; self.python = python_binary
        io.require(type(self.expected) is dict and 0 < len(self.expected) <= 32768 and
                   {'.', 'src', '.venv', '.venv/bin/tu1nz-public-s7', '.venv/bin/tu1nz-public-s8-landing',
                    '.venv/bin/python', 'src/tu1nz_exposure_s10/runtime.py'} <= set(self.expected),
                   'RUNTIME_INVENTORY_INCOMPLETE')
        for rel in self.expected:
            p = PurePosixPath(rel)
            io.require(not p.is_absolute() and '..' not in p.parts and str(p) == rel and
                       (not p.parts or p.parts[0] not in EXCLUDED), 'RUNTIME_REFERENCE_PATH')
        self.libc = ctypes.CDLL(None, use_errno=True)
        try:
            self.events = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            io.require(self.events >= 0, 'RUNTIME_WATCH_UNAVAILABLE')
            self.parent = paths.get('/opt/tu1nz_repos')
            self.fd = os.open('adult-publishing-core', READ | os.O_DIRECTORY, dir_fd=self.parent)
            self.root_before = metadata(paths.d, self.fd)
            self._watch(self.fd)
            observed = {'.': {'kind': 'directory'}}
            self._walk(self.fd, '.', observed, 0)
            io.require(observed == self.expected, 'RUNTIME_CONTENT_OR_NAMESPACE_DRIFT')
            self.digest = io.sha(io.canonical(observed)); self.check()
        except BaseException as error:
            error._runtime_cleanup = tuple(self.close())
            raise

    def _watch(self, fd):
        wd = self.libc.inotify_add_watch(self.events, os.fsencode('/proc/self/fd/'+str(fd)), 0x00002fce)
        io.require(wd >= 0, 'RUNTIME_WATCH_UNAVAILABLE')

    def _walk(self, fd, rel, result, depth):
        io.require(depth < 32 and time.monotonic() < self.deadline, 'RUNTIME_CAPTURE_BOUND')
        before = metadata(self.paths.d, fd)
        for name in sorted(os.listdir(fd)):
            if rel == '.' and name in EXCLUDED: continue
            key = name if rel == '.' else rel+'/'+name
            io.require(key in self.expected and len(result) < 32768, 'UNBOUND_RUNTIME_OBJECT')
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(s.st_mode):
                io.require(s.st_uid == 0 and not os.listxattr('/proc/self/fd/'+str(fd)+'/'+name,
                           follow_symlinks=False), 'RUNTIME_SYMLINK_OWNER_OR_ATTRIBUTE')
                target = os.readlink(name, dir_fd=fd)
                resolved = (Path(ROOT)/key).resolve(strict=True)
                io.require(resolved.is_relative_to(ROOT) or
                           str(resolved) == self.python and PurePosixPath(key).name in ('python', 'python3', 'python3.12'),
                           'RUNTIME_LINK_ESCAPE')
                result[key] = {'kind': 'link', 'target': target}
                self.identities[key] = (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns)
                continue
            child = os.open(name, READ | (os.O_DIRECTORY if stat.S_ISDIR(s.st_mode) else 0), dir_fd=fd)
            try:
                m = metadata(self.paths.d, child); self._watch(child)
                io.require((s.st_dev, s.st_ino) == m[:2], 'RUNTIME_OBJECT_CHANGED')
                if stat.S_ISDIR(s.st_mode):
                    result[key] = {'kind': 'directory'}; self._walk(child, key, result, depth+1)
                else:
                    io.require(stat.S_ISREG(s.st_mode) and 0 <= s.st_size <= 32*1024*1024 and s.st_nlink == 1,
                               'RUNTIME_FILE_TYPE_OR_BOUND')
                    self.bytes += s.st_size; io.require(self.bytes <= 512*1024*1024, 'RUNTIME_BYTES_BOUND')
                    raw = os.pread(child, s.st_size+1, 0)
                    io.require(len(raw) == s.st_size, 'RUNTIME_SHORT_READ')
                    result[key] = {'kind': 'file', 'sha256': io.sha(raw)}
                    self.files.add((s.st_dev, s.st_ino))
                io.require(metadata(self.paths.d, child) == m, 'RUNTIME_CHANGED_DURING_READ')
                again = os.stat(name, dir_fd=fd, follow_symlinks=False)
                io.require((again.st_dev, again.st_ino, again.st_mtime_ns, again.st_ctime_ns) ==
                           (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns), 'RUNTIME_NAME_CHANGED')
                self.identities[key] = m
            finally: os.close(child)
        io.require(metadata(self.paths.d, fd) == before, 'RUNTIME_DIRECTORY_CHANGED_DURING_READ')

    def check(self):
        try:
            io.require(not self.broken and time.monotonic() < self.deadline, 'RUNTIME_FENCE_LOST')
            raw = os.read(self.events, 65536) if self.events is not None else b'BROKEN'
        except BlockingIOError: raw = b''
        except BaseException:
            self.broken = True; raise
        try:
            io.require(not raw, 'RUNTIME_WRITE_METADATA_OR_NAMESPACE_EVENT')
            current = os.stat('adult-publishing-core', dir_fd=self.parent, follow_symlinks=False)
            io.require((current.st_dev, current.st_ino) == self.root_before[:2] and
                       metadata(self.paths.d, self.fd) == self.root_before, 'RUNTIME_ROOT_REPLACED')
            self.paths.check()
        except BaseException:
            self.broken = True; raise

    def close(self):
        errors = []
        if self.fd is not None and self.events is not None and self.root_before is not None:
            try: self.check()
            except BaseException as error: errors.append(getattr(error, 'primary', 'PUBLIC_BOOTSTRAP_RUNTIME_CLOSE_UNKNOWN'))
        for name in ('fd', 'events'):
            fd = getattr(self, name)
            if fd is not None:
                try: os.close(fd)
                except OSError: errors.append('PUBLIC_BOOTSTRAP_RUNTIME_DESCRIPTOR_CLOSE_UNKNOWN')
                setattr(self, name, None)
        return errors
