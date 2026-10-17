"""No-follow live bindings, create-only private objects and real restore copies.

Administrative/kernel roles are admitted elsewhere from actual, source-bound
observations. This module never accepts a flag claiming those gates passed.
"""
from __future__ import annotations

import base64
import ctypes
import fcntl
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import struct
import time

import tu1nz_public_operator_io as io

READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOATIME
DIR = READ | os.O_DIRECTORY


def security(row):
    out = {k: row[k] for k in ('device', 'inode', 'uid', 'gid', 'mode', 'type', 'attrs', 'flags')}
    if row['type'] == stat.S_IFDIR:
        out['flags'] &= ~(0x1000 | 0x80000)
    return out


class Paths:
    def __init__(self, entry, *, deadline):
        self.d = entry; self.deadline = deadline; self.rows = {}; self.events = None
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.events = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        io.require(self.events >= 0, 'PATH_WATCH_UNAVAILABLE')
        self.names = {}; self.self_watches = set(); self.failed = False
        self.get('/')

    def get(self, path):
        p = PurePosixPath(path)
        io.require(p.is_absolute() and '..' not in p.parts and str(p) == str(path), 'PATH_SCOPE')
        name = str(p)
        if name in self.rows:
            return self.rows[name][0]
        parent = self.get(str(p.parent)) if name != '/' else None
        self.check()  # drain previous bindings BEFORE admitting this new name
        fd = os.open(p.name, DIR, dir_fd=parent) if parent is not None else os.open('/', DIR)
        try:
            row = self.d.metadata(fd, staging_ancestor=name == '/opt/tu1nz_repos')
            self.rows[name] = (fd, row, parent, p.name)
            own = self.libc.inotify_add_watch(self.events, os.fsencode('/proc/self/fd/'+str(fd)), 0x2ec4)
            io.require(own >= 0, 'PATH_WATCH_UNAVAILABLE')
            self.self_watches.add(own)
            if parent is not None:
                wd = self.libc.inotify_add_watch(self.events, os.fsencode('/proc/self/fd/'+str(parent)), 0x2ec4)
                io.require(wd >= 0, 'PATH_WATCH_UNAVAILABLE')
                self.names.setdefault(wd, set()).add(p.name)
            self.check()
            return fd
        except BaseException:
            if name not in self.rows:
                os.close(fd)
            raise

    def check(self):
        try:
            io.require(not self.failed and time.monotonic() < self.deadline, 'PATH_FENCE_LOST')
            while True:
                try:
                    raw = os.read(self.events, 65536)
                except BlockingIOError:
                    break
                offset = 0
                while offset < len(raw):
                    wd, mask, _, count = struct.unpack_from('iIII', raw, offset)
                    name = raw[offset+16:offset+16+count].split(b'\0', 1)[0].decode()
                    io.require(not mask & (0x4000 | 0x2000 | 0x400 | 0x800 | 0x8000), 'PATH_WATCH_LOST')
                    io.require(not (mask & 4 and not name and wd in self.self_watches), 'PATH_METADATA_EVENT')
                    io.require(name not in self.names.get(wd, set()), 'PATH_RENAME_EVENT')
                    offset += 16+count
            for name, (fd, before, parent, leaf) in self.rows.items():
                row = self.d.metadata(fd, staging_ancestor=name == '/opt/tu1nz_repos')
                current = os.lstat('/') if parent is None else os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                io.require((current.st_dev, current.st_ino) == (before['device'], before['inode']) and
                           security(row) == security(before), 'PATH_SECURITY_OR_IDENTITY_CHANGED')
        except BaseException:
            self.failed = True
            raise

    def absent(self, path):
        p = PurePosixPath(path); fd = self.get(str(p.parent))
        try:
            os.stat(p.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            self.check()
            return
        raise io.Hold('PUBLIC_OPERATOR_OCCUPIED_NO_ADOPTION')

    def create_directory(self, path, mode=0o700):
        p = PurePosixPath(path)
        self.absent(path)
        self.d.new_directory(self.get(str(p.parent)), p.name, mode)
        fd = self.get(path)
        row = self.d.metadata(fd)
        io.require(row['uid'] == row['gid'] == 0 and row['mode'] == mode and not row['attrs'],
                   'NEW_PRIVATE_DIRECTORY_PROFILE')
        return fd

    def create_file(self, path, raw, mode=0o600):
        p = PurePosixPath(path); self.absent(path)
        self.d.new_file(self.get(str(p.parent)), p.name, raw, mode)
        value, row = self.d.stable_file(self.get(str(p.parent)), p.name)
        io.require(value == raw and row['uid'] == row['gid'] == 0 and row['mode'] == mode and
                   not row['attrs'], 'NEW_FILE_PROFILE')
        return row

    def read(self, path):
        p = PurePosixPath(path)
        value = self.d.stable_file(self.get(str(p.parent)), p.name)
        self.check()
        return value

    def quarantine(self, source, target, expected):
        s, t = PurePosixPath(source), PurePosixPath(target)
        raw, row = self.read(source)
        io.require(all(row[k] == expected[k] for k in row if k != 'atime_ns'), 'QUARANTINE_IDENTITY_CHANGED')
        self.absent(target)
        src = self.get(str(s.parent)); dst = self.get(str(t.parent))
        io.require(os.fstat(src).st_dev == os.fstat(dst).st_dev, 'QUARANTINE_CROSS_DEVICE')
        # The exact file is not a retained directory binding; moving it cannot
        # hide an ancestor event. No general expected-event suppression exists.
        self.d.rename_at(src, s.name, dst, t.name, 1)
        again, after = self.read(target)
        io.require(raw == again and all(after[k] == row[k] for k in row if k != 'ctime_ns'),
                   'QUARANTINE_POSTSTATE')
        self.check()
        return after

    def close(self):
        errors = []
        try:
            self.check()
        except BaseException as e:
            errors.append(getattr(e, 'primary', 'PUBLIC_BOOTSTRAP_PATH_CLOSE_UNCONFIRMED'))
        for fd, *_ in reversed(list(self.rows.values())):
            try:
                os.close(fd)
            except OSError as e:
                errors.append(type(e).__name__)
        self.rows.clear()
        if self.events is not None:
            os.close(self.events); self.events = None
        return errors


class Backup:
    """Protected source objects -> owned copies -> fresh independent restore.

    Source paths are selected by the exact authenticated baseline, never globbed
    into a widened mutation set. No original object is restored or normalized.
    """
    def __init__(self, paths, files, root, check):
        self.paths, self.files, self.root, self.check = paths, files, root, check
        self.manifest = None

    def create(self):
        p = self.paths
        before = p.create_directory(self.root+'/before')
        p.create_directory(self.root+'/restore-test')
        self.manifest = {}
        for index, path in enumerate(sorted(self.files)):
            self.check()
            raw, row = p.read(path)
            io.require(io.sha(raw) == self.files[path], 'BACKUP_INPUT_DRIFT')
            name = str(index).zfill(3)
            p.d.new_file(before, name, raw)
            reread, copied = p.d.stable_file(before, name)
            io.require(raw == reread and copied['uid'] == 0 and copied['mode'] == 0o600,
                       'BACKUP_INDEPENDENT_READBACK')
            self.manifest[path] = {'copy': name, 'sha256': io.sha(raw), 'original': row}
        p.d.new_file(before, 'manifest.json', io.canonical(self.manifest))
        io.require(p.d.stable_file(before, 'manifest.json')[0] == io.canonical(self.manifest),
                   'BACKUP_MANIFEST_READBACK')
        self.check()
        return io.sha(io.canonical(self.manifest))

    def restore_test(self):
        p = self.paths
        io.require(self.manifest is not None, 'BACKUP_REQUIRED')
        root = p.get(self.root+'/restore-test')
        p.d.new_directory(root, 'tree', 0o700)
        restored = os.open('tree', DIR, dir_fd=root)
        handles = {'/': restored}
        try:
            for path, row in sorted(self.manifest.items()):
                self.check(); pp = PurePosixPath(path)
                parent = PurePosixPath('/')
                for part in pp.parent.parts[1:]:
                    target = str(parent/part)
                    if target not in handles:
                        p.d.new_directory(handles[str(parent)], part, 0o700)
                        handles[target] = os.open(part, DIR, dir_fd=handles[str(parent)])
                    parent = parent/part
                raw, _ = p.d.stable_file(p.get(self.root+'/before'), row['copy'])
                io.require(io.sha(raw) == row['sha256'], 'RESTORE_COPY_CHANGED')
                p.d.new_file(handles[str(parent)], pp.name, raw)
                p.d.restore_metadata(handles[str(parent)], pp.name, row['original'])
                copied, actual = p.d.stable_file(handles[str(parent)], pp.name)
                expected = row['original']
                io.require(io.sha(copied) == row['sha256'] and
                           all(actual[k] == expected[k] for k in ('uid', 'gid', 'mode', 'attrs', 'mtime_ns')) and
                           actual['flags'] & ~p.d.PHYSICAL_FLAGS == expected['flags'] & ~p.d.PHYSICAL_FLAGS,
                           'RESTORE_CONTENT_OR_METADATA')
            p.d.rename_at(root, 'tree', root, 'tree-return', 1)
            p.d.rename_at(root, 'tree-return', root, 'tree', 1)
            io.require(os.stat('tree', dir_fd=root, follow_symlinks=False).st_ino == os.fstat(restored).st_ino,
                       'RESTORE_RENAME_RETURN')
            self.check()
        finally:
            for fd in handles.values():
                os.close(fd)
        return io.sha(io.canonical(self.manifest))
