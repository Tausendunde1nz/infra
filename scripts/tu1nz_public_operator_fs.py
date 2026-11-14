"""No-follow live bindings, create-only private objects and real restore copies.

Administrative/kernel roles are admitted elsewhere from actual, source-bound
observations. This module never accepts a flag claiming those gates passed.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
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


OWNED_FILE_FIELDS = frozenset(('device', 'inode', 'uid', 'gid', 'mode', 'type', 'nlink',
                              'size', 'mtime_ns', 'ctime_ns', 'atime_ns', 'attrs', 'flags'))


def owned_file_matches(raw, actual, expected, *, moved):
    """Validate a complete READY-bound inode; never adopt a partial object.

    A current moved inode has a new real ctime, which is returned to the caller
    for its NEW observation. It is not an ACK for any earlier rename. Once a
    post-rename record exists the caller additionally binds that actual ctime.
    No bytes, mode, ownership, mtime, xattrs or flags may be repaired here.
    """
    io.require(type(expected) is dict and set(expected) == {'sha256', 'metadata'} and
               type(expected['metadata']) is dict and set(expected['metadata']) == OWNED_FILE_FIELDS,
               'OWNED_READY_FILE_SCHEMA')
    before = expected['metadata']
    io.require(all(type(row[k]) is int and 0 <= row[k] < 2**64
                   for row in (before, actual) if type(row) is dict and set(row) == OWNED_FILE_FIELDS
                   for k in OWNED_FILE_FIELDS-{'attrs'}), 'OWNED_FILE_METADATA_TYPES')
    io.require(type(raw) is bytes and type(actual) is dict and set(actual) == OWNED_FILE_FIELDS and
               before['type'] == actual['type'] == stat.S_IFREG and
               before['nlink'] == actual['nlink'] == 1 and
               before['uid'] == before['gid'] == actual['uid'] == actual['gid'] == 0 and
               before['mode'] in (0o555, 0o600, 0o644) and before['attrs'] == {} and
               before['flags'] in (0, 0x80000) and
               io.sha(raw) == expected['sha256'] and len(raw) == before['size'],
               'OWNED_COMPLETE_FILE_REQUIRED')
    ignored = {'atime_ns', 'ctime_ns'} if moved else {'atime_ns'}
    io.require(all(actual[k] == before[k] for k in OWNED_FILE_FIELDS-ignored),
               'OWNED_FILE_IDENTITY_OR_METADATA_CHANGED')
    if moved:
        io.require(type(actual['ctime_ns']) is int and actual['ctime_ns'] >= before['ctime_ns'],
                   'OWNED_RENAME_CTIME_INVALID')
    return {'sha256': expected['sha256'], 'metadata': actual,
            'ctime_basis': 'CURRENT_RENAME_OBSERVATION' if moved else 'EXACT_READY_CANDIDATE'}


class Paths:
    def __init__(self, entry, *, deadline):
        self.d = entry; self.deadline = deadline; self.rows = {}; self.events = None
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.events = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        io.require(self.events >= 0, 'PATH_WATCH_UNAVAILABLE')
        self.names = {}; self.self_watches = set(); self.failed = False
        self._read_depth=0;self.census_cleanup=[]
        self.get('/')

    def get(self, path):
        p = PurePosixPath(path)
        io.require(p.is_absolute() and '..' not in p.parts and str(p) == str(path), 'PATH_SCOPE')
        name = str(p)
        if name in self.rows:
            return self.rows[name][0]
        parent = self.get(str(p.parent)) if name != '/' else None
        self.check(full=True)  # new name admissions always recheck ALL parents
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
            self.check(full=True)
            return fd
        except BaseException:
            if name not in self.rows:
                os.close(fd)
            raise

    @contextmanager
    def read_census(self):
        """One no-effect interval, not a previous-GREEN cache.

        Every nested check still drains/latches events and enforces deadline.
        Full fresh parent metadata/name checks bracket the whole read census.
        New bindings always force full checks; mutation/close APIs are barred.
        Only the reviewed R5 Authority's read-only check uses this context.
        """
        before=self._read_depth
        io.require(0<=before<64,'PATH_READ_CENSUS_SCOPE')
        self.check(full=before==0)
        primary=None
        try:
            self._read_depth=before+1
            yield
        except BaseException as error:
            primary=error
            raise
        finally:
            self._read_depth=before
            if before==0:
                try:self.check(full=True)
                except BaseException as closing:
                    if primary is None:raise
                    # Preserve the original error. Closing loss remains latched
                    # and is separately reported by the ordinary Paths.close.
                    self.failed=True
                    self.census_cleanup.append(getattr(closing,'primary',
                        'PUBLIC_OPERATOR_PATH_CENSUS_CLOSE_UNKNOWN'))

    def check(self, *, full=False):
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
            if self._read_depth and not full:
                # inode flag ioctls do not have the same notification contract
                # as chmod/chown/ACL/xattr and rename. Retain their fresh
                # point checks too; never infer flags from an empty queue.
                for fd,before,*_ in self.rows.values():
                    flags=struct.unpack('I',fcntl.ioctl(fd,self.d.F_GETFLAGS,struct.pack('I',0)))[0]
                    if before['type']==stat.S_IFDIR:flags&=~(0x1000|0x80000)
                    io.require(flags==security(before)['flags'],'PATH_FLAGS_CHANGED')
                return  # events and flags were NOT deferred
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
        io.require(self._read_depth==0,'PATH_EFFECT_DURING_READ_CENSUS')
        p = PurePosixPath(path)
        self.absent(path)
        self.d.new_directory(self.get(str(p.parent)), p.name, mode)
        fd = self.get(path)
        row = self.d.metadata(fd)
        io.require(row['uid'] == row['gid'] == 0 and row['mode'] == mode and not row['attrs'],
                   'NEW_PRIVATE_DIRECTORY_PROFILE')
        return fd

    def create_file(self, path, raw, mode=0o600):
        io.require(self._read_depth==0,'PATH_EFFECT_DURING_READ_CENSUS')
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
        io.require(self._read_depth==0,'PATH_EFFECT_DURING_READ_CENSUS')
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

    def classify_owned_pair(self, candidate, target, expected, *, quarantine=None):
        """Exactly one complete own file at one of the fixed bound names.

        The maintenance adapter supplies its compiled ten-file mapping and
        authenticated READY metadata. This function grants no arbitrary path
        permissions and performs no mutation or historical ACK reconstruction.
        Missing parents, unreadable names, two names or symlinks are UNKNOWN/
        HOLD, not an absence that authorizes repair.
        """
        self.check(full=True)
        places = {'candidate': candidate, 'target': target}
        if quarantine is not None:
            places['quarantine'] = quarantine
        io.require(len(set(places.values())) == len(places), 'OWNED_PAIR_DISTINCT_NAMES')
        present = []
        for place, name in places.items():
            path = PurePosixPath(name)
            io.require(path.is_absolute() and '..' not in path.parts and str(path) == name,
                       'OWNED_PAIR_PATH')
            parent = self.get(str(path.parent))
            try:
                row = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            io.require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1, 'OWNED_PAIR_NOT_SINGLE_REGULAR')
            raw, actual = self.d.stable_file(parent, path.name)
            proof = owned_file_matches(raw, actual, expected, moved=place != 'candidate')
            present.append({'place': place, 'path': name, **proof})
        io.require(len(present) == 1, 'OWNED_PAIR_MISSING_OR_DUPLICATED')
        # A second no-follow name census detects a new/removed partner during
        # classification. Full relevant Writer fences remain an outer gate.
        selected = present[0]
        for place, name in places.items():
            path = PurePosixPath(name); parent = self.get(str(path.parent))
            if place != selected['place']:
                self.absent(name)
            else:
                raw, actual = self.d.stable_file(parent, path.name)
                owned_file_matches(raw, actual, expected, moved=place != 'candidate')
                io.require(all(actual[k] == selected['metadata'][k] for k in OWNED_FILE_FIELDS-{'atime_ns'}),
                           'OWNED_PAIR_CHANGED_DURING_CENSUS')
        self.check(full=True)
        return selected

    def publish_owned_candidate(self, candidate, target, expected):
        """One atomic no-replace move of a complete candidate, never a write.

        Caller must durably record its action intent before entering. A lost
        rename/fsync/ACK ends this action; no retry or cleanup delete is made.
        A later permitted recovery may only classify the actual two names.
        """
        io.require(self._read_depth == 0, 'PATH_EFFECT_DURING_READ_CENSUS')
        before = self.classify_owned_pair(candidate, target, expected)
        io.require(before['place'] == 'candidate', 'OWNED_PUBLICATION_ALREADY_EFFECTIVE_NO_REPLAY')
        source, dest = PurePosixPath(candidate), PurePosixPath(target)
        src, dst = self.get(str(source.parent)), self.get(str(dest.parent))
        io.require(os.fstat(src).st_dev == os.fstat(dst).st_dev == expected['metadata']['device'],
                   'OWNED_PUBLICATION_CROSS_DEVICE')
        self.d.rename_at(src, source.name, dst, dest.name, 1)  # RENAME_NOREPLACE, fsync both parents
        after = self.classify_owned_pair(candidate, target, expected)
        io.require(after['place'] == 'target', 'OWNED_PUBLICATION_POSTSTATE_UNKNOWN')
        # Rename changes directory timestamps too. Preserve the actual rows in
        # the new receipt; do not manufacture the pre-rename ctime or suppress
        # the existing ancestor security/event checks.
        after['parents'] = {str(source.parent): self.d.metadata(src),
                            str(dest.parent): self.d.metadata(dst)}
        self.check(full=True)
        return after

    def close(self):
        io.require(self._read_depth==0,'PATH_CLOSE_DURING_READ_CENSUS')
        errors = list(self.census_cleanup)
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

    def load_verified_existing(self, *, expected_sha256=None):
        """Freshly read a COMPLETE original backup and restored file tree.

        Read-only, no completion of partial files, no historical ACK repair.
        The caller separately classifies the original failure: a negative
        integrity/probe result cannot be overruled by invoking this reader.
        Missing/incomplete evidence raises; only explicit N5 admission can
        choose the one fixed new recovery copy/test, using create()/restore_test().
        This is a file restore witness, never a database restore or rollback.
        """
        io.require(self.manifest is None and self.root in (
            '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1',
            '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1/recovery-once') and
            type(self.files) is dict and 0 < len(self.files) <= 256,
            'EXISTING_BACKUP_FIXED_SCOPE')
        self.check(); p = self.paths
        before = p.get(self.root+'/before'); restored_parent = p.get(self.root+'/restore-test')
        for fd in (before, restored_parent):
            row = p.d.metadata(fd)
            io.require(row['uid'] == row['gid'] == 0 and row['mode'] == 0o700 and not row['attrs'],
                       'EXISTING_BACKUP_PRIVATE_PROFILE')
        raw, record = p.d.stable_file(before, 'manifest.json')
        manifest = io.parse(raw); digest = io.sha(raw)
        io.require(type(manifest) is dict and set(manifest) == set(self.files) and
                   io.canonical(manifest) == raw and
                   (expected_sha256 is None or expected_sha256 == digest), 'EXISTING_BACKUP_MANIFEST_BINDING')
        io.require(record['uid'] == record['gid'] == 0 and record['mode'] == 0o600 and
                   record['nlink'] == 1 and not record['attrs'], 'EXISTING_BACKUP_MANIFEST_PROFILE')
        expected_copies = {'manifest.json'}
        tree = self.root+'/restore-test/tree'; directories = {tree: set()}
        for index, path in enumerate(sorted(self.files)):
            self.check(); source = PurePosixPath(path); item = manifest[path]
            io.require(source.is_absolute() and str(source) == path and '..' not in source.parts and
                       len(source.parts) <= 32 and type(item) is dict and
                       set(item) == {'copy', 'sha256', 'original'} and item['copy'] == str(index).zfill(3) and
                       item['sha256'] == self.files[path] and type(item['original']) is dict and
                       set(item['original']) == OWNED_FILE_FIELDS, 'EXISTING_BACKUP_ITEM_BINDING')
            original, current = p.read(path)
            io.require(io.sha(original) == self.files[path] and
                       all(current[k] == item['original'][k] for k in OWNED_FILE_FIELDS-{'atime_ns'}),
                       'EXISTING_BACKUP_SOURCE_NOT_CURRENT')
            copied, copy_row = p.d.stable_file(before, item['copy'])
            io.require(copied == original and copy_row['uid'] == copy_row['gid'] == 0 and
                       copy_row['mode'] == 0o600 and copy_row['nlink'] == 1 and not copy_row['attrs'] and
                       not copy_row['flags'] & ~p.d.PHYSICAL_FLAGS, 'EXISTING_BACKUP_COPY_CHANGED')
            expected_copies.add(item['copy'])
            parent = tree
            for part in source.parts[1:-1]:
                directories[parent].add(part); parent += '/'+part
                directories.setdefault(parent, set())
            directories[parent].add(source.name)
            restored, actual = p.read(parent+'/'+source.name)
            wanted = item['original']
            io.require(restored == original and actual['nlink'] == 1 and
                       all(actual[k] == wanted[k] for k in ('uid', 'gid', 'mode', 'attrs', 'mtime_ns')) and
                       actual['flags'] & ~p.d.PHYSICAL_FLAGS == wanted['flags'] & ~p.d.PHYSICAL_FLAGS,
                       'EXISTING_RESTORE_CONTENT_OR_METADATA_CHANGED')
        io.require(set(os.listdir(before)) == expected_copies and
                   set(os.listdir(restored_parent)) == {'tree'}, 'EXISTING_BACKUP_OR_RESTORE_EXTRA_OBJECT')
        for path, names in directories.items():
            self.check(); fd = p.get(path); row = p.d.metadata(fd)
            io.require(row['uid'] == row['gid'] == 0 and row['mode'] == 0o700 and not row['attrs'] and
                       set(os.listdir(fd)) == names, 'EXISTING_RESTORE_TREE_CHANGED')
        again, after = p.d.stable_file(before, 'manifest.json')
        io.require(again == raw and all(after[k] == record[k] for k in OWNED_FILE_FIELDS-{'atime_ns'}),
                   'EXISTING_BACKUP_MANIFEST_CHANGED_DURING_READ')
        self.check(); self.manifest = manifest
        return {'manifest_sha256': digest, 'scope_files_sha256': io.sha(io.canonical(self.files)),
                'current_copies_and_restored_metadata_verified': True,
                'historical_ack_reconstructed': False, 'live_or_database_restore': False}

    def classify_original_for_recovery(self):
        """Read the old fixed private copy/test, without finishing or repairing it.

        Only absent objects or exact byte prefixes in the compiled copy/tree
        layout qualify as an interrupted private copy. Wrong bytes, extra
        names, unsafe metadata, unexplained manifest bytes, or source drift
        remain HOLD. The caller must ALSO reject recorded negative findings.
        A truncated manifest qualifies only as an exact canonical prefix of
        ALL current bound source metadata, after all copies and before any
        restore object. It is left unchanged and never parsed as a receipt.
        """
        io.require(self.manifest is None and self.root ==
                   '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1' and
                   0 < len(self.files) <= 256, 'RECOVERY_PARTIAL_BACKUP_SCOPE')
        self.check(); p = self.paths; source = {}; expected_names = {}
        for index, path in enumerate(sorted(self.files)):
            self.check(); raw, row = p.read(path)
            io.require(io.sha(raw) == self.files[path], 'RECOVERY_BACKUP_CURRENT_SOURCE_DRIFT')
            source[path] = (raw, row); expected_names[str(index).zfill(3)] = path
        def directory(path):
            parent, name = str(PurePosixPath(path).parent), PurePosixPath(path).name
            try:os.stat(name, dir_fd=p.get(parent), follow_symlinks=False)
            except FileNotFoundError:
                p.absent(path); return None
            fd = p.get(path); row = p.d.metadata(fd)
            io.require(row['uid'] == row['gid'] == 0 and row['mode'] == 0o700 and not row['attrs'],
                       'RECOVERY_PARTIAL_BACKUP_DIRECTORY_PROFILE')
            return fd
        before = directory(self.root+'/before'); restore = directory(self.root+'/restore-test')
        io.require(restore is None or before is not None, 'RECOVERY_RESTORE_WITH_LOST_ORIGINAL_BACKUP_DIRECTORY')
        complete = before is not None and restore is not None
        manifest = None; observed = []
        if before is not None:
            names = set(os.listdir(before))
            io.require(names <= set(expected_names) | {'manifest.json'}, 'RECOVERY_PARTIAL_BACKUP_EXTRA_OBJECT')
            for name in sorted(names-{'manifest.json'}):
                self.check(); raw, row = p.d.stable_file(before, name)
                wanted, _ = source[expected_names[name]]
                io.require(row['uid'] == row['gid'] == 0 and row['mode'] == 0o600 and
                           row['nlink'] == 1 and not row['attrs'] and not row['flags'] & ~p.d.PHYSICAL_FLAGS and
                           len(raw) <= len(wanted) and wanted.startswith(raw), 'RECOVERY_PRIVATE_COPY_NEGATIVE_CONTENT')
                complete = complete and raw == wanted
                observed.append({'copy': name, 'sha256': io.sha(raw), 'bytes': len(raw)})
            complete = complete and names == set(expected_names) | {'manifest.json'}
            if 'manifest.json' in names:
                raw, row = p.d.stable_file(before, 'manifest.json')
                io.require(row['uid'] == row['gid'] == 0 and row['mode'] == 0o600 and row['nlink'] == 1 and
                           not row['attrs'] and not row['flags'] & ~p.d.PHYSICAL_FLAGS,
                           'RECOVERY_EXISTING_MANIFEST_PROFILE')
                expected_raw = io.canonical({path: {'copy': name, 'sha256': self.files[path],
                                                    'original': source[path][1]}
                                             for name,path in expected_names.items()})
                if len(raw) < len(expected_raw) and expected_raw.startswith(raw):
                    # No permissive JSON parser or rewritten manifest. Even
                    # an atime difference prevents this exact prefix proof.
                    io.require(restore is not None and not os.listdir(restore),
                               'RECOVERY_PARTIAL_MANIFEST_WITH_LATER_RESTORE')
                    complete = False
                else:
                    value = io.parse(raw)
                    io.require(type(value) is dict and set(value) == set(source) and io.canonical(value) == raw,
                               'RECOVERY_EXISTING_MANIFEST_INCOMPLETE_OR_INVALID')
                    for name, path in expected_names.items():
                        item = value[path]; original = source[path][1]
                        io.require(type(item) is dict and set(item) == {'copy', 'sha256', 'original'} and
                                   item['copy'] == name and item['sha256'] == self.files[path] and
                                   type(item['original']) is dict and set(item['original']) == OWNED_FILE_FIELDS and
                                   all(item['original'][k] == original[k] for k in OWNED_FILE_FIELDS-{'atime_ns'}),
                                   'RECOVERY_EXISTING_MANIFEST_SOURCE_MISMATCH')
                    manifest = value
                # The original code writes the manifest only AFTER all copies
                # passed readback. Missing/truncated copies now are a concrete
                # integrity contradiction, not an interrupted pre-manifest copy.
                io.require(names == set(expected_names) | {'manifest.json'} and all(
                    v['sha256'] == self.files[expected_names[v['copy']]] for v in observed),
                    'RECOVERY_MANIFEST_WITH_LOST_OR_CHANGED_COPIES')
        if restore is not None:
            names = set(os.listdir(restore))
            io.require(names <= {'tree', 'tree-return'} and len(names) <= 1,
                       'RECOVERY_PARTIAL_RESTORE_EXTRA_OR_DUPLICATE_TREE')
            complete = complete and names == {'tree'}
            if names:
                io.require(manifest is not None, 'RECOVERY_RESTORE_WITHOUT_COMPLETE_BACKUP_MANIFEST')
                name = next(iter(names)); tree = self.root+'/restore-test/'+name
                expected_dirs = {'': set()}; expected_files = {}
                for path in source:
                    parts = PurePosixPath(path).parts[1:]; parent = ''
                    for part in parts[:-1]:
                        expected_dirs[parent].add(part); parent = parent+'/'+part if parent else part
                        expected_dirs.setdefault(parent, set())
                    expected_dirs[parent].add(parts[-1]); expected_files['/'.join(parts)] = path
                visited = set()
                def walk(relative):
                    nonlocal complete
                    self.check(); path = tree+('/'+relative if relative else ''); fd = directory(path)
                    io.require(fd is not None, 'RECOVERY_RESTORE_DIRECTORY_VANISHED')
                    actual_names = set(os.listdir(fd))
                    io.require(actual_names <= expected_dirs[relative], 'RECOVERY_PARTIAL_RESTORE_FOREIGN_NAME')
                    for leaf in sorted(actual_names):
                        rel = relative+'/'+leaf if relative else leaf
                        if rel in expected_dirs:walk(rel); continue
                        original_path = expected_files[rel]; wanted, current = source[original_path]
                        raw, row = p.d.stable_file(fd, leaf); visited.add(original_path)
                        io.require(row['uid'] == 0 and row['gid'] in (0, current['gid']) and
                                   row['mode'] in (0o600, current['mode']) and row['nlink'] == 1 and
                                   all(k in current['attrs'] and current['attrs'][k] == v for k,v in row['attrs'].items()) and
                                   not row['flags'] & ~p.d.PHYSICAL_FLAGS and
                                   len(raw) <= len(wanted) and wanted.startswith(raw),
                                   'RECOVERY_PRIVATE_RESTORE_NEGATIVE_CONTENT_OR_METADATA')
                        complete = complete and raw == wanted and all(row[k] == current[k] for k in
                            ('uid', 'gid', 'mode', 'attrs', 'mtime_ns')) and (
                            row['flags'] & ~p.d.PHYSICAL_FLAGS == current['flags'] & ~p.d.PHYSICAL_FLAGS)
                    io.require(set(os.listdir(fd)) == actual_names, 'RECOVERY_PARTIAL_RESTORE_CHANGED')
                walk(''); complete = complete and visited == set(source)
        self.check()
        if complete:
            proof = self.load_verified_existing()
            return {'state': 'COMPLETE_CURRENT_COPY_AND_RESTORE', **proof}
        return {'state': 'INCOMPLETE_PRIVATE_COPY_REQUIRES_NEW_FIXED_TEST',
                'scope_files_sha256': io.sha(io.canonical(self.files)),
                'private_copy_inventory_sha256': io.sha(io.canonical(observed)),
                'old_objects_changed': False, 'old_restore_claimed_successful': False}
