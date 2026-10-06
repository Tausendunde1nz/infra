"""Create only new, preplanned immutable stock; never adopt or repair a path.

Parent watch precedes mkdir; a permission fence precedes every file. Each
writer descriptor is closed before sealing its inode. All names/bytes/modes
are fixed by the caller's authenticated release plan before any target write.
This primitive is not a live provisioner, rollback or authority receipt.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from tu1nz_s8_execution_contract import Journal, canonical, close_members, close_preserving, fingerprint, hex_value, protected, require
from tu1nz_s8_journal_fence import APPEND, IMMUTABLE, NewJournalFence, add_inode_protection, inode_flags
from tu1nz_s8_path_policy import PathChain, parent_metadata


class ParentCreationWitness:
    def __init__(self, parent: Path, name: str):
        require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name), "STOCK_NAME_RED")
        require(parent.is_absolute() and parent.resolve(strict=True) == parent, "STOCK_PARENT_RED")
        parent_metadata(parent, creation=True)
        self.chain = PathChain(parent, creation=True)
        self.parent, self.name = parent, os.fsencode(name)
        self.identity = parent.stat().st_dev, parent.stat().st_ino
        self.created = False
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            require(self.fd >= 0, "STOCK_PARENT_WATCH_REQUIRED")
            # Own parent relocation/removal/metadata + direct child changes.
            self.wd = libc.inotify_add_watch(self.fd, os.fsencode(parent), 0x00000fc4)
            require(self.wd >= 0, "STOCK_PARENT_WATCH_REQUIRED")
        except BaseException:
            self.close(); raise

    def check(self, *, require_creation=False):
        self.chain.check()
        m = parent_metadata(self.parent, creation=True)
        require((m.st_dev, m.st_ino) == self.identity, "STOCK_PARENT_DRIFT")
        while True:
            try: payload = os.read(self.fd, 65536)
            except BlockingIOError: break
            offset = 0
            while offset < len(payload):
                require(len(payload) - offset >= 16, "STOCK_PARENT_EVENT_RED")
                wd, mask, _cookie, size = struct.unpack_from("iIII", payload, offset)
                offset += 16
                require(offset + size <= len(payload) and wd == self.wd
                        and not mask & (0x4000 | 0x8000), "STOCK_PARENT_EVENT_RED")
                name = payload[offset:offset + size].split(b"\0", 1)[0]
                offset += size
                if not name:
                    require(False, "STOCK_PARENT_CHANGED")
                if name == self.name:
                    require(mask == 0x40000100 and not self.created, "STOCK_PATH_CHANGED")
                    self.created = True
        require(not require_creation or self.created, "STOCK_CREATE_NOT_OBSERVED")

    def close(self):
        try:
            if self.fd is not None and self.fd >= 0:
                os.close(self.fd); self.fd = None
        finally:
            self.chain.close()


class NewStock:
    def _initialize(self, root, files, state_directory):
        require(os.geteuid() == 0 and os.getegid() == 0, "STOCK_ROOT_REQUIRED")
        # PID-1's frozen launcher prescribes this umask. Do not change global
        # process policy behind a caller's back or chmod newly exposed files.
        fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                      if ":" in line)
        require(fields.get("Umask", "").strip() == "0077", "STOCK_UMASK_RED")
        require(type(files) is dict and bool(files) and type(state_directory) is bool, "STOCK_PLAN_RED")
        for name, spec in files.items():
            require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name)
                    and name not in {"stock-plan.json", "state"}
                    and type(spec) is dict and set(spec) == {"sha256", "size"}
                    and hex_value(spec["sha256"], 64) and type(spec["size"]) is int
                    and 0 < spec["size"] <= 1024 * 1024 * 1024, "STOCK_PLAN_RED")
        self.root, self.files, self.state_directory = root, json.loads(canonical(files)), state_directory
        self.witness = self.fence = self.journal = None
        self.failed = self.closed = False
        self.records = {}

    def __init__(self, root: Path, files: dict[str, dict], *, state_directory=False):
        self._initialize(root, files, state_directory)
        try:
            self.witness = ParentCreationWitness(root.parent, root.name)
            # A preexisting partial/empty/symlink path consumes this name.
            try: os.mkdir(root.name, mode=0o700, dir_fd=self.witness.chain.fd)
            except FileExistsError: require(False, "STOCK_ALREADY_EXISTS_NO_ADOPTION")
            os.fsync(self.witness.chain.fd)
            self.witness.check(require_creation=True)
            directory = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.witness.chain.fd)
            try:
                m = protected(root, directory=True, mode=0o700)
                require(fingerprint(m) == fingerprint(os.fstat(directory)), "STOCK_IDENTITY_RED")
                add_inode_protection(directory, APPEND)
                self.identity = os.fstat(directory).st_dev, os.fstat(directory).st_ino
            finally: os.close(directory)
            self.witness.check(require_creation=True)
            self.fence = NewJournalFence(root)
            self.journal = Journal(root)
            self.journal.once("stock-plan.json", dict(schema="TU1NZ_S8_NEW_STOCK_V1",
                predecessor="ABSENT", files=self.files, state_directory=state_directory,
                owner=0, group=0, directory_mode="0700", file_mode="0600", acl="NONE"))
            self._seal_file("stock-plan.json")
            self.check()
        except BaseException as error:
            self.failed = True; close_preserving(error, self); raise

    def _seal_file(self, name):
        self.fence.check()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.journal.fd)
        try:
            add_inode_protection(fd, IMMUTABLE)
            self.records[name] = fingerprint(os.fstat(fd))
        finally: os.close(fd)
        os.fsync(self.journal.fd)

    def check(self):
        require(not self.closed and not self.failed, "STOCK_NO_AUTHORITY")
        try:
            self.witness.check(require_creation=True)
            self.fence.check()
            self.journal.check()
            require(set(os.listdir(self.journal.fd)) == set(self.records), "STOCK_UNBOUND_OBJECT")
            for name, identity in self.records.items():
                m = protected(self.root / name, mode=0o600)
                require(fingerprint(m) == identity, "STOCK_FILE_DRIFT")
            self.fence.check()
        except BaseException:
            self.failed = True; raise

    def put(self, name: str, data: bytes):
        """Small immutable inputs; the image reader may stream separately later."""
        self.check()
        try:
            require(name in self.files and name not in self.records and type(data) is bytes
                    and len(data) == self.files[name]["size"]
                    and hashlib.sha256(data).hexdigest() == self.files[name]["sha256"], "STOCK_INPUT_RED")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.journal.fd)
            try:
                remaining = memoryview(data)
                while remaining:
                    count = os.write(fd, remaining)
                    require(count > 0, "STOCK_WRITE_RED"); remaining = remaining[count:]
                os.fsync(fd)
            finally: os.close(fd)
            self._seal_file(name)
            self.check()
        except BaseException:
            self.failed = True; raise

    def seal(self):
        self.check()
        try:
            require(set(self.records) == {"stock-plan.json", *self.files}, "STOCK_INCOMPLETE")
            state_identity = None
            if self.state_directory:
                os.mkdir("state", mode=0o700, dir_fd=self.journal.fd)
                child = os.open("state", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.journal.fd)
                try:
                    protected(self.root / "state", directory=True, mode=0o700)
                    require(not os.listdir(child), "STOCK_STATE_NOT_EMPTY")
                    add_inode_protection(child, APPEND)
                    state_identity = os.fstat(child).st_dev, os.fstat(child).st_ino
                finally: os.close(child)
            self.fence.check(); self.witness.check(require_creation=True)
            add_inode_protection(self.journal.fd, IMMUTABLE)
            self.fence.check(); self.witness.check(require_creation=True)
            require(inode_flags(self.journal.fd) & (APPEND | IMMUTABLE) == APPEND | IMMUTABLE,
                    "STOCK_DIRECTORY_NOT_SEALED")
            # Creation is permitted before the final immutable transition.
            # Reject an unexpected name even if it appeared after the earlier
            # completeness check (e.g. mkdir/link without a regular-file open).
            require(set(os.listdir(self.journal.fd)) == set(self.records) |
                    ({"state"} if self.state_directory else set()), "STOCK_UNBOUND_OBJECT")
            self.fence.check(); self.witness.check(require_creation=True)
            proof = dict(root_identity=self.identity, files=self.records, immutable=True,
                         state_directory=self.state_directory, state_identity=state_identity, live_authority=False)
            self.close()
            return proof
        except BaseException as error:
            self.failed = True; close_preserving(error, self); raise

    def close(self):
        self.closed = True
        close_members(self, "fence", "journal", "witness")
