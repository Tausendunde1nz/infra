"""New one-shot journal: exact writer fence -> immutable record handoff.

This is not a resume API. Even a directory left empty by an interrupted
creation is consumed. The only supported constructor creates a new directory;
historical directories, records and failed operations are never adopted.
"""
from __future__ import annotations

import os
from pathlib import Path

from tu1nz_s8_execution_contract import Journal, close_members, close_preserving, fingerprint, protected, require
from tu1nz_s8_journal_fence import (
    APPEND, IMMUTABLE, NewJournalFence, add_inode_protection, inode_flags,
)


class ProtectedJournal:
    def __init__(self, root: Path):
        require(os.geteuid() == 0, "PRIVILEGED_JOURNAL_REQUIRED")
        protected(root.parent, directory=True)
        self.root = root
        self.journal = None
        self.fence = None
        self.records = {}
        self.failed = False
        self.closed = False
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory = None
        try:
            # The separately provisioned parent must already retain new names
            # against removal/rebinding. Mere root ownership is insufficient.
            require(inode_flags(parent) & APPEND, "APPEND_ONLY_PARENT_REQUIRED")
            require((os.fstat(parent).st_dev, os.fstat(parent).st_ino) ==
                    (root.parent.stat().st_dev, root.parent.stat().st_ino), "JOURNAL_PARENT_DRIFT")
            # No exist_ok, stale directory adoption, removal or resume path.
            try:
                os.mkdir(root.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                require(False, "ALREADY_CONSUMED_NO_RETRY")
            os.fsync(parent)
            directory = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            add_inode_protection(directory, APPEND)
            self.fence = NewJournalFence(root)
            self.journal = Journal(root)
            self.check()
        except BaseException as error:
            self.failed = True
            close_preserving(error, self)
            raise
        finally:
            if directory is not None:
                os.close(directory)
            os.close(parent)

    def check(self):
        require(not self.closed and not self.failed, "JOURNAL_NO_AUTHORITY")
        try:
            self.fence.check()
            require(set(os.listdir(self.journal.fd)) == set(self.records), "JOURNAL_UNBOUND_OBJECT")
            for name, identity in self.records.items():
                m = protected(self.root / name, mode=0o600)
                require(fingerprint(m) == identity, "JOURNAL_SEALED_RECORD_DRIFT")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.journal.fd)
                try:
                    require(fingerprint(os.fstat(fd)) == identity and inode_flags(fd) & IMMUTABLE,
                            "JOURNAL_SEALED_RECORD_DRIFT")
                finally:
                    os.close(fd)
            self.fence.check()
        except BaseException:
            self.failed = True
            raise

    def once(self, name, value):
        self.check()
        try:
            result = self.journal.once(name, value)
            # Journal.once closed its only writable descriptor. The fence was
            # already active before creation and denies every other thread.
            self.fence.check()
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.journal.fd)
            try:
                add_inode_protection(fd, IMMUTABLE)
                self.records[name] = fingerprint(os.fstat(fd))
            finally:
                os.close(fd)
            os.fsync(self.journal.fd)
            self.check()
            return result
        except BaseException:
            self.failed = True
            raise

    def read(self, name):
        self.check()
        try:
            require(name in self.records, "JOURNAL_UNBOUND_OBJECT")
            value = self.journal.read(name)
            self.check()
            return value
        except BaseException:
            self.failed = True
            raise

    def handoff(self):
        """No fresh authority after close; only already sealed records remain.

        A failed/partial operation can never enter this successful handoff.
        After a successful handoff new opens cannot alter any recorded inode;
        directory append protection permanently retains every consumed name.
        """
        self.check()
        require(bool(self.records), "EMPTY_JOURNAL_NO_AUTHORITY")
        self.close()

    def close(self):
        # Cleanup must release permission requests even after an I/O failure.
        # Never remove flags, delete objects, emit GREEN or retry a write here.
        self.closed = True
        close_members(self, "fence", "journal")
