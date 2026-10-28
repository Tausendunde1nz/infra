"""New journalled binding of an existing EMPTY drop-in; never a slot reset.

The caller has already consumed its new execution-stock name. The exact
prestate and monotone transitions are durably sealed in that operation's
separate journal BEFORE changing this inode. No chmod/chown/ACL normalization,
unsealing, resume or adoption of existing regular files is implemented.
"""
import os

from tu1nz_s8_execution_contract import Journal, close_members, close_preserving, descriptor_scope, require
from tu1nz_s8_journal_fence import APPEND, MetadataWitness, NewJournalFence, add_inode_protection, inode_flags
from tu1nz_s8_new_stock import NewStock
from tu1nz_s8_path_policy import PathChain, dropin_snapshot


class ExistingWitness:
    def __init__(self, root):
        self.chain = self.metadata = None
        try:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with descriptor_scope(fd):
                self.metadata = MetadataWitness(fd, children=False)
                self.chain = PathChain(root, metadata_endpoint=self.metadata)
                from tu1nz_s8_journal_fence import inode_fid
                require(inode_fid(self.chain.fd) in self.metadata.targets, "DROPIN_IDENTITY_RED")
        except BaseException as error:
            close_preserving(error, self)
            raise

    def check(self, *, require_creation=False):
        # No claim that this directory was created by the current process.
        self.chain.check()

    def close(self):
        close_members(self, "chain", "metadata")


class ExistingDropinStock(NewStock):
    def __init__(self, root, files, *, expected, binding_journal, operation):
        self._initialize(root, files, False)
        try:
            self.witness = ExistingWitness(root)
            require(expected.get("state") == "EXISTING_EMPTY" and dropin_snapshot(root) == expected,
                    "DROPIN_PRESTATE_CHANGED")
            self.identity = tuple(expected["fingerprint"][:2])
            binding_journal.once("intent.json", dict(schema="TU1NZ_S8_EXISTING_DROPIN_BINDING_V1",
                operation=operation, predecessor=expected, historical_continuity=False,
                new_binding=True, files=self.files, directory_mode="0755", file_mode="0600",
                transitions=["ADD_APPEND", "EXACT_THREAD_FENCE", "CREATE_AND_SEAL_PLANNED_FILES",
                             "ADD_IMMUTABLE"], retry_allowed=False, runtime_authority=False))
            self.witness.check()
            require(dropin_snapshot(root) == expected, "DROPIN_PRESTATE_CHANGED")
            # Operate on the already witnessed descriptor, not a re-resolved
            # name. A concurrent exchange/metadata event remains fatal even if
            # restored. Own flag metadata is now an exact FID/TID transaction,
            # not an assumption that the ioctl emits no inotify event.
            directory = self.witness.chain.fd
            require(inode_flags(directory) == expected["inode_flags"], "DROPIN_FLAGS_CHANGED")
            add_inode_protection(directory, APPEND, observers=(self.witness.metadata,))
            self.witness.check()
            require(not os.listdir(directory), "DROPIN_NOT_EMPTY_OR_REBOUND")
            self.fence = NewJournalFence(root, directory_mode=0o755)
            require(self.fence.identity == self.identity, "DROPIN_IDENTITY_RED")
            self.journal = Journal(root, directory_mode=0o755)
            require(self.journal.identity == self.identity, "DROPIN_IDENTITY_RED")
            self.witness.check()
            self.journal.once("stock-plan.json", dict(schema="TU1NZ_S8_BOUND_EMPTY_STOCK_V1",
                predecessor=expected, historical_continuity=False, files=self.files,
                owner=0, group=0, directory_mode="0755", file_mode="0600", acl="NONE",
                operation=operation, runtime_authority=False))
            self._seal_file("stock-plan.json")
            self.check()
        except BaseException as error:
            self.failed = True
            close_preserving(error, self)
            raise
