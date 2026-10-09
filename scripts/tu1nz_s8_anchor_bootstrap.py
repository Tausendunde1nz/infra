"""One live construction lifetime; never adopt an existing anchor or slot.

No standalone bootstrap/repair/resume entrypoint is exported. The verified
provisioner consumes this global name before touching execution stock/drop-in.
The grant is bound to that exact already-running process and boot. Replacing a
movable historical parent cannot remove the top-level consumed namespace.
"""
import os

import tu1nz_s8_anchor as a
import tu1nz_s8_execution_contract as c
from tu1nz_s8_new_stock import NewStock
from tu1nz_s8_protected_journal import ProtectedJournal
from tu1nz_s8_journal_fence import IMMUTABLE, add_inode_protection

_ENTERED = False


class Anchor:
    def __init__(self, *, binding, grant):
        global _ENTERED
        a.grant_host(grant, owner=True)
        c.require(not _ENTERED, "ANCHOR_PROCESS_ALREADY_ENTERED")
        _ENTERED = True  # An exception before a durable name is not a retry.
        a.absent()
        self.stock = self.journal = None
        self.proof = None
        self.record = dict(schema=a.SCHEMA, slot=c.SLOT, host=grant["host"], binding=binding,
            grant_sha256=c.digest(grant), provisioner=grant["provisioner"], retry_allowed=False,
            restore_authority=False)
        payload = c.canonical(self.record)
        import hashlib
        try:
            self.stock = NewStock(a.ROOT, {"anchor.json": dict(size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest())}, state_directory=True)
            self.stock.put("anchor.json", payload)
            root = self.stock.seal()
            self.journal = ProtectedJournal(a.ROOT/"state"/c.SLOT)
            intent = dict(anchor_sha256=c.digest(self.record), slot=c.SLOT,
                grant_sha256=c.digest(grant), provisioner=grant["provisioner"])
            self.journal.once("intent.json", intent)
            self.proof = dict(host=grant["host"], root_identity=list(root["root_identity"]),
                state_identity=list(root["state_identity"]), slot_identity=list(self.journal.journal.identity),
                record_sha256=c.digest(self.record), intent_sha256=c.digest(intent))
        except BaseException as error:
            # Best effort cleanup cannot delete protection or replace the
            # primary error. The outer provisioner separately reports cleanup.
            c.close_preserving(error, self)
            raise

    def bind_objects(self, objects):
        a.grant_host({"host": self.record["host"], "provisioner": self.record["provisioner"]}, owner=True)
        c.require(self.proof is not None and self.journal is not None, "ANCHOR_NO_HANDOFF")
        self.journal.once("objects.json", objects)
        self.proof["objects_sha256"] = c.digest(objects)
        self.journal.check()
        add_inode_protection(self.journal.journal.fd, IMMUTABLE)
        self.journal.handoff()
        self.journal = None
        return dict(self.proof)

    def close(self):
        c.close_members(self, "journal", "stock")
