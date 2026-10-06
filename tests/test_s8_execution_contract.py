"""Durable local protocol tests; these do not claim integrated/live admission."""
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

from scripts import tu1nz_s8_execution_contract as c


NOW=datetime(2026,10,5,12,tzinfo=timezone.utc)
INVOCATION="1"*32


def binding():return dict(freeze_sha256="a"*64,image_sha256="b"*64)
def grant():return dict(schema="TU1NZ_S8_EXECUTION_GRANT_V2",slot=c.SLOT,
                       incident_invocation=c.FAILED_INVOCATION,freeze_sha256="a"*64,
                       image_sha256="b"*64,human_authorization_sha256="c"*64,
                       host=dict(machine_sha256="d"*64, mount_sha256="e"*64,
                                 boot_id="11111111-1111-1111-1111-111111111111",
                                 root_identity=[1,2],namespace_identity=[3,4]),
                       provisioner=dict(pid=123,start_ticks=456,uid=0,
                                        boot_id="11111111-1111-1111-1111-111111111111"),
                       issued_at=NOW.isoformat(),expires_at=(NOW+timedelta(hours=1)).isoformat())
def lease():return dict(release=c.LEASE_RELEASE,owner=None,expires=None,revision=c.LEASE_REVISION,
                       last_poll=c.LAST_POLL,updated=c.LAST_UPDATE,code="BOT_POLLER_NOT_RUNNING")


@unittest.skipUnless(sys.platform=="linux", "native Linux ACL/journal semantics required")
class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.journal=c.Journal(self.root,uid=os.getuid())
        self.journal.once("operation.json",dict(grant_sha256=c.digest(grant()),binding_sha256=c.digest(binding())))
    def tearDown(self):self.journal.close();self.temp.cleanup()
    def condition(self,observer=lease):
        with patch.object(c,"process_identity",return_value=dict(pid=1,uid=0)):
            return c.consume_condition(self.journal,invocation=INVOCATION,coordinator=dict(pid=1,uid=0),
                clock=lambda:NOW,observe_lease=observer,binding=binding(),grant=grant())
    def test_one_initial_boundary_and_distinct_execution(self):
        self.assertTrue(self.condition())
        c.consume_execution(self.journal,invocation=INVOCATION,clock=lambda:NOW,binding=binding(),grant=grant())
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        with self.assertRaisesRegex(c.ContractError,"ALREADY_CONSUMED"):self.condition()
        with self.assertRaisesRegex(c.ContractError,"ALREADY_CONSUMED"):
            c.consume_execution(self.journal,invocation=INVOCATION,clock=lambda:NOW,binding=binding(),grant=grant())
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})
    def test_unknown_observation_consumes_before_read_and_cannot_reopen(self):
        def lost():
            self.assertTrue((self.root/"activation.json").exists())
            raise OSError("isolated lost observation")
        with self.assertRaises(OSError):self.condition(lost)
        self.journal.close();self.journal=c.Journal(self.root,uid=os.getuid())
        with self.assertRaisesRegex(c.ContractError,"ALREADY_CONSUMED"):self.condition()
    def test_foreign_or_revised_row_rejected_not_waited_out(self):
        for key,value in (("owner","foreign"),("revision",c.LEASE_REVISION+1),("expires",NOW.isoformat())):
            row=lease();row[key]=value
            with self.subTest(key=key),self.assertRaises(c.ContractError):c.lease_admission(row)
    def test_partial_journal_is_consuming(self):
        fd=os.open(self.root/"activation.json",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        with self.assertRaisesRegex(c.ContractError,"ALREADY_CONSUMED"):self.condition()
        with self.assertRaisesRegex(c.ContractError,"JOURNAL_SIZE_RED"):self.journal.read("activation.json")
    def test_concurrent_journal_lock_refuses_other_process(self):
        other=c.Journal(self.root,uid=os.getuid())
        try:
            with self.journal.locked():
                with self.assertRaisesRegex(c.ContractError,"CONCURRENT_OPERATION"):
                    with other.locked():self.fail("unexpected lock")
        finally:other.close()
    def test_expired_execution_consumes_and_rejects(self):
        self.condition()
        with self.assertRaisesRegex(c.ContractError,"GRANT_TIME_RED"):
            c.consume_execution(self.journal,invocation=INVOCATION,clock=lambda:NOW+timedelta(days=1),
                                binding=binding(),grant=grant())
        with self.assertRaisesRegex(c.ContractError,"ALREADY_CONSUMED"):
            c.consume_execution(self.journal,invocation=INVOCATION,clock=lambda:NOW,binding=binding(),grant=grant())
    def test_receipt_independent_from_later_poll_health(self):
        self.condition()
        permit=c.canonical(c.permit_value(self.journal,invocation=INVOCATION,
            application=dict(commit="d"*40,tree="e"*40),source_hashes={
                key:"f"*64 for key in ("runtime.py","polling.py","recovery_admission.py")},binding=binding(),grant=grant()))
        import hashlib
        receipt=dict(event="S8_ATOMIC_ADMISSION_ACCEPTED",slot=c.SLOT,permit_sha256=hashlib.sha256(permit).hexdigest(),
                     invocation=INVOCATION,expected_revision=c.LEASE_REVISION,claimed_revision=c.LEASE_REVISION+1,
                     owner_sha256="d"*64)
        c.initial_receipt(receipt,permit,INVOCATION)
        receipt["claimed_revision"]+=1
        with self.assertRaises(c.ContractError):c.initial_receipt(receipt,permit,INVOCATION)


if __name__=="__main__":unittest.main()
