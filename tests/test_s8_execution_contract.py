"""Durable local protocol tests; these do not claim integrated/live admission."""
from datetime import datetime,timedelta,timezone
import json
import copy
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
def accepted_inventory(value):
    """Synthetic parser fixture, NEVER a rights inventory or live acceptance."""
    def actor(identity, role, uid, write):
        return dict(identity_sha256=identity*64, role=role, uid=uid,
                    authorization_sha256="4"*64, evidence_sha256="5"*64,
                    namespace_write=write, manager_api=write, helper_api=write)
    return dict(schema="TU1NZ_S8_SYSTEMD_ACCEPTANCE_V1", model=c.SYSTEMD_MODEL, slot=c.SLOT,
                freeze_sha256=value["freeze_sha256"], host_sha256=c.digest(value["host"]),
                observed_at=value["issued_at"], expires_at=value["expires_at"],
                inventory_complete=True, maintenance_excluded=True,
                evidence={name:"6"*64 for name in c.SYSTEMD_INVENTORY_SCOPES},
                actors=[actor("1", "ADMINISTRATOR", 0, True), actor("2", "NONADMIN_SERVICE", 0, False)])


def grant():
    value=dict(schema="TU1NZ_S8_EXECUTION_GRANT_V3",slot=c.SLOT,
                       incident_invocation=c.FAILED_INVOCATION,freeze_sha256="a"*64,
                       image_sha256="b"*64,human_authorization_sha256="c"*64,
                       host=dict(machine_sha256="d"*64, mount_sha256="e"*64,
                                 boot_id="11111111-1111-1111-1111-111111111111",
                                 root_identity=[1,2],namespace_identity=[3,4]),
                       provisioner=dict(pid=123,start_ticks=456,uid=0,
                                        boot_id="11111111-1111-1111-1111-111111111111"),
                       issued_at=NOW.isoformat(),expires_at=(NOW+timedelta(hours=1)).isoformat())
    value["systemd_acceptance"]=accepted_inventory(value)
    return value
def lease():return dict(release=c.LEASE_RELEASE,owner=None,expires=None,revision=c.LEASE_REVISION,
                       last_poll=c.LAST_POLL,updated=c.LAST_UPDATE,code="BOT_POLLER_NOT_RUNNING")


class AdministrationTests(unittest.TestCase):
    def check(self, value): c.grant_check(value, binding(), NOW)

    def test_explicit_roles_not_uid_zero_determine_parser_admission(self):
        value=grant(); self.check(value)
        self.assertEqual(value["systemd_acceptance"]["actors"][1]["uid"],0)
        # UID0 helper is allowed only with positively evidenced NO authority.
        for field in ("namespace_write","manager_api","helper_api"):
            changed=copy.deepcopy(value); changed["systemd_acceptance"]["actors"][1][field]=True
            with self.subTest(field=field),self.assertRaisesRegex(c.ContractError,"NONADMIN_AUTHORITY_RED"):
                self.check(changed)

    def test_missing_old_incomplete_or_unknown_acceptance_denies(self):
        for change in (lambda v:v.pop("systemd_acceptance"),
                lambda v:v.update(schema="TU1NZ_S8_EXECUTION_GRANT_V2"),
                lambda v:v["systemd_acceptance"].update(inventory_complete=False),
                lambda v:v["systemd_acceptance"].update(maintenance_excluded=False),
                lambda v:v["systemd_acceptance"].update(actors=[]),
                lambda v:v["systemd_acceptance"]["actors"][0].update(role="ROOT"),
                lambda v:v["systemd_acceptance"]["actors"][1].update(namespace_write="UNKNOWN")):
            value=grant();change(value)
            with self.assertRaises(c.ContractError):self.check(value)
        for scope in c.SYSTEMD_INVENTORY_SCOPES:
            for changed in (None,"UNKNOWN","0"*64):
                value=grant()
                if changed is None:del value["systemd_acceptance"]["evidence"][scope]
                else:value["systemd_acceptance"]["evidence"][scope]=changed
                with self.subTest(scope=scope),self.assertRaises(c.ContractError):self.check(value)

    def test_contradictory_duplicate_actor_and_no_named_administrator_denies(self):
        for change in (lambda a:a.append(copy.deepcopy(a[0])),
                lambda a:a[0].update(role="NONADMIN_SERVICE"),
                lambda a:a[1].update(role="ADMINISTRATOR"),
                lambda a:a[0].update(authorization_sha256="UNKNOWN")):
            value=grant();change(value["systemd_acceptance"]["actors"])
            with self.assertRaises(c.ContractError):self.check(value)

    def test_host_freeze_slot_and_model_are_independently_bound(self):
        for field,changed in (("host_sha256","7"*64),("freeze_sha256","8"*64),
                ("slot","new-slot"),("model","old-model")):
            value=grant();value["systemd_acceptance"][field]=changed
            with self.subTest(field=field),self.assertRaises(c.ContractError):self.check(value)

    def test_stale_future_expired_or_overlong_acceptance_denies(self):
        for field,changed in (("observed_at",NOW-timedelta(seconds=301)),
                ("observed_at",NOW+timedelta(seconds=1)),("expires_at",NOW),
                ("expires_at",NOW+timedelta(days=2))):
            value=grant();value["systemd_acceptance"][field]=changed.isoformat()
            with self.subTest(field=field),self.assertRaises(c.ContractError):self.check(value)


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
