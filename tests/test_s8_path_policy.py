"""Native exact ACL/mask/default policy and existing-object handoff tests."""
import array
import fcntl
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_path_policy as policy
from tu1nz_s8_existing_dropin import ExistingDropinStock
from tu1nz_s8_protected_journal import ProtectedJournal
from tu1nz_s8_journal_fence import APPEND, add_inode_protection
from tu1nz_s8_new_stock import ParentCreationWitness
from tu1nz_s8_dispatch_boundary import DispatchBoundary
from tu1nz_s8_admission_channel import AdmissionChannel
import tu1nz_s8_journal_fence as fence_module


class PathCleanupTests(unittest.TestCase):
    """Fault injection only; not the blocked systemd namespace experiment."""
    def witness(self):
        witness = object.__new__(policy.PathChain)
        witness.events, witness.descriptors = 101, [102, 103]
        witness.failed = False
        return witness

    def test_metadata_rejection_survives_close_failure(self):
        metadata = SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o40700, st_uid=0, st_gid=0)
        with patch.object(policy, "_parent_metadata", return_value=metadata), \
                patch.object(policy.os, "open", return_value=201), \
                patch.object(policy.os, "fstat", return_value=metadata), \
                patch("tu1nz_s8_journal_fence.inode_flags", return_value=0x40), \
                patch.object(policy.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaisesRegex(c.ContractError, "PARENT_FLAGS_RED") as result:
                policy.parent_metadata(Path("/synthetic"))
        self.assertEqual(result.exception._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")])
        close.assert_called_once_with(201)

    def test_descriptor_scope_aggregates_even_when_error_redaction_fails(self):
        class Unprintable(OSError):
            def __str__(self): raise RuntimeError("private logging failure")
        primary = c.ContractError("S8_EXECUTION_PRIMARY_RED")
        primary._s8_abort_error = dict(code="S8_EXECUTION_ABORT_RED")
        with patch.object(c.os, "close", side_effect=Unprintable()) as close:
            with self.assertRaises(c.ContractError) as result:
                with c.descriptor_scope(201, 202, 201): raise primary
            self.assertEqual([call.args[0] for call in close.call_args_list], [201, 202])
        self.assertIs(result.exception, primary)
        self.assertEqual(primary._s8_abort_error["code"], "S8_EXECUTION_ABORT_RED")
        self.assertEqual(primary._s8_cleanup_errors, [dict(type="Unprintable", code="UNKNOWN")]*2)

    def test_cleanup_only_scope_is_red_and_attempts_all_descriptors(self):
        with patch.object(c.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaisesRegex(c.ContractError, "DESCRIPTOR_CLEANUP_RED") as result:
                with c.descriptor_scope(201, 202): pass
        self.assertEqual(close.call_count, 2)
        self.assertEqual(result.exception._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")]*2)

    def test_resource_scope_preserves_primary_and_closes_every_resource_once(self):
        class Broken:
            calls = 0
            def close(self):
                self.calls += 1
                raise OSError("private")
        first, second = Broken(), Broken()
        primary = c.ContractError("S8_EXECUTION_PRIMARY_RED")
        with self.assertRaises(c.ContractError) as result:
            with c.resource_scope(first, second): raise primary
        self.assertIs(result.exception, primary)
        self.assertEqual((first.calls, second.calls), (1, 1))
        self.assertEqual(primary._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")]*2)

    def test_dispatch_and_admission_resource_ownership_detached_before_close(self):
        class Broken:
            calls = 0
            def close(self):
                self.calls += 1
                raise OSError("private")
        dispatcher = object.__new__(DispatchBoundary)
        dispatcher.server, dispatcher.journal = Broken(), Broken()
        server, journal = dispatcher.server, dispatcher.journal
        with self.assertRaises(c.ContractError) as result: dispatcher.close()
        self.assertEqual(result.exception._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")]*2)
        dispatcher.close()
        self.assertEqual((server.calls, journal.calls), (1, 1))
        channel = object.__new__(AdmissionChannel)
        channel.server = Broken(); server = channel.server
        with self.assertRaises(c.ContractError): channel.close()
        channel.close()
        self.assertTrue(channel.closed)
        self.assertEqual(server.calls, 1)

    def test_journal_write_failure_and_unlock_failure_retain_primary(self):
        journal = object.__new__(c.Journal)
        journal.fd = 501
        with patch.object(journal, "check"), \
                patch.object(c.os, "open", return_value=502), \
                patch.object(c.os, "write", return_value=0), \
                patch.object(c.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaisesRegex(c.ContractError, "JOURNAL_WRITE_RED") as result:
                journal.once("operation.json", dict(synthetic=True))
            close.assert_called_once_with(502)
        self.assertEqual(result.exception._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")])
        primary = c.ContractError("S8_EXECUTION_PRIMARY_RED")
        with patch.object(journal, "check"), patch.object(c.fcntl, "flock", side_effect=[None, OSError("private")]):
            with self.assertRaises(c.ContractError) as result:
                with journal.locked(): raise primary
        self.assertIs(result.exception, primary)
        self.assertEqual(primary._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")])

    def test_journal_close_unknown_is_not_retried(self):
        journal = object.__new__(c.Journal)
        journal.fd = 501
        with patch.object(c.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaisesRegex(c.ContractError, "DESCRIPTOR_CLEANUP_RED"): journal.close()
            journal.close()
        self.assertIsNone(journal.fd)
        close.assert_called_once_with(501)

    def test_fence_worker_failure_retains_primary_and_releases_owned_fd(self):
        witness = object.__new__(fence_module.NewJournalFence)
        witness.stop = SimpleNamespace(is_set=lambda: False)
        witness.fd, witness.consumer_error, witness.failure = 601, None, False
        witness.owner_pid, witness.owner_tid = os.getpid(), fence_module.threading.get_native_id()
        primary = c.ContractError("S8_EXECUTION_FANOTIFY_EVENT_RED")
        primary._s8_abort_error = dict(code="S8_EXECUTION_ABORT_RED")
        with patch.object(fence_module.select, "select", side_effect=primary), \
                patch.object(c.os, "close", side_effect=OSError("private")) as close:
            witness._serve()
            with self.assertRaises(c.ContractError) as result: witness.check()
        self.assertIs(result.exception, primary)
        self.assertTrue(witness.failure)
        self.assertIsNone(witness.fd)
        self.assertEqual(primary._s8_abort_error["code"], "S8_EXECUTION_ABORT_RED")
        self.assertEqual(primary._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")])
        close.assert_called_once_with(601)

    def test_channel_constructor_timeout_failure_preserves_primary(self):
        primary = c.ContractError("S8_EXECUTION_CHANNEL_PRIMARY_RED")
        server = SimpleNamespace(settimeout=lambda _: (_ for _ in ()).throw(primary),
                                 close=lambda: (_ for _ in ()).throw(OSError("private")))
        with patch("tu1nz_s8_admission_channel.os.geteuid", return_value=0), \
                patch("tu1nz_s8_admission_channel.protect_process"), \
                patch("tu1nz_s8_admission_channel.socket.SOCK_CLOEXEC", 0x80000, create=True), \
                patch("tu1nz_s8_admission_channel.socket.socket", return_value=server):
            with self.assertRaises(c.ContractError) as result: AdmissionChannel(Path("/synthetic"), "synthetic.service")
        self.assertIs(result.exception, primary)
        self.assertEqual(primary._s8_cleanup_errors[0]["code"], "S8_EXECUTION_RESOURCE_CLEANUP_RED")

    def test_all_closes_attempted_redacted_once_no_retry(self):
        witness = self.witness()
        with patch.object(policy.os, "close", side_effect=OSError("private-path-and-secret")) as close:
            with self.assertRaisesRegex(c.ContractError, "PATH_WITNESS_CLEANUP_RED") as result:
                witness.close()
            self.assertEqual([call.args[0] for call in close.call_args_list], [101, 103, 102])
            self.assertEqual(result.exception._s8_cleanup_errors,
                             [dict(type="OSError", code="UNKNOWN")]*3)
            witness.close()
            self.assertEqual(close.call_count, 3)
        self.assertIsNone(witness.events)
        self.assertEqual(witness.descriptors, [])
        self.assertTrue(witness.failed)

    def test_body_primary_and_abort_survive_multiple_cleanup_errors(self):
        witness = self.witness()
        primary = c.ContractError("S8_EXECUTION_PRIMARY_RED")
        primary._s8_abort_error = dict(type="ContractError", code="S8_EXECUTION_ABORT_RED")
        with patch.object(policy.os, "close", side_effect=OSError("private")):
            with self.assertRaises(c.ContractError) as result:
                with witness: raise primary
        self.assertIs(result.exception, primary)
        self.assertEqual(primary._s8_abort_error["code"], "S8_EXECUTION_ABORT_RED")
        self.assertEqual(primary._s8_cleanup_errors[0]["code"], "S8_EXECUTION_PATH_WITNESS_CLEANUP_RED")
        self.assertEqual(primary._s8_cleanup_errors[1:], [dict(type="OSError", code="UNKNOWN")]*3)

    def test_final_integrity_check_failure_not_replaced(self):
        witness = self.witness()
        primary = c.ContractError("S8_EXECUTION_PARENT_IDENTITY_RED")
        with patch.object(witness, "check", side_effect=primary), \
                patch.object(policy.os, "close", side_effect=OSError("private")):
            with self.assertRaises(c.ContractError) as result:
                with witness: pass
        self.assertIs(result.exception, primary)
        self.assertEqual(len(primary._s8_cleanup_errors), 4)

    def test_parent_creation_closes_both_resources_and_preserves_nested_errors(self):
        chain = self.witness()
        witness = object.__new__(ParentCreationWitness)
        witness.fd, witness.chain = 104, chain
        with patch.object(policy.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaisesRegex(c.ContractError, "STOCK_PARENT_CLEANUP_RED") as result:
                witness.close()
            self.assertEqual([call.args[0] for call in close.call_args_list], [104, 101, 103, 102])
            self.assertEqual(len(result.exception._s8_cleanup_errors), 5)
            witness.close()
            self.assertEqual(close.call_count, 4)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                    os.environ.get("container") == "docker", "disposable native kernel only")
class PathPolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(Path("/.dockerenv").exists())
        self.old = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory(prefix="s8-policy-", dir="/etc")
        self.root = Path(self.temp.name)

    def tearDown(self):
        for path in sorted([*self.root.rglob("*"), self.root], key=lambda p:len(p.parts), reverse=True):
            if path.is_symlink(): continue
            fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
            try:
                value = array.array("L",[0]); fcntl.ioctl(fd,0x80086601,value,True)
                value[0] &= ~0x30; fcntl.ioctl(fd,0x40086602,value)
            finally: os.close(fd)
        self.temp.cleanup(); os.umask(self.old)

    def test_unlisted_gid_acl_xattr_defaults_remain_rejected(self):
        for name, value in ((policy.ACCESS,policy.acl_bytes(policy.CONFIG_ACCESS)),
                            (policy.DEFAULT,policy.acl_bytes(policy.CONFIG_ACCESS)), ("user.foreign",b"x")):
            os.setxattr(self.root,name,value)
            with self.assertRaises(c.ContractError): policy.parent_metadata(self.root)
            os.removexattr(self.root,name)
        os.chown(self.root,0,1001)
        with self.assertRaises(c.ContractError): policy.parent_metadata(self.root)

    def test_effective_mask_distinguishes_read_from_write(self):
        policy.no_nonowner_write(policy.CONFIG_ACCESS)
        policy.no_nonowner_write(policy.REPOSITORY_ACCESS)
        for index, entry in enumerate(policy.REPOSITORY_ACCESS):
            if entry[0] == 16:
                entries = list(policy.REPOSITORY_ACCESS); entries[index] = (16,7,entry[2])
                with self.assertRaisesRegex(c.ContractError,"EFFECTIVE_WRITE_RED"):
                    policy.no_nonowner_write(entries)

    def test_unknown_inode_flags_rejected_on_strict_and_acl_parent(self):
        # NODUMP is real persistent inode metadata, not an xattr. It must not
        # become silently accepted merely because DAC/ACL traversal is safe.
        for profile in (False, True):
            if profile:
                os.chown(self.root, 0, 1001)
                os.setxattr(self.root, policy.ACCESS, policy.acl_bytes(policy.CONFIG_ACCESS))
                os.chmod(self.root, 0o750)
            profiles = {self.root: (0o750, policy.CONFIG_ACCESS, None)} if profile else {}
            with patch.dict(policy.PROFILES, profiles):
                policy.parent_metadata(self.root)
                fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    value = array.array("L", [0]); fcntl.ioctl(fd, 0x80086601, value, True)
                    original = value[0]
                    value[0] |= 0x40; fcntl.ioctl(fd, 0x40086602, value)
                    with self.assertRaisesRegex(c.ContractError, "PARENT_FLAGS_RED"):
                        policy.parent_metadata(self.root)
                    with self.assertRaisesRegex(c.ContractError, "PARENT_FLAGS_RED"):
                        policy.PathChain(self.root)
                finally:
                    fcntl.ioctl(fd, 0x40086602, array.array("L", [original]))
                    os.close(fd)
                policy.parent_metadata(self.root)

    def test_ancestor_exchange_and_restore_is_an_event_not_clean_snapshot(self):
        child = self.root/"child"; child.mkdir()
        witness = policy.PathChain(child)
        try:
            child.rename(self.root/"exchanged"); (self.root/"exchanged").rename(child)
            with self.assertRaisesRegex(c.ContractError,"PARENT_CHANGED"):
                witness.check()
        finally: witness.close()

    def test_existing_empty_directory_gets_new_binding_without_new_provenance(self):
        dropin = self.root/"dropin"; dropin.mkdir(); dropin.chmod(0o755)
        expected = policy.dropin_snapshot(dropin)
        parent = self.root/"journal-parent"; parent.mkdir()
        fd = os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
        try: add_inode_protection(fd,APPEND)
        finally: os.close(fd)
        journal = ProtectedJournal(parent/"binding")
        payload = b"[Service]\nRestart=no\n"
        import hashlib
        files = {"00-atomic-admission.conf":dict(size=len(payload),sha256=hashlib.sha256(payload).hexdigest())}
        stock = None
        try:
            stock = ExistingDropinStock(dropin,files,expected=expected,binding_journal=journal,
                operation=dict(synthetic=True))
            stock.put("00-atomic-admission.conf",payload)
            proof = stock.seal()
            self.assertEqual(list(proof["root_identity"]),expected["fingerprint"][:2])
            intent = journal.read("intent.json")
            self.assertIs(intent["historical_continuity"],False)
            self.assertEqual(intent["predecessor"]["origin"],"UNKNOWN")
            journal.handoff()
        finally:
            if stock is not None: stock.close()
            journal.close()
        with self.assertRaises(c.ContractError): policy.dropin_snapshot(dropin)

    def test_foreign_dropin_and_acl_never_included(self):
        dropin = self.root/"dropin"; dropin.mkdir(); dropin.chmod(0o755)
        (dropin/"foreign.conf").write_bytes(b"foreign")
        with self.assertRaisesRegex(c.ContractError,"NOT_EMPTY"):
            policy.dropin_snapshot(dropin)

    def test_native_lost_close_acknowledgements_preserve_primary_and_close_every_fd(self):
        witness = policy.PathChain(self.root)
        owned = [witness.events, *witness.descriptors]
        actual_close = os.close
        primary = c.ContractError("S8_EXECUTION_PARENT_IDENTITY_RED")
        def lost_ack(fd):
            actual_close(fd)
            raise OSError("synthetic lost acknowledgement; private details")
        with patch.object(policy.os, "close", side_effect=lost_ack) as close:
            with self.assertRaises(c.ContractError) as result:
                with witness: raise primary
            self.assertIs(result.exception, primary)
            self.assertCountEqual([call.args[0] for call in close.call_args_list], owned)
            self.assertEqual(primary._s8_cleanup_errors[1:],
                             [dict(type="OSError", code="UNKNOWN")]*len(owned))
            witness.close()
            self.assertEqual(close.call_count, len(owned))
        for fd in owned:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_native_constructor_primary_survives_cleanup_failure(self):
        primary = c.ContractError("S8_EXECUTION_PARENT_METADATA_RED")
        actual_close = os.close
        closed = []
        def lost_ack(fd):
            actual_close(fd); closed.append(fd)
            raise OSError("private details")
        with patch.object(policy, "parent_metadata", side_effect=primary), \
                patch.object(policy.os, "close", side_effect=lost_ack):
            with self.assertRaises(c.ContractError) as result: policy.PathChain(self.root)
        self.assertIs(result.exception, primary)
        self.assertEqual(len(closed), 2)  # real inotify and first ancestor FD
        self.assertEqual(primary._s8_cleanup_errors[1:], [dict(type="OSError", code="UNKNOWN")]*2)
        for fd in closed:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_native_metadata_flags_rejection_survives_lost_close_ack(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        value = array.array("L", [0]); fcntl.ioctl(fd, 0x80086601, value, True)
        original = value[0]
        fcntl.ioctl(fd, 0x40086602, array.array("L", [original | 0x40]))
        os.close(fd)
        actual_close = os.close
        closed = []
        def lost_ack(descriptor):
            actual_close(descriptor); closed.append(descriptor)
            raise OSError("private lost acknowledgement")
        try:
            with patch.object(policy.os, "close", side_effect=lost_ack):
                with self.assertRaisesRegex(c.ContractError, "PARENT_FLAGS_RED") as result:
                    policy.parent_metadata(self.root)
            self.assertEqual(result.exception._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")])
            self.assertEqual(len(closed), 1)
            with self.assertRaises(OSError): os.fstat(closed[0])
        finally:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: fcntl.ioctl(fd, 0x40086602, array.array("L", [original]))
            finally: os.close(fd)

    def test_native_sealed_copy_primary_and_both_owned_fds_survive_lost_close_ack(self):
        from scripts import tu1nz_s8_sealed_root as sealed
        image = self.root/"synthetic-image"
        image.write_bytes(b"synthetic")
        actual_close = os.close
        closed = []
        def lost_ack(fd):
            actual_close(fd); closed.append(fd)
            raise OSError("private lost acknowledgement")
        with patch.object(sealed.os, "close", side_effect=lost_ack):
            with self.assertRaisesRegex(sealed.SealedRootError, "IMAGE_INPUT_DRIFT") as result:
                sealed.sealed_copy(image, hashlib.sha256(b"different").hexdigest())
        self.assertEqual(result.exception._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")]*2)
        self.assertEqual(len(set(closed)), 2)
        for fd in closed:
            with self.assertRaises(OSError): os.fstat(fd)


if __name__ == "__main__": unittest.main()
