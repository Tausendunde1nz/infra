"""Portable protocol tests, NOT native fanotify/flag/namespace evidence."""
import os
import ast
import ctypes
import array
import fcntl
from pathlib import Path
import struct
import sys
import threading
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import tu1nz_s8_journal_fence as f
import tu1nz_s8_new_stock as stock
import tu1nz_s8_path_policy as policy
from tu1nz_s8_execution_contract import ContractError

FID = (b"12345678", 1, b"abcdefgh")
OTHER = (b"12345678", 1, b"ijklmnop")


def event(tid, fid=FID, *, mask=4):
    fsid, kind, handle = fid
    size = (20 + len(handle) + 3) & ~3
    info = struct.pack("=BBH", 1, 0, size) + fsid + struct.pack("=Ii", len(handle), kind) + handle
    info = info.ljust(size, b"\0")
    return f.EVENT.pack(f.EVENT.size + size, 3, 0, f.EVENT.size, mask, -1, tid) + info


def witness(*, selected=False, bound=True, children=True):
    w = object.__new__(f.MetadataWitness)
    w.fd = 701
    w.owner = os.getpid(), threading.get_native_id()
    w.failed = False
    w.pending = None
    w.selected, w.bound, w.children = selected, bound, children
    w.targets = {FID}
    return w


class MetadataProtocolTests(unittest.TestCase):
    def test_existing_diagnostic_loader_ids_resolve_without_running_native_cases(self):
        source = Path(__file__).with_name("s8_diagnostic_once.py").read_text()
        names = [node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant)
                 and isinstance(node.value, str) and node.value.startswith("tests.test_s8_journal_kernel_barrier.")]
        self.assertTrue(names)
        for name in names:
            suite = unittest.defaultTestLoader.loadTestsFromName(name)
            self.assertEqual(suite.countTestCases(), 1)
            self.assertNotEqual(next(iter(suite)).__class__.__name__, "_FailedTest")

    def test_fd_handle_uses_comparison_api_and_opaque_bytes_only(self):
        libc = Mock()
        def fs(fd, target):
            self.assertEqual(fd, 702); target[56:64] = FID[0]; return 0
        def handle(fd, path, target, mount, options):
            self.assertEqual((fd, path, options), (702, b"", 0x1200))
            struct.pack_into("=Ii", target, 0, len(FID[2]), FID[1]); target[8:16] = FID[2]; return 0
        libc.fstatfs.side_effect = fs; libc.name_to_handle_at.side_effect = handle
        with patch.object(f.sys, "platform", "linux"), \
             patch.object(f.os, "uname", return_value=SimpleNamespace(machine="x86_64")), \
             patch.object(f.ctypes, "CDLL", return_value=libc):
            self.assertEqual(f.inode_fid(702), FID)
        libc.open_by_handle_at.assert_not_called()

    def test_unsupported_fid_or_mark_is_hold_without_fallback_or_fd_leak(self):
        libc = Mock(); libc.fanotify_init.return_value = 701; libc.fanotify_mark.return_value = -1
        with patch.object(f, "inode_fid", return_value=FID), patch.object(f.ctypes, "CDLL", return_value=libc), \
             patch.object(f.os, "close") as close:
            with self.assertRaisesRegex(ContractError, "METADATA_MARK_REQUIRED"): f.MetadataWitness(702)
        close.assert_called_once_with(701)
        # Linux UAPI: NOTIF=0, CLOEXEC=1, NONBLOCK=2; CONTENT=4 is forbidden
        # with REPORT_FID, even though 4 separately means the ATTRIB event mask.
        libc.fanotify_init.assert_called_once_with(0x303, os.O_RDONLY | os.O_CLOEXEC)
        self.assertEqual(libc.fanotify_mark.call_args.args, (701, 9, 0x48000004, -100, b"/proc/self/fd/702"))
        with patch.object(f, "inode_fid", side_effect=ContractError("S8_EXECUTION_METADATA_FILE_HANDLE_REQUIRED")), \
             patch.object(f.ctypes, "CDLL") as library:
            with self.assertRaises(ContractError): f.MetadataWitness(702)
        library.assert_not_called()

    def test_exact_fid_tid_and_aligned_payloads(self):
        for size in (1, 2, 3, 4, 8, 12, 128):
            fid = (FID[0], 1, b"x" * size)
            self.assertEqual(list(f.metadata_events(event(17, fid))), [(17, fid)])

    def test_malformed_unknown_overflow_and_zero_actor_fail_closed(self):
        good = event(17)
        corrupt = [b"", good[:23], good[:-1], good + b"x", event(0), event(-1),
                   event(17, mask=0x4000), event(17, (FID[0], 0, FID[2])),
                   event(17, (FID[0], 1, b"")), event(17, mask=0x10004)]
        for position in (4, 5, 6, 24, 25, 26):
            raw = bytearray(good); raw[position] ^= 0x80; corrupt.append(bytes(raw))
        for payload in corrupt:
            with self.subTest(payload=payload.hex()):
                with self.assertRaises(ContractError): list(f.metadata_events(payload))

    def test_no_owner_exception_without_token(self):
        w = witness()
        with patch.object(f.os, "read", return_value=event(w.owner[1])):
            with self.assertRaisesRegex(ContractError, "METADATA_EVENT_RED"): w.check()
        self.assertTrue(w.failed)

    def test_foreign_chmod_restore_stays_red_even_with_owner_event_and_token(self):
        # Represents coalesced foreign chmod+restore (one event) plus own flag.
        for raw_order in (False, True):
            w = witness(); w.pending = [FID, 0]
            raws = [event(w.owner[1]), event(w.owner[1] + 1)]
            if raw_order: raws.reverse()
            with patch.object(f.os, "read", return_value=b"".join(raws)):
                with self.assertRaisesRegex(ContractError, "METADATA_EVENT_RED"): w.finish()
            self.assertTrue(w.failed)

    def test_own_other_object_never_matches_token(self):
        w = witness(); w.pending = [FID, 0]
        with patch.object(f.os, "read", return_value=event(w.owner[1], OTHER)):
            with self.assertRaises(ContractError): w.check()

    def test_preexisting_owner_event_cannot_be_relabelled_as_new_transaction(self):
        w = witness()
        with patch.object(f.os, "read", return_value=event(w.owner[1])), patch.object(f, "inode_fid") as fid:
            with self.assertRaises(ContractError): w.begin(702)
        fid.assert_not_called(); self.assertIsNone(w.pending)

    def test_exact_flag_transaction_queue_order_readback_and_one_use(self):
        w = witness(); state = [0x80000]; calls = []
        def ioctl(fd, request, data, *args):
            calls.append((fd, request))
            self.assertEqual(fd, 702)
            if request == f.GET_FLAGS: data[0] = state[0]
            else:
                self.assertEqual(w.pending, [FID, 0])
                self.assertEqual(data[0], 0x80020); state[0] = data[0]
        with patch.object(f, "inode_fid", return_value=FID), patch.object(f.fcntl, "ioctl", side_effect=ioctl), \
             patch.object(f.os, "fsync") as sync, \
             patch.object(f.os, "read", side_effect=[BlockingIOError(), event(w.owner[1]), BlockingIOError()]):
            f.add_inode_protection(702, f.APPEND, observers=(w,))
        self.assertEqual(calls, [(702, f.GET_FLAGS), (702, f.SET_FLAGS), (702, f.GET_FLAGS)])
        sync.assert_called_once_with(702)
        self.assertIsNone(w.pending); self.assertFalse(w.failed)
        with patch.object(f.os, "read", return_value=event(w.owner[1])):
            with self.assertRaises(ContractError): w.check()

    def test_no_event_wrong_readback_or_failed_ioctl_invalidates_all_observers(self):
        for fault in ("missing", "readback", "ioctl"):
            a, b = witness(), witness(); changed = fault != "readback"
            with patch.object(f, "inode_fid", return_value=FID), \
                 patch.object(f, "inode_flags", side_effect=[0, f.APPEND if changed else 0]), \
                 patch.object(f.fcntl, "ioctl", side_effect=OSError() if fault == "ioctl" else None), \
                 patch.object(f.os, "fsync"), patch.object(f.os, "read", side_effect=BlockingIOError()):
                with self.assertRaises((OSError, ContractError)):
                    f.add_inode_protection(702, f.APPEND, observers=(a, b))
            self.assertTrue(a.failed and b.failed)

    def test_prebind_history_is_not_read_or_lost_and_target_event_is_red(self):
        w = witness(selected=True, bound=False)
        with patch.object(f.os, "read") as read:
            with self.assertRaisesRegex(ContractError, "BINDING_REQUIRED"): w.check()
        read.assert_not_called()
        w = witness(selected=True, bound=False)
        with patch.object(f, "inode_fid", return_value=OTHER), \
             patch.object(f.os, "read", return_value=event(w.owner[1] + 1, OTHER)):
            with self.assertRaisesRegex(ContractError, "METADATA_EVENT_RED"): w.bind(702)
        self.assertTrue(w.failed)

    def test_valid_unselected_sibling_only_is_not_new_protected_scope(self):
        w = witness(selected=True)
        with patch.object(f.os, "read", side_effect=[event(w.owner[1] + 1, OTHER), BlockingIOError()]): w.check()
        self.assertFalse(w.failed)
        with patch.object(f.os, "read", return_value=event(w.owner[1] + 1)):
            with self.assertRaises(ContractError): w.check()

    def test_selected_or_exact_inode_cannot_authorize_other_object(self):
        for options in (dict(selected=True), dict(children=False)):
            w = witness(**options)
            with patch.object(f.os, "read", side_effect=BlockingIOError()), patch.object(f, "inode_fid", return_value=OTHER):
                with self.assertRaisesRegex(ContractError, "TRANSITION_OBJECT_RED"): w.begin(702)

    def test_process_thread_fd_or_queue_loss_is_never_pass(self):
        for kind in ("thread", "process", "fd", "eof", "read"):
            w = witness()
            if kind == "thread": w.owner = w.owner[0], w.owner[1] + 1
            if kind == "process": w.owner = w.owner[0] + 1, w.owner[1]
            if kind == "fd": w.fd = None
            with patch.object(f.os, "read", return_value=b"", side_effect=OSError() if kind == "read" else None):
                with self.assertRaises((ContractError, OSError)): w.check()
            self.assertTrue(w.failed)

    def test_close_detaches_once_even_on_failure(self):
        w = witness()
        with patch.object(f.os, "close", side_effect=OSError()) as close:
            with self.assertRaises(ContractError): w.close()
            w.close()
        close.assert_called_once_with(701)
        self.assertTrue(w.failed); self.assertIsNone(w.fd)


class NamespaceTransferTests(unittest.TestCase):
    def chain(self, endpoint):
        value = object.__new__(policy.PathChain)
        value.failed, value.events, value.owner = False, 801, os.getpid()
        value.directory = Path("/synthetic/root")
        value.descriptors = [802, 803]
        m = SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o40700, st_uid=0, st_gid=0)
        value.nodes = [(1, value.directory.parent, 802, policy.identity(m), b"root", False),
                       (2, value.directory, 803, policy.identity(m), None, False)]
        value.metadata_endpoint = endpoint
        return value, m

    def check_event(self, endpoint, wd, mask, name):
        chain, m = self.chain(endpoint)
        payload = struct.pack("=iIII", wd, mask, 0, len(name)) + name
        with patch.object(policy, "parent_metadata", return_value=m), patch.object(policy.os, "fstat", return_value=m), \
             patch.object(policy.os, "read", side_effect=[payload, BlockingIOError()]), \
             patch.object(f, "inode_fid", return_value=FID): chain.check()
        return chain

    def test_exact_endpoint_attrib_requires_continuous_witness(self):
        endpoint = Mock(targets={FID})
        self.check_event(endpoint, 1, 0x40000004, b"root\0")
        self.check_event(endpoint, 2, 0x40000004, b"")
        self.assertEqual(endpoint.check.call_count, 4)
        with self.assertRaisesRegex(ContractError, "PARENT_CHANGED"):
            self.check_event(None, 2, 0x40000004, b"")

    def test_endpoint_never_delegates_rename_restore_watchloss_or_mixed_mask(self):
        for wd, mask, name in [(1, 0x40000040, b"root\0"), (1, 0x40000080, b"root\0"),
                               (2, 0x8000, b""), (2, 0x4000, b""), (77, 4, b""),
                               (2, 0x40000044, b""), (1, 4, b"")]:
            with self.subTest(wd=wd, mask=mask):
                with self.assertRaises(ContractError): self.check_event(Mock(targets={FID}), wd, mask, name)

    def test_foreign_endpoint_metadata_is_not_hidden_by_inotify_delegation(self):
        endpoint = Mock(targets={FID}); endpoint.check.side_effect = ContractError("S8_EXECUTION_JOURNAL_METADATA_EVENT_RED")
        with self.assertRaises(ContractError): self.check_event(endpoint, 2, 4, b"")

    def test_parent_creation_has_exact_create_rule_and_no_name_exchange_allowance(self):
        for mask in (0x40000100, 0x40000040, 0x40000080, 0x8000, 0x4000):
            w = object.__new__(stock.ParentCreationWitness)
            w.chain, w.parent, w.name, w.identity = Mock(), Path("/synthetic"), b"root", (1, 2)
            w.created, w.fd, w.wd, w.metadata = False, 801, 1, Mock(bound=True)
            raw = struct.pack("=iIII", 1, mask, 0, 5) + b"root\0"
            with patch.object(stock, "parent_metadata", return_value=SimpleNamespace(st_dev=1, st_ino=2)), \
                 patch.object(stock.os, "read", side_effect=[raw, BlockingIOError()]):
                if mask == 0x40000100:
                    w.check(require_creation=True); self.assertTrue(w.created)
                else:
                    with self.assertRaises(ContractError): w.check(require_creation=True)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                     os.environ.get("container") == "docker", "disposable native kernel only")
class NativeSealMetadataTests(unittest.TestCase):
    """Eight real-kernel cases, never inferred from the portable tests above."""
    def setUp(self):
        self.umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory(prefix="s8-seal-metadata-", dir="/etc")
        self.root = Path(self.temporary.name)
        self.resources = []

    def tearDown(self):
        # Close observers BEFORE the test-only restoration of disposable flags.
        errors = []
        for resource in reversed(self.resources):
            try: resource.close()
            except BaseException as error: errors.append(error)
        for path in sorted([*self.root.rglob("*"), self.root], key=lambda p: len(p.parts), reverse=True):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                value = array.array("L", [0]); fcntl.ioctl(fd, f.GET_FLAGS, value, True)
                value[0] &= ~0x30; fcntl.ioctl(fd, f.SET_FLAGS, value)
            finally: os.close(fd)
        self.temporary.cleanup(); os.umask(self.umask)
        if errors: raise errors[0]

    def watch(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: w = f.MetadataWitness(fd)
        finally: os.close(fd)
        self.resources.append(w)
        return w

    def record(self):
        path = self.root / "record"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try: os.write(fd, b"synthetic"); os.fsync(fd)
        finally: os.close(fd)
        return path, os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    def foreign(self, path, *, thread=False, fd=None):
        def mutate():
            if fd is None: os.chmod(path, 0o640); os.chmod(path, 0o600)
            else: os.fchmod(fd, 0o640); os.fchmod(fd, 0o600)
        if thread:
            errors = []
            def worker():
                try: mutate()
                except BaseException as error: errors.append(error)
            child = threading.Thread(target=worker, daemon=True); child.start(); child.join(timeout=2)
            self.assertFalse(child.is_alive()); self.assertEqual(errors, [])
        else:
            pid = os.fork()
            if pid == 0:
                try: mutate()
                except BaseException: os._exit(99)
                os._exit(0)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)

    def test_N01_prebind_foreign_chmod_restore_is_retained(self):
        w = stock.ParentCreationWitness(self.root, "new"); self.resources.append(w)
        path = self.root / "new"; path.mkdir(mode=0o700)
        w.check(require_creation=True)
        # Directory 0700 restored after a real foreign root metadata mutation.
        pid = os.fork()
        if pid == 0:
            try: os.chmod(path, 0o750); os.chmod(path, 0o700)
            except BaseException: os._exit(99)
            os._exit(0)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with self.assertRaisesRegex(ContractError, "METADATA_EVENT_RED"): w.metadata.bind(fd)
        finally: os.close(fd)

    def test_N02_own_append_and_immutable_are_one_use_and_object_bound(self):
        w = self.watch(); path, fd = self.record()
        try:
            f.add_inode_protection(fd, f.IMMUTABLE, observers=(w,)); w.check()
            self.assertIsNone(w.pending)
            with self.assertRaises(PermissionError): os.chmod(path, 0o640)
            w.check()
        finally: os.close(fd)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            f.add_inode_protection(directory, f.APPEND, observers=(w,))
            f.add_inode_protection(directory, f.IMMUTABLE, observers=(w,))
            w.check(); self.assertIsNone(w.pending)
        finally: os.close(directory)

    def actor_pair(self, *, thread):
        w = self.watch(); path, fd = self.record()
        try:
            w.begin(fd)
            self.foreign(path, thread=thread, fd=None if thread else fd)
            # Exact real own flag event shares object/mask but not kernel TID.
            f.add_inode_protection(fd, f.IMMUTABLE)
            with self.assertRaisesRegex(ContractError, "METADATA_EVENT_RED"): w.finish()
        finally: os.close(fd)

    def test_N03_same_process_foreign_thread_cannot_coalesce_into_owner(self):
        self.actor_pair(thread=True)

    def test_N04_foreign_process_cannot_coalesce_into_owner(self):
        self.actor_pair(thread=False)

    def test_N05_owner_chmod_restore_without_flag_transaction_is_red(self):
        w = self.watch(); path, fd = self.record(); os.close(fd)
        os.chmod(path, 0o640); os.chmod(path, 0o600)
        with self.assertRaisesRegex(ContractError, "METADATA_EVENT_RED"): w.check()

    def test_N06_endpoint_transfer_keeps_rename_and_return_detection(self):
        from tu1nz_s8_existing_dropin import ExistingWitness
        path = self.root / "endpoint"; path.mkdir(mode=0o755)
        w = ExistingWitness(path); self.resources.append(w)
        other = self.root / "moved"; os.rename(path, other); os.rename(other, path)
        with self.assertRaisesRegex(ContractError, "PARENT_CHANGED"): w.check()

    def test_N07_parent_namespace_watch_removal_is_red(self):
        w = stock.ParentCreationWitness(self.root, "new"); self.resources.append(w)
        libc = ctypes.CDLL(None, use_errno=True)
        self.assertEqual(libc.inotify_rm_watch(w.fd, w.wd), 0)
        with self.assertRaises(ContractError): w.check()

    def test_N08_lost_metadata_queue_never_becomes_empty_success(self):
        w = self.watch(); os.close(w.fd); w.fd = None
        with self.assertRaisesRegex(ContractError, "WITNESS_LOST"): w.check()


if __name__ == "__main__": unittest.main()
