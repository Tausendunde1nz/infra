"""Real protected namespace plus actual production admission rejection.

No server paths are touched: native cases require the fresh disposable CI
container. Cold-boot refusal is a separate predicate test, not a claim that a
container process restart is a physical host/power-loss test.
"""
import array
import ctypes
import errno
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_anchor as anchor
import tu1nz_s8_anchor_bootstrap as bootstrap
import tu1nz_s8_execution_contract as c
import tu1nz_s8_provision as provision


def grant():
    now = datetime.now(timezone.utc)
    return dict(schema="TU1NZ_S8_EXECUTION_GRANT_V2", slot=c.SLOT, incident_invocation=c.FAILED_INVOCATION,
        freeze_sha256="a"*64, image_sha256="b"*64, human_authorization_sha256="c"*64,
        issued_at=now.isoformat(), expires_at=(now+timedelta(hours=1)).isoformat(),
        host=anchor.host(), provisioner=c.process_identity(os.getpid()))


class AnchorPortableTests(unittest.TestCase):
    def test_cleanup_failure_does_not_replace_primary(self):
        class Broken:
            def close(self): raise OSError("private details must not escape")
        primary = c.ContractError("S8_EXECUTION_SYNTHETIC_PRIMARY")
        c.close_preserving(primary, Broken(), Broken())
        self.assertEqual(str(primary), "S8_EXECUTION_SYNTHETIC_PRIMARY")
        self.assertEqual(primary._s8_cleanup_errors, [dict(type="OSError",code="UNKNOWN")]*2)

    def test_fixed_slot_and_path_do_not_include_release(self):
        self.assertEqual(str(anchor.ROOT), "/tu1nz-s8-admission-anchor-v1")
        self.assertEqual(c.SLOT, "s8-same-release-20261004-1")
        self.assertNotIn(c.FREEZE_TAG, str(anchor.ROOT))

    def test_host_boot_restore_mismatch_denied_before_process_lookup(self):
        # Synthetic input boundary only, NOT a native reboot simulation.
        with patch.object(anchor, "host", return_value={"boot_id": "new"}), \
             patch.object(c, "process_identity", side_effect=AssertionError("must not trust stale owner")):
            with self.assertRaisesRegex(c.ContractError, "HOST_BINDING_RED"):
                anchor.grant_host(dict(host={"boot_id":"old"}, provisioner={"pid":123}))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                    os.environ.get("container") == "docker", "disposable native kernel only")
class AnchorNativeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(Path("/.dockerenv").is_file())
        self.assertFalse(os.path.lexists(anchor.ROOT), "never touch existing stock")
        self.umask = os.umask(0o077)
        importlib.reload(bootstrap)
        self.authority = grant()
        self.binding = dict(freeze_sha256="a"*64, image_sha256="b"*64)

    def tearDown(self):
        # Clear only this fresh test's own explicit root in a disposable host.
        if anchor.ROOT.exists():
            for path in sorted([*anchor.ROOT.rglob("*"), anchor.ROOT], key=lambda p: len(p.parts), reverse=True):
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    raw = array.array("L", [0]); fcntl.ioctl(fd, 0x80086601, raw, True)
                    raw[0] &= ~0x30; fcntl.ioctl(fd, 0x40086602, raw)
                finally: os.close(fd)
            shutil.rmtree(anchor.ROOT)
        os.umask(self.umask)

    def test_sealed_slot_objects_and_release_are_bound(self):
        operation = bootstrap.Anchor(binding=self.binding, grant=self.authority)
        proof = operation.bind_objects(dict(synthetic=True))
        operation.close()
        self.assertEqual(anchor.validate(proof, binding=self.binding, grant=self.authority,
            dispatcher=self.authority["provisioner"]), dict(synthetic=True))
        wrong = dict(self.binding, freeze_sha256="d"*64)
        with self.assertRaisesRegex(c.ContractError, "RELEASE_BINDING_RED"):
            anchor.validate(proof, binding=wrong, grant=self.authority, dispatcher=self.authority["provisioner"])
        importlib.reload(bootstrap)  # Fresh interpreter state cannot replace durable refusal.
        with self.assertRaisesRegex(c.ContractError, "ANCHOR_EXISTS"):
            bootstrap.Anchor(binding=wrong, grant=self.authority)

    def test_existing_empty_foreign_and_partial_never_adopted(self):
        anchor.ROOT.mkdir(mode=0o700)
        for payload in (None, b'{', b'{"foreign":true}'):
            if payload is not None:
                (anchor.ROOT/"anchor.json").write_bytes(payload)
            before = {p.name:p.read_bytes() for p in anchor.ROOT.iterdir()}
            importlib.reload(bootstrap)
            with self.assertRaisesRegex(c.ContractError, "ANCHOR_EXISTS"):
                bootstrap.Anchor(binding=self.binding, grant=self.authority)
            self.assertEqual(before, {p.name:p.read_bytes() for p in anchor.ROOT.iterdir()})

    def test_production_preflight_refuses_anchor_before_incident_and_mutations(self):
        from tests.test_s8_execution_release import sample, tag
        from tu1nz_s8_frozen_entry import INSTALLER_MODULES
        sources = {name:(Path(__file__).resolve().parents[1]/"scripts"/(name+".py")).read_bytes()
                   for name in INSTALLER_MODULES}
        value = sample()
        value["control_sources"] = {name:hashlib.sha256(raw).hexdigest() for name,raw in sources.items()}
        image = b"synthetic no executable image"
        value["image"]["sha256"] = hashlib.sha256(image).hexdigest(); value["image"]["size"] = len(image)
        raw, object_id = tag(value)
        self.authority.update(freeze_sha256=c.digest(value),image_sha256=value["image"]["sha256"])
        anchor.ROOT.mkdir(mode=0o700)
        with patch.object(provision.observer, "failed_precondition", side_effect=AssertionError("must refuse first")):
            with self.assertRaisesRegex(c.ContractError, "ANCHOR_EXISTS"):
                provision.provision(tag_bytes=raw, tag_object=object_id, grant_bytes=c.canonical(self.authority),
                    expected_grant_sha256=c.digest(self.authority),
                    image_bytes=image, control_sources=sources)
        self.assertEqual(list(anchor.ROOT.iterdir()), [])

    def test_foreign_process_cannot_reuse_live_owner_grant_even_with_absent_anchor(self):
        pid = os.fork()
        if pid == 0:
            try:
                bootstrap.Anchor(binding=self.binding, grant=self.authority)
            except c.ContractError as error:
                os._exit(0 if "GRANT_OTHER_PROCESS" in str(error) else 1)
            os._exit(2)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]), 0)
        self.assertFalse(anchor.ROOT.exists())

    def test_root_file_writer_cannot_move_rebind_or_clear_anchor(self):
        operation = bootstrap.Anchor(binding=self.binding, grant=self.authority)
        operation.bind_objects(dict(synthetic=True)); operation.close()
        pid = os.fork()
        if pid == 0:
            class Header(ctypes.Structure): _fields_ = [("version",ctypes.c_uint32),("pid",ctypes.c_int)]
            class Data(ctypes.Structure):
                _fields_ = [("effective",ctypes.c_uint32),("permitted",ctypes.c_uint32),("inheritable",ctypes.c_uint32)]
            libc = ctypes.CDLL(None, use_errno=True)
            assert libc.capset(ctypes.byref(Header(0x20080522,0)),(Data*2)()) == 0
            fields = dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
            assert all(int(fields[k],16)==0 for k in ("CapEff","CapPrm","CapInh","CapAmb"))
            actions = [lambda: anchor.ROOT.rename(anchor.ROOT.with_name("forbidden-rebind")),
                       lambda: (anchor.ROOT/"state"/c.SLOT).rename(anchor.ROOT/"state/forbidden-rebind"),
                       lambda: (anchor.ROOT/"anchor.json").write_bytes(b"foreign"),
                       lambda: anchor.ROOT.chmod(0o777)]
            descriptor = os.open(anchor.ROOT,os.O_RDONLY|os.O_DIRECTORY)
            actions.append(lambda: fcntl.ioctl(descriptor,0x40086602,array.array("L",[0])))
            for action in actions:
                try: action()
                except OSError as error: assert error.errno == errno.EPERM
                else: os._exit(3)
            os.close(descriptor)
            os._exit(0)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]), 0)

    def test_interruption_after_each_anchor_mutation_leaves_no_new_admission(self):
        # One subtest per fresh object tree. Injections terminate the actual
        # constructing process, not mocks that report a guard as successful.
        for phase in ("root-created", "root-sealed", "slot-created", "intent-sealed", "objects-sealed"):
            with self.subTest(phase=phase):
                self.assertFalse(anchor.ROOT.exists())
                pid = os.fork()
                if pid == 0:
                    authority = grant()
                    if phase in {"root-created", "slot-created"}:
                        original = os.mkdir
                        def interrupted(name, *args, **kwargs):
                            original(name,*args,**kwargs)
                            if name == (anchor.ROOT.name if phase == "root-created" else c.SLOT): os._exit(77)
                        os.mkdir = interrupted
                    if phase == "root-sealed":
                        original = bootstrap.NewStock.seal
                        def interrupted(stock):
                            original(stock); os._exit(77)
                        bootstrap.NewStock.seal = interrupted
                    operation = bootstrap.Anchor(binding=self.binding, grant=authority)
                    if phase == "intent-sealed": os._exit(77)
                    operation.bind_objects(dict(synthetic=True)); os._exit(77)
                self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]),77)
                importlib.reload(bootstrap)
                with self.assertRaisesRegex(c.ContractError,"ANCHOR_EXISTS"):
                    bootstrap.Anchor(binding=self.binding,grant=self.authority)
                # Explicit disposable fixture reset BETWEEN independent cases,
                # never a path available to the production implementation.
                self.tearDown(); self.setUp()

    def test_missing_anchor_after_dead_owner_cannot_reanimate_backup_grant(self):
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            os.write(write,c.canonical(grant())); os.close(write); os._exit(0)
        os.close(write)
        data = os.read(read,16384); os.close(read)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]),0)
        backed_up_grant = json.loads(data)
        self.assertFalse(anchor.ROOT.exists())
        with self.assertRaises((c.ContractError, FileNotFoundError)):
            bootstrap.Anchor(binding=self.binding,grant=backed_up_grant)
        self.assertFalse(anchor.ROOT.exists())


if __name__ == "__main__": unittest.main()
