"""Native exact ACL/mask/default policy and existing-object handoff tests."""
import array
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_path_policy as policy
from tu1nz_s8_existing_dropin import ExistingDropinStock
from tu1nz_s8_protected_journal import ProtectedJournal
from tu1nz_s8_journal_fence import APPEND, add_inode_protection


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


if __name__ == "__main__": unittest.main()
