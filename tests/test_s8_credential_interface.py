"""Only synthetic credential metadata; no live secrets or changes."""
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from tu1nz_s8_sealed_root import credential_metadata, SealedRootError


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0 and
                    os.environ.get("container")=="docker","isolated Linux root only")
class CredentialInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="s8-credential-metadata-",dir="/etc")
        self.root=Path(self.temp.name)
        self.path=self.root/"synthetic"
        self.path.write_bytes(b"SYNTHETIC_ONLY")
        account=pwd.getpwnam("nobody")
        self.uid,self.gid=account.pw_uid,account.pw_gid

    def tearDown(self):self.temp.cleanup()

    def check(self):
        _,layout=credential_metadata(self.root,uid=self.uid,gid=self.gid,directory=True)
        return credential_metadata(self.path,uid=self.uid,gid=self.gid,layout=layout)[1]

    def private(self):
        os.chown(self.root,self.uid,self.gid);self.root.chmod(0o500)
        os.chown(self.path,self.uid,self.gid);self.path.chmod(0o400)

    def named(self):
        self.root.chmod(0o500);self.path.chmod(0o400)
        for path,access in ((self.root,"rx"),(self.path,"r")):
            subprocess.run(["setfacl","-m",f"u:{self.uid}:{access}",str(path)],check=True)

    def test_exact_private_uid_layout(self):
        self.private();self.assertEqual(self.check(),"private-uid")

    def test_exact_root_named_user_acl_layout(self):
        self.named();self.assertEqual(self.check(),"root-named-user-acl")

    def test_unexpected_reader_acl_rejected(self):
        self.named()
        subprocess.run(["setfacl","-m","u:12345:r",str(self.path)],check=True)
        with self.assertRaises(SealedRootError):self.check()

    def test_write_default_acl_and_hardlink_rejected(self):
        self.named()
        subprocess.run(["setfacl","-m",f"u:{self.uid}:rw",str(self.path)],check=True)
        with self.assertRaises(SealedRootError):self.check()
        subprocess.run(["setfacl","-m",f"u:{self.uid}:r",str(self.path)],check=True)
        subprocess.run(["setfacl","-m","d:u::rx,d:g::---,d:o::---",str(self.root)],check=True)
        with self.assertRaises(SealedRootError):self.check()
        subprocess.run(["setfacl","-k",str(self.root)],check=True)
        os.link(self.path,self.root/"extra-link")
        with self.assertRaises(SealedRootError):self.check()

    def test_mixed_metadata_does_not_inherit_directory_provenance(self):
        self.named()
        subprocess.run(["setfacl","-b",str(self.path)],check=True)
        os.chown(self.path,self.uid,self.gid);self.path.chmod(0o400)
        with self.assertRaises(SealedRootError):self.check()


if __name__=="__main__":unittest.main()
