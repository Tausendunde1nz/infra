"""Real Linux mount/seal/ACL tests in a disposable privileged child namespace."""
import errno
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import tu1nz_s8_sealed_root as s


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux root required")
class KernelImageTests(unittest.TestCase):
    def test_sealed_source_and_root_writers_cannot_change_running_image(self):
        # Fork before unshare: the runner/host namespace is never changed.
        child = os.fork()
        if child == 0:
            try:
                self.probe()
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def probe(self):
        s.private_namespace()
        with tempfile.TemporaryDirectory(prefix="s8-sealed-test-", dir="/var/tmp") as directory:
            root = Path(directory)
            tree = root/"tree"; tree.mkdir()
            (tree/"code.py").write_text("frozen\n")
            (tree/"dev").mkdir()
            (tree/"dev/null").touch(mode=0o644)
            # A deliberately inherited ACL must not enter the execution image.
            subprocess.run(["setfacl","-m","d:u:65534:rwx",str(tree)],check=True)
            image = root/"image.squashfs"
            subprocess.run(["mksquashfs",str(tree),str(image),"-noappend","-no-xattrs",
                            "-all-root","-processors","1","-no-progress"],
                           check=True,stdout=subprocess.DEVNULL)
            sha = hashlib.sha256(image.read_bytes()).hexdigest()
            fd = s.sealed_copy(image, sha)
            mountpoint = root/"mounted"; mountpoint.mkdir(mode=0o700)
            mounted = s.MountedImage(fd,mountpoint)
            try:
                mounted.attach()
                self.assertEqual((mountpoint/"code.py").read_text(),"frozen\n")
                try:
                    self.assertEqual(os.listxattr(mountpoint),[])
                except OSError as error:
                    # Kernel may compile SquashFS without xattr support at all.
                    self.assertEqual(error.errno,errno.EOPNOTSUPP)
                for action in (
                    lambda:(mountpoint/"code.py").write_text("foreign"),
                    lambda:os.chmod(mountpoint/"code.py",0o777),
                    lambda:os.setxattr(mountpoint/"code.py","user.test",b"foreign"),
                    lambda:os.rename(mountpoint/"code.py",mountpoint/"other.py"),
                    lambda:os.write(fd,b"foreign"),
                    lambda:os.ftruncate(fd,1),
                ):
                    with self.assertRaises(OSError) as error: action()
                    self.assertIn(error.exception.errno,(errno.EROFS,errno.EPERM,errno.EOPNOTSUPP))
                image.write_bytes(b"foreign backing path replacement")
                self.assertEqual((mountpoint/"code.py").read_text(),"frozen\n")
                mounted._check_loop()
                s.bind_null_device(mounted)
                null_fd = os.open(mountpoint/"dev/null", os.O_RDWR)
                try:
                    self.assertEqual(os.write(null_fd, b"synthetic"), 9)
                    self.assertEqual(os.read(null_fd, 1), b"")
                finally:
                    os.close(null_fd)
                with self.assertRaises(OSError): os.chmod(mountpoint/"dev/null", 0o777)
                # A second bind cannot adopt the previously exposed device.
                with self.assertRaises(s.SealedRootError): s.bind_null_device(mounted)
                s.run(["/usr/bin/umount", str(mountpoint/"dev/null")])
            finally:
                mounted.close()
                os.close(fd)


if __name__ == "__main__": unittest.main()
