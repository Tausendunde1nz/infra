"""Real Linux mount/seal/ACL tests in a disposable privileged child namespace."""
import errno
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts import tu1nz_s8_sealed_root as s


class MountedCleanupTests(unittest.TestCase):
    """Pure fault injection: no mount, device, host or blocked namespace probe."""
    def mounted(self):
        mounted = object.__new__(s.MountedImage)
        mounted.loop_fd, mounted.attached, mounted.mounted = 701, True, True
        mounted.original_device = 1
        mounted.destination = SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=2))
        return mounted

    def test_identity_failure_keeps_primary_no_foreign_unmount_or_close_retry(self):
        mounted = self.mounted()
        primary = s.SealedRootError("S8_EXECUTION_LOOP_IDENTITY_RED")
        primary._s8_abort_error = dict(code="S8_EXECUTION_ABORT_RED")
        with patch.object(mounted, "_check_loop", side_effect=primary), \
                patch.object(s, "run") as run, \
                patch.object(s.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaises(s.SealedRootError) as result: mounted.close()
            mounted.close()
        self.assertIs(result.exception, primary)
        self.assertIsNone(mounted.loop_fd)
        self.assertTrue(mounted.mounted)
        self.assertEqual(primary._s8_abort_error["code"], "S8_EXECUTION_ABORT_RED")
        self.assertEqual(primary._s8_cleanup_errors, [dict(type="OSError", code="UNKNOWN")])
        close.assert_called_once_with(701)
        run.assert_not_called()

    def test_unmount_failure_remains_primary_and_owned_fd_is_released(self):
        mounted = self.mounted()
        primary = s.SealedRootError("S8_EXECUTION_MOUNT_COMMAND_RED")
        with patch.object(mounted, "_check_loop"), \
                patch.object(s.os, "fstat", return_value=SimpleNamespace(st_rdev=2)), \
                patch.object(s, "run", side_effect=primary) as run, \
                patch.object(s.os, "close", side_effect=OSError("private")) as close:
            with self.assertRaises(s.SealedRootError) as result: mounted.close()
            mounted.close()
        self.assertIs(result.exception, primary)
        self.assertTrue(mounted.mounted)
        run.assert_called_once()
        close.assert_called_once_with(701)


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
