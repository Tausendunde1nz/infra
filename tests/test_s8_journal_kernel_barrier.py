"""Native persistent-inode protection probe, isolated containers only.

Root file writers are not exempt: writes, truncation, chmod and unlink must
fail. Changing immutable flags with CAP_LINUX_IMMUTABLE is privileged kernel
administration, not an allowed recovery action. Cleanup does it ONLY on the
exact disposable objects this test created. No production journal is touched.
"""
import array
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from tu1nz_s8_journal_fence import NewJournalFence
from tu1nz_s8_execution_contract import ContractError

GET_FLAGS=0x80086601
SET_FLAGS=0x40086602
APPEND=0x20
IMMUTABLE=0x10


def flags(fd):
    value=array.array("L",[0]);fcntl.ioctl(fd,GET_FLAGS,value,True)
    return value[0]


def set_flags(fd,value):
    fcntl.ioctl(fd,SET_FLAGS,array.array("L",[value]))
    assert flags(fd)==value


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0 and
                    os.environ.get("container")=="docker", "disposable privileged Linux only")
class KernelJournalBarrierTests(unittest.TestCase):
    def test_kernel_flag_seal_does_not_hide_a_chmod_in_the_event_allowlist(self):
        with tempfile.TemporaryDirectory(prefix="s8-inode-events-",dir="/var/tmp") as temporary:
            path=Path(temporary)/"probe";path.write_bytes(b"bound")
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);old=flags(fd)
            libc=ctypes.CDLL(None,use_errno=True)
            listener=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
            self.assertGreaterEqual(listener,0)
            try:
                self.assertGreaterEqual(libc.inotify_add_watch(listener,os.fsencode(temporary),0x4),0)
                set_flags(fd,old|IMMUTABLE)
                with self.assertRaises(BlockingIOError):os.read(listener,65536)
            finally:
                set_flags(fd,old);os.close(fd);os.close(listener)

    def protected_root(self):
        temporary=tempfile.TemporaryDirectory(prefix="s8-fenced-journal-",dir="/var/tmp")
        root=Path(temporary.name)/"journal";root.mkdir(mode=0o700)
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        old=flags(fd);set_flags(fd,old|APPEND)
        return temporary,root,fd,old

    def test_single_writer_fence_before_creation_and_immutable_handoff(self):
        temporary,root,directory,old=self.protected_root()
        fence=None;read_fd=None;record_flags=None
        try:
            fence=NewJournalFence(root)
            record=root/"operation.json"
            fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            os.write(fd,b"bound");os.fsync(fd);os.close(fd)
            fence.check()
            read_fd=os.open(record,os.O_RDONLY|os.O_NOFOLLOW)
            record_flags=flags(read_fd)
            set_flags(read_fd,record_flags|IMMUTABLE)
            fence.check()
            fence.close();fence=None
            with self.assertRaises(PermissionError):record.write_bytes(b"other")
            self.assertEqual(record.read_bytes(),b"bound")
        finally:
            if fence is not None:fence.close()
            if read_fd is not None:
                if record_flags is not None:set_flags(read_fd,record_flags)
                os.close(read_fd)
            set_flags(directory,old);os.close(directory);temporary.cleanup()

    def test_foreign_root_open_before_sealing_is_denied_and_invalidates_operation(self):
        temporary,root,directory,old=self.protected_root()
        fence=None
        try:
            fence=NewJournalFence(root)
            record=root/"operation.json"
            fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            os.write(fd,b"bound");os.close(fd)
            child=os.fork()
            if child==0:
                try:record.write_bytes(b"other")
                except PermissionError:os._exit(0)
                except BaseException:os._exit(2)
                os._exit(1)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child,0)[1]),0)
            with self.assertRaisesRegex(ContractError,"JOURNAL_FOREIGN_OPEN_RED"):fence.check()
            self.assertEqual(record.read_bytes(),b"bound")
        finally:
            if fence is not None:fence.close()
            set_flags(directory,old);os.close(directory);temporary.cleanup()

    def test_restored_foreign_metadata_change_is_not_content_equality(self):
        temporary,root,directory,old=self.protected_root()
        fence=None
        try:
            fence=NewJournalFence(root)
            record=root/"operation.json"
            fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
            child=os.fork()
            if child==0:
                try:record.chmod(0o640);record.chmod(0o600)
                except BaseException:os._exit(2)
                os._exit(0)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child,0)[1]),0)
            with self.assertRaisesRegex(ContractError,"JOURNAL_METADATA_EVENT_RED"):fence.check()
        finally:
            if fence is not None:fence.close()
            set_flags(directory,old);os.close(directory);temporary.cleanup()

    def test_completed_record_and_partial_slot_cannot_be_removed_by_new_root_writer(self):
        with tempfile.TemporaryDirectory(prefix="s8-journal-kernel-",dir="/var/tmp") as temporary:
            root=Path(temporary)/"journal";root.mkdir(mode=0o700)
            directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            old_directory=flags(directory)
            record_fd=None;old_record=None
            try:
                set_flags(directory,old_directory|APPEND)
                record=root/"operation.json"
                record_fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                os.write(record_fd,b'{"consumed":true}');os.fsync(record_fd)
                # An immutable inode does NOT revoke an already-open writable
                # descriptor. The separate guard must exclude such handles.
                os.close(record_fd)
                record_fd=os.open(record,os.O_RDONLY|os.O_NOFOLLOW)
                old_record=flags(record_fd)
                set_flags(record_fd,old_record|IMMUTABLE)
                os.fsync(directory)
                for name,action in (("write",lambda:record.write_bytes(b"forged")),
                               ("chmod",lambda:record.chmod(0o666)),("unlink",lambda:record.unlink()),
                               ("rename-record",lambda:record.rename(root/"moved.json")),
                               ("rename-directory",lambda:root.rename(root.with_name("moved")))):
                    with self.assertRaises(OSError,msg=name) as error:action()
                    self.assertEqual(error.exception.errno,errno.EPERM)
                # Interruption before a file is filled/sealed is still
                # consuming: the protected directory forbids removing it.
                partial=root/"activation.json"
                fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
                with self.assertRaises(OSError) as error:partial.unlink()
                self.assertEqual(error.exception.errno,errno.EPERM)
                with self.assertRaises(FileExistsError):os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                self.assertEqual(record.read_bytes(),b'{"consumed":true}')
            finally:
                if record_fd is not None:
                    if old_record is not None:set_flags(record_fd,old_record)
                    os.close(record_fd)
                set_flags(directory,old_directory)
                os.close(directory)

    def test_immutable_flag_is_not_write_handle_revocation(self):
        with tempfile.TemporaryDirectory(prefix="s8-retained-handle-",dir="/var/tmp") as temporary:
            path=Path(temporary)/"probe"
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            old=flags(fd)
            try:
                os.write(fd,b"initial")
                set_flags(fd,old|IMMUTABLE)
                # Counterexample retained as evidence: flags alone must never
                # be accepted as writer exclusion by the live contract.
                os.ftruncate(fd,0)
                self.assertEqual(path.stat().st_size,0)
            finally:
                set_flags(fd,old);os.close(fd)


if __name__=="__main__":unittest.main()
