"""Real durable pre-start consumption; test-owned native Linux/PID 1 only."""
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tu1nz_s8_execution_contract import ContractError
from tu1nz_s8_dispatch_boundary import DispatchBoundary
from tu1nz_s8_journal_fence import APPEND, add_inode_protection
import tu1nz_s8_frozen_entry as frozen


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                    os.environ.get("container") == "docker", "disposable native PID 1 only")
class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tu1nz-dispatch-", dir="/etc")
        self.root = Path(self.temporary.name)
        self.name = self.root.name.replace("_", "-") + ".service"
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try: add_inode_protection(fd, APPEND)
        finally: os.close(fd)

    def tearDown(self):
        subprocess.run(["systemctl", "stop", self.name], capture_output=True)
        # Exact disposable test objects; no reset/flag-removal live API.
        paths = list(self.root.rglob("*"))
        for path in sorted([*paths, self.root], key=lambda p: len(p.parts), reverse=True):
            if path.is_socket(): continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                value = array.array("L", [0]); fcntl.ioctl(fd, 0x80086601, value, True)
                value[0] &= ~0x30; fcntl.ioctl(fd, 0x40086602, value)
            finally: os.close(fd)
        self.temporary.cleanup()

    def test_unknown_start_and_repeated_dispatch_never_call_pid1_twice(self):
        boundary = DispatchBoundary(self.root, self.name, "a" * 64)
        calls = []
        def unknown():
            calls.append(1)
            raise TimeoutError("synthetic lost start acknowledgement")
        with self.assertRaises(TimeoutError): boundary.issue_once(unknown)
        before = {p.name: p.read_bytes() for p in (self.root / "dispatch").iterdir()}
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED"):
            boundary.issue_once(unknown)
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED"):
            DispatchBoundary(self.root, self.name, "a" * 64)
        self.assertEqual(calls, [1])
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / "dispatch").iterdir()})

    def test_interruption_before_pid1_preserves_consumption(self):
        pid = os.fork()
        if pid == 0:
            boundary = DispatchBoundary(self.root, self.name, "a" * 64)
            # No Python cleanup: model power/process loss before start call.
            os._exit(0)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
        self.assertTrue((self.root / "dispatch/dispatch-intent.json").is_file())
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED"):
            DispatchBoundary(self.root, self.name, "a" * 64)

    def test_actual_pid1_can_receive_once_but_new_invocation_cannot(self):
        boundary = DispatchBoundary(self.root, self.name, "a" * 64)
        sources = {name: (Path("/source/scripts") / (name + ".py")).read_bytes() for name in frozen.MODULES}
        main = ("from pathlib import Path\nfrom tu1nz_s8_dispatch_boundary import receive_once\n"
                f"receive_once(Path({str(self.root)!r}),coordinator={self.name!r},"
                f"owner={boundary.owner!r},binding_sha256={'a' * 64!r})\n").encode()
        expected = {name: hashlib.sha256(value).hexdigest() for name, value in {**sources, "entry": main}.items()}
        program = frozen.build(sources, main, expected)
        args = ["systemd-run", "--quiet", "--wait", "--collect", "--unit=" + self.name,
                "--property=Type=oneshot", "/usr/bin/python3", "-I", "-B", "-S", "-c", program]
        job = boundary.issue_once(lambda: subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.assertEqual(job.wait(timeout=20), 0)
        receipt = json.loads((self.root / "dispatch/dispatch-handoff.json").read_bytes())
        self.assertEqual(receipt["binding_sha256"], "a" * 64)
        before = {p.name: p.read_bytes() for p in (self.root / "dispatch").iterdir()}
        replay = subprocess.run(args, capture_output=True, timeout=20)
        self.assertNotEqual(replay.returncode, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / "dispatch").iterdir()})

    def test_foreign_root_process_gets_no_handoff(self):
        boundary = DispatchBoundary(self.root, self.name, "a" * 64)
        program = ("import socket,json\n"
            "s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)\n"
            f"s.connect({str(self.root / 'dispatch.sock')!r})\n"
            f"s.send(json.dumps(dict(invocation={'b' * 32!r},binding_sha256={'a' * 64!r}),"
            "sort_keys=True,separators=(',',':')).encode())\n"
            "assert not s.recv(64)\n")
        children = []
        def start():
            child = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "-S", "-c", program])
            children.append(child)
            return child
        with self.assertRaisesRegex(ContractError, "CHANNEL_PID1_ROLE_RED"):
            boundary.issue_once(start)
        self.assertEqual(children[0].wait(timeout=10), 0)
        self.assertFalse((self.root / "dispatch/dispatch-handoff.json").exists())
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED"):
            DispatchBoundary(self.root, self.name, "a" * 64)


if __name__ == "__main__": unittest.main()
