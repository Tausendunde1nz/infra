"""Frozen code/data construction, plus actual isolated PID-1 execution."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import tu1nz_s8_frozen_entry as entry


class FrozenEntryTests(unittest.TestCase):
    def sources(self):
        root = Path(__file__).resolve().parents[1] / "scripts"
        modules = {name: (root / (name + ".py")).read_bytes() for name in entry.MODULES}
        main = b'from tu1nz_s8_execution_contract import SLOT\nprint("S8_FROZEN_PROOF:"+SLOT)\n'
        expected = {name: hashlib.sha256(value).hexdigest() for name, value in {**modules, "entry": main}.items()}
        return modules, main, expected

    def test_exact_source_without_mutable_imports(self):
        modules, main, expected = self.sources()
        program = entry.build(modules, main, expected)
        self.assertEqual(program, entry.build(modules, main, expected))
        result = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", program],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "S8_FROZEN_PROOF:s8-same-release-20261004-1")
        self.assertLess(len(entry.systemd_command(program, "coordinate")), 100100)

    def test_drift_missing_module_and_expansion_reject(self):
        modules, main, expected = self.sources()
        with self.assertRaisesRegex(ValueError, "SOURCE_BINDING_RED"):
            entry.build(modules, main + b"\n", expected)
        with self.assertRaisesRegex(ValueError, "SOURCE_SET_RED"):
            entry.build({}, main, expected)
        for value in ('"', "\\", "$", "%", "\n"):
            with self.assertRaisesRegex(ValueError, "COMMAND_RED"):
                entry.systemd_command("import base64,zlib;" + value, "execute")

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                         os.environ.get("container") == "docker", "disposable PID 1 only")
    def test_pid1_loaded_entry_ignores_mutable_control_path(self):
        modules, main, expected = self.sources()
        program = entry.build(modules, main, expected)
        with tempfile.TemporaryDirectory(prefix="s8-frozen-unit-", dir="/run") as directory:
            root = Path(directory)
            name = "tu1nz-" + root.name + ".service"
            unit = Path("/run/systemd/system") / name
            try:
                unit.write_text("[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                    "Environment=PYTHONPATH=" + str(root) + "\n"
                    "ExecStart=" + entry.systemd_command(program, "coordinate") + "\n")
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                # The Control module name exists on an attacker-controlled
                # search path, but -I/-S and embedded sys.modules exclude it.
                (root / "tu1nz_s8_execution_contract.py").write_text('raise RuntimeError("FOREIGN_IMPORT")\n')
                subprocess.run(["systemctl", "start", name], check=True)
                output = subprocess.check_output(["journalctl", "--no-pager", "-o", "cat", "-u", name], text=True)
                self.assertIn("S8_FROZEN_PROOF:s8-same-release-20261004-1", output)
                self.assertNotIn("FOREIGN_IMPORT", output)
            finally:
                subprocess.run(["systemctl", "stop", name], check=False, capture_output=True)
                if unit.exists(): unit.unlink()
                subprocess.run(["systemctl", "daemon-reload"], check=True)


if __name__ == "__main__": unittest.main()
