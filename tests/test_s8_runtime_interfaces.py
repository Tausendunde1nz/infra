"""No provider calls: strict content and resolver interface grammar."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tu1nz_s8_execution_contract import ContractError
from tu1nz_s8_runtime_interfaces import CONFIG_NAMES, configuration_inputs, resolver_input
from tu1nz_s8_runtime_interfaces import mount_configuration
import tu1nz_s8_sealed_root as sealed


class RuntimeInterfaceTests(unittest.TestCase):
    def test_exact_configuration_set_and_bytes(self):
        values = {name: b'{}\n' for name in CONFIG_NAMES}
        expected = {name: hashlib.sha256(value).hexdigest() for name, value in values.items()}
        self.assertEqual(configuration_inputs(values, expected), values)
        for wrong in ({**values, "unexpected": b"x"}, {k: v for k, v in values.items() if k != CONFIG_NAMES[0]},
                      {**values, CONFIG_NAMES[0]: b"foreign"}):
            with self.assertRaises(ContractError): configuration_inputs(wrong, expected)

    def test_bounded_os_dns_snapshot(self):
        values = (b"nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch example.invalid\n",
                  b"# synthetic\nnameserver ::1\nnameserver 192.0.2.53\noptions timeout:2 attempts:2\n")
        for value in values: self.assertEqual(resolver_input(value), value)

    def test_unknown_or_ambiguous_dns_rejected(self):
        for value in (b"", b"nameserver 0.0.0.0\n", b"nameserver 224.0.0.1\n", b"nameserver localhost\n",
                      b"nameserver ::1\noptions debug\n", b"nameserver ::1\noptions timeout:20\n",
                      b"nameserver ::1\nnameserver ::1\n", b"nameserver ::1\nsearch bad;domain other\noption bad\n",
                      b"nameserver ::1\nsearch example.invalid\nsearch other.invalid\n", b"nameserver ::1\0",
                      b"nameserver ::1\nlookup file bind\n", b"nameserver ::1\n" * 1000):
            with self.subTest(value=value[:80]), self.assertRaises(ContractError): resolver_input(value)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                    os.environ.get("container") == "docker", "disposable native kernel only")
class NativeConfigurationTests(unittest.TestCase):
    def test_readonly_interfaces_do_not_replace_permit_root_or_import_paths(self):
        with tempfile.TemporaryDirectory(prefix="s8-config-test-", dir="/var/tmp") as temporary:
            child = os.fork()
            if child == 0:
                try: self.probe(Path(temporary))
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    os._exit(1)
                os._exit(0)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 0)

    def probe(self, parent):
        sealed.private_namespace()
        tree = parent / "tree"
        for name in ("etc/tu1nz/s8-atomic-admission-r1", "run/s8-configuration", "application"):
            (tree / name).mkdir(parents=True)
        for name in CONFIG_NAMES: (tree / "etc/tu1nz" / name).touch()
        (tree / "etc/resolv.conf").touch()
        image = parent / "image.squashfs"
        subprocess.run(["mksquashfs", str(tree), str(image), "-noappend", "-no-xattrs", "-all-root",
                        "-processors", "1", "-no-progress"], check=True, stdout=subprocess.DEVNULL)
        fd = sealed.sealed_copy(image, hashlib.sha256(image.read_bytes()).hexdigest())
        root = parent / "mounted"; root.mkdir(mode=0o700)
        mounted = sealed.MountedImage(fd, root).attach()
        values = {name: b'{"synthetic":true}\n' for name in CONFIG_NAMES}
        expected = {name: hashlib.sha256(payload).hexdigest() for name, payload in values.items()}
        resolver = b"nameserver 127.0.0.53\noptions edns0 trust-ad\n"
        try:
            mount_configuration(mounted, values, expected, resolver)
            self.assertEqual((root / "etc/resolv.conf").read_bytes(), resolver)
            for name in CONFIG_NAMES:
                path = root / "etc/tu1nz" / name
                self.assertEqual(path.read_bytes(), values[name])
                for mutate in (lambda: path.write_bytes(b"foreign"), lambda: path.chmod(0o777),
                               lambda: os.setxattr(path, "user.writer", b"foreign")):
                    with self.assertRaises(OSError): mutate()
            with self.assertRaises(OSError): (root / "etc/resolv.conf").write_bytes(b"foreign")
            for name in ("application", "etc/tu1nz/s8-atomic-admission-r1"):
                self.assertEqual((root / name).stat().st_dev, root.stat().st_dev)
            # Keep the existing permit interface's independent image-object
            # predicate. Configuration cannot mint, replace or relax it.
            sealed.private_permit(mounted, b'{"synthetic":true}')
            self.assertEqual((root / "etc/tu1nz/s8-atomic-admission-r1/permit.json").read_bytes(),
                             b'{"synthetic":true}')
            sealed.run(["/usr/bin/umount", str(root / "etc/tu1nz/s8-atomic-admission-r1")])
            with self.assertRaises(ContractError): mount_configuration(mounted, values, expected, resolver)
        finally:
            for name in ("etc/resolv.conf", *("etc/tu1nz/" + name for name in CONFIG_NAMES), "run/s8-configuration"):
                sealed.run(["/usr/bin/umount", str(root / name)])
            mounted.close(); os.close(fd)


if __name__ == "__main__": unittest.main()
