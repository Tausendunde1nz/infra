"""Native PID-1 overlay proof. Disposable units only, no live provisioning."""
import array
import fcntl
import os
from pathlib import Path
import sys
import unittest

from tests import test_s8_systemd_boundary as boundary
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from tu1nz_s8_execution_units import runtime_dropin


def flag(path,value):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:fcntl.ioctl(fd,0x40086602,array.array("L",[value]))
    finally:os.close(fd)


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0 and
                    os.environ.get("container")=="docker","isolated PID 1 only")
class PersistentUnitInterlockTests(unittest.TestCase):
    def test_legacy_base_restore_cannot_restore_normal_claim_or_restart(self):
        fixture=boundary.SystemdBoundaryTests(methodName="test_success_stays_running_but_restarts_never_reexecute")
        fixture.setUp()
        directory=Path("/etc/systemd/system")/(fixture.runtime+".d")
        path=directory/"90-s8-atomic.conf"
        try:
            # This isolated component sets protection before loading the unit.
            # Complete writer-fenced provisioning is a separate integrated gate.
            directory.mkdir(mode=0o755)
            text=runtime_dropin(fixture.root/"fixture.py",runtime=fixture.runtime,
                coordinator=fixture.coordinator,runtime_user="nobody",runtime_group="nogroup")
            text="\n".join(line for line in text.splitlines() if not line.startswith(
                ("ReadWritePaths=","LoadCredential=","InaccessiblePaths=")))
            text+="\nReadWritePaths="+str(fixture.root)+"\nLoadCredential=offline_probe:"+str(fixture.root/"offline-credential")+"\n"
            path.write_text(text);path.chmod(0o644)
            flag(path,0x10);flag(directory,0x10)
            boundary.command("systemctl","daemon-reload")
            self.assertEqual(fixture.start("success").wait(timeout=20),0)
            base=Path("/run/systemd/system")/fixture.runtime
            normal=fixture.root/"forbidden-normal-start"
            base.write_text("[Service]\nType=simple\nExecStart=/usr/bin/touch "+str(normal)+
                            "\nExecStartPre=/usr/bin/touch "+str(normal)+"\nRestart=always\n")
            boundary.command("systemctl","daemon-reload")
            self.assertEqual(fixture.prop(fixture.runtime,"Restart"),"no")
            self.assertEqual(fixture.prop(fixture.runtime,"RefuseManualStart"),"yes")
            self.assertEqual(fixture.prop(fixture.runtime,"ExecStartPre"),"")
            self.assertNotIn("touch",fixture.prop(fixture.runtime,"ExecStart"))
            before={p.name:p.read_bytes() for p in fixture.root.glob("*.json")}
            self.assertNotEqual(boundary.command("systemctl","restart",fixture.runtime,check=False).returncode,0)
            self.assertFalse(normal.exists())
            self.assertEqual(before,{p.name:p.read_bytes() for p in fixture.root.glob("*.json")})
            with self.assertRaises(OSError):path.write_text("[Service]\nExecStart=/usr/bin/true\n")
            with self.assertRaises(OSError):path.unlink()
            with self.assertRaises(OSError):path.chmod(0o666)
            with self.assertRaises(OSError):(directory/"99-bypass.conf").write_text("[Unit]\nRefuseManualStart=no\n")
        finally:
            # Exact test-owned objects only; no production reset/remove API.
            if directory.exists():flag(directory,0)
            if path.exists():flag(path,0);path.unlink()
            if directory.exists():directory.rmdir()
            fixture.tearDown()


if __name__=="__main__":unittest.main()
