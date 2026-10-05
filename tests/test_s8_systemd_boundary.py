"""Native PID-1 proof; only disposable Linux containers may run this suite.

No Telegram/network/production database. Actual systemd dependency, SIGKILL,
rate-limit and re-exec semantics, not mocks. SQL integration is a separate gate.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from tu1nz_s8_execution_units import render


FIXTURE = r'''
import json,os,subprocess,sys,time
from pathlib import Path
root=Path(__file__).parent
config=json.loads((root/"config.json").read_text())
def once(name):
 fd=os.open(root/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 try:os.write(fd,b"spent\n");os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
mode=sys.argv[1]
if mode=="coordinate":
 once("coordinator.json")
 subprocess.run(["systemd-run","--quiet","--wait","--collect","--unit="+config["dispatch"],
   "--property=Requires="+config["runtime"],"--property=After="+config["runtime"],"/usr/bin/true"],check=True)
 for _ in range(100):
  if (root/"executed.json").exists():break
  time.sleep(.05)
 else:raise SystemExit(2)
 if config["mode"]=="coordinator-kill":
  (root/"kill-ready").write_text("ready")
  time.sleep(120)
elif mode=="condition":
 if config["mode"]=="before-condition-kill":
  (root/"condition-ready").write_text("ready")
  time.sleep(120)
 once("activation.json")
elif mode=="execute":
 once("executed.json")
 os.execv("/usr/bin/sleep",["sleep","120"])
else:raise SystemExit(2)
'''


def command(*args, check=True):
    return subprocess.run(args,capture_output=True,text=True,timeout=45,check=check)


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0 and
                    os.environ.get("container")=="docker", "disposable systemd container only")
class SystemdBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="tu1nz-s8-test-",dir="/run")
        self.root=Path(self.temp.name)
        suffix=self.root.name.replace("_","-")
        self.runtime=suffix+"-runtime.service";self.coordinator=suffix+"-coordinator.service"
        self.dispatch=suffix+"-dispatch.service"
        fixture=self.root/"fixture.py";fixture.write_text(FIXTURE)
        self.units=render(fixture,runtime=self.runtime,coordinator=self.coordinator)
        for name,content in self.units.items():
            # Fixtures have no real credentials or historical directories.
            # Keep rate limits, Restart, BindsTo, RefuseManualStart, type and
            # condition/start wiring exactly as rendered by production source.
            content="\n".join(line for line in content.splitlines() if not
                              line.startswith(("LoadCredential=","ReadWritePaths=","InaccessiblePaths=")))
            content+="\nReadWritePaths="+str(self.root)+"\n"
            (Path("/run/systemd/system")/name).write_text(content)
        command("systemctl","daemon-reload")

    def tearDown(self):
        command("systemctl","stop",self.runtime,self.coordinator,check=False)
        for name in self.units:
            (Path("/run/systemd/system")/name).unlink()
        command("systemctl","daemon-reload")
        self.temp.cleanup()

    def start(self,mode):
        (self.root/"config.json").write_text(json.dumps(dict(mode=mode,runtime=self.runtime,dispatch=self.dispatch)))
        return subprocess.Popen(["systemctl","start",self.coordinator],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    def until(self,predicate):
        end=time.monotonic()+15
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        self.fail("native systemd phase deadline")

    def prop(self,unit,key):
        return command("systemctl","show",unit,"--value","--property="+key).stdout.strip()

    def test_success_stays_running_but_restarts_never_reexecute(self):
        job=self.start("success")
        self.assertEqual(job.wait(timeout=20),0)
        self.assertEqual(self.prop(self.runtime,"ActiveState"),"active")
        self.assertEqual(self.prop(self.coordinator,"SubState"),"exited")
        self.assertEqual(self.prop(self.runtime,"NRestarts"),"0")
        before={p.name:p.read_bytes() for p in self.root.glob("*.json")}
        self.assertNotEqual(command("systemctl","restart",self.runtime,check=False).returncode,0)
        self.assertNotEqual(command("systemctl","restart",self.coordinator,check=False).returncode,0)
        self.until(lambda:self.prop(self.runtime,"ActiveState")!="active")
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.glob("*.json")})

    def test_coordinator_kill_stops_runtime_without_retry(self):
        job=self.start("coordinator-kill")
        self.until(lambda:(self.root/"kill-ready").exists())
        pid=int(self.prop(self.coordinator,"MainPID"));self.assertGreater(pid,1)
        os.kill(pid,signal.SIGKILL)
        self.assertNotEqual(job.wait(timeout=20),0)
        self.until(lambda:self.prop(self.runtime,"ActiveState")!="active")
        self.assertEqual(self.prop(self.runtime,"NRestarts"),"0")
        self.assertNotEqual(command("systemctl","start",self.coordinator,check=False).returncode,0)

    def test_condition_interruption_before_journal_still_cannot_start_again(self):
        job=self.start("before-condition-kill")
        self.until(lambda:(self.root/"condition-ready").exists())
        pid=int(self.prop(self.runtime,"ControlPID"));self.assertGreater(pid,1)
        os.kill(pid,signal.SIGKILL)
        self.assertNotEqual(job.wait(timeout=20),0)
        self.assertFalse((self.root/"activation.json").exists())
        self.assertFalse((self.root/"executed.json").exists())
        self.assertNotEqual(command("systemctl","start",self.coordinator,check=False).returncode,0)
        self.assertNotEqual(command("systemctl","start",self.runtime,check=False).returncode,0)
        # A manager re-exec is not a reset of persistent attempt authority.
        command("systemctl","daemon-reexec")
        self.assertNotEqual(command("systemctl","start",self.coordinator,check=False).returncode,0)
        self.assertFalse((self.root/"executed.json").exists())


if __name__=="__main__":unittest.main()
