"""Actual systemd peer identity + durable fenced one-shot protocol.

No fake PID-1 responses and no Telegram requests. The application/SQL path is
still a separate required integration layer; this suite never claims it.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from tests import test_s8_systemd_boundary as boundary

command = boundary.command


PROTOCOL_FIXTURE = r'''
import hashlib,json,os,pwd,subprocess,sys,time
from datetime import datetime,timedelta,timezone
from pathlib import Path
sys.path.insert(0,"/source/scripts")
from tu1nz_s8_admission_channel import AdmissionChannel,request_once
from tu1nz_s8_execution_contract import *
from tu1nz_s8_protected_journal import ProtectedJournal
from tu1nz_s8_journal_fence import APPEND,add_inode_protection
root=Path(__file__).parent
config=json.loads((root/"config.json").read_text())
mode=sys.argv[1]
clock=lambda:datetime.now(timezone.utc)
if mode=="coordinate":
 directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 add_inode_protection(directory,APPEND);os.close(directory)
 journal=ProtectedJournal(root/"journal")
 channel=AdmissionChannel(root/"channel.sock",config["runtime"])
 started=clock()
 binding=dict(freeze_sha256="a"*64,image_sha256="b"*64)
 grant=dict(schema="TU1NZ_S8_EXECUTION_GRANT_V1",slot=SLOT,incident_invocation=FAILED_INVOCATION,
  freeze_sha256="a"*64,image_sha256="b"*64,human_authorization_sha256="c"*64,
  issued_at=started.isoformat(),expires_at=(started+timedelta(minutes=2)).isoformat())
 journal.once("operation.json",dict(grant_sha256=digest(grant),binding_sha256=digest(binding)))
 identity=process_identity(os.getpid())
 lease=dict(release=LEASE_RELEASE,owner=None,expires=None,revision=LEASE_REVISION,
  last_poll=LAST_POLL,updated=LAST_UPDATE,code="BOT_POLLER_NOT_RUNNING")
 if config["mode"]=="foreign-lease":lease["owner"]="foreign-offline-owner"
 dispatch=subprocess.Popen(["systemd-run","--quiet","--wait","--collect","--unit="+config["dispatch"],
  "--property=Requires="+config["runtime"],"--property=After="+config["runtime"],"/usr/bin/true"],
  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  def condition(invocation,peer):
   consume_condition(journal,invocation=invocation,coordinator=identity,clock=clock,
    observe_lease=lambda:lease,binding=binding,grant=grant)
   return canonical(dict(phase="condition",invocation=invocation))
  def execute(invocation,peer):
   consume_execution(journal,invocation=invocation,clock=clock,binding=binding,grant=grant)
   return canonical(permit_value(journal,invocation=invocation,
    application=dict(commit="d"*40,tree="e"*40),source_hashes={
     name:"f"*64 for name in ("runtime.py","polling.py","recovery_admission.py")},binding=binding,grant=grant))
  channel.accept_once("condition",condition)
  channel.accept_once("execute",execute)
  require(dispatch.wait(timeout=10)==0,"OFFLINE_DISPATCH_RED")
  for _ in range(200):
   if (root/"client-returned.json").exists():break
   time.sleep(.02)
  else:raise RuntimeError("offline client handoff missing")
  journal.once("handoff.json",dict(invocation=channel.invocation,accepted_claim=False))
  journal.handoff()
 finally:
  channel.close();journal.close()
elif mode in ("condition","execute"):
 response=request_once(root/"channel.sock",coordinator_unit=config["coordinator"],
  phase=mode,invocation=os.environ["INVOCATION_ID"])
 payload=json.loads(response)
 if mode=="condition":
  assert payload==dict(phase="condition",invocation=os.environ["INVOCATION_ID"])
 else:
  assert payload["invocation"]==os.environ["INVOCATION_ID"] and payload["slot"]==SLOT
  assert payload["expected_revision"]==LEASE_REVISION
  fd=os.open(root/"client-returned.json",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  os.write(fd,canonical(dict(permit_sha256=hashlib.sha256(response).hexdigest())));os.close(fd)
  account=pwd.getpwnam("nobody")
  os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
  os.execv("/usr/bin/sleep",["sleep","120"])
else:raise SystemExit(2)
'''


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0
                    and os.environ.get("container") == "docker", "disposable systemd Linux only")
class AdmissionChannelTests(boundary.SystemdBoundaryTests):
    # Inode protection needs the disposable disk-backed filesystem, not /run
    # tmpfs or a unit-private /var/tmp view. Never use a production state path.
    temporary_base = "/etc"
    # Inherit only the native fixture methods, not unrelated base test cases.
    test_success_stays_running_but_restarts_never_reexecute = None
    test_coordinator_kill_stops_runtime_without_retry = None
    test_existing_failed_unit_is_not_rearmed_or_confused_with_a_fresh_unit = None
    test_condition_interruption_before_journal_still_cannot_start_again = None

    def setUp(self):
        super().setUp()
        (self.root / "fixture.py").write_text(PROTOCOL_FIXTURE)

    def start(self, mode):
        (self.root / "config.json").write_text(json.dumps(dict(
            mode=mode, runtime=self.runtime, coordinator=self.coordinator, dispatch=self.dispatch)))
        return subprocess.Popen(["systemctl", "start", self.coordinator],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def tearDown(self):
        import array
        import fcntl
        command("systemctl", "stop", self.runtime, self.coordinator, check=False)
        # Reset only this test's disposable objects after all actors stop.
        paths = list((self.root / "journal").iterdir()) if (self.root / "journal").exists() else []
        if (self.root / "journal").exists():
            paths.append(self.root / "journal")
        paths.append(self.root)
        for path in paths:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                raw = array.array("L", [0])
                fcntl.ioctl(fd, 0x80086601, raw, True)
                raw[0] &= ~0x30
                fcntl.ioctl(fd, 0x40086602, raw)
            finally:
                os.close(fd)
        super().tearDown()

    def test_actual_pid1_condition_and_execution_share_one_durable_invocation(self):
        job = self.start("success")
        self.assertEqual(job.wait(timeout=40), 0, command("journalctl", "-u", self.coordinator,
                         "-u", self.runtime, "--no-pager", "-n", "25").stdout)
        self.assertEqual(self.prop(self.runtime, "ActiveState"), "active")
        self.assertEqual(self.prop(self.runtime, "NRestarts"), "0")
        journal = self.root / "journal"
        records = {p.name: json.loads(p.read_bytes()) for p in journal.iterdir()}
        self.assertEqual(set(records), {"operation.json", "activation.json", "execution.json", "handoff.json"})
        invocation = self.prop(self.runtime, "InvocationID")
        self.assertEqual(records["activation.json"]["invocation"], invocation)
        self.assertEqual(records["execution.json"]["invocation"], invocation)
        self.assertIs(records["handoff.json"]["accepted_claim"], False)
        before = {p.name: p.read_bytes() for p in journal.iterdir()}
        self.assertNotEqual(command("systemctl", "restart", self.coordinator, check=False).returncode, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in journal.iterdir()})

    def test_foreign_lease_rejects_after_durable_activation_without_execution(self):
        job = self.start("foreign-lease")
        self.assertNotEqual(job.wait(timeout=40), 0)
        journal = self.root / "journal"
        self.assertTrue((journal / "activation.json").is_file())
        self.assertFalse((journal / "execution.json").exists())
        self.assertFalse((self.root / "client-returned.json").exists())
        self.assertNotEqual(self.prop(self.runtime, "ActiveState"), "active")
        before = {p.name: p.read_bytes() for p in journal.iterdir()}
        self.assertNotEqual(command("systemctl", "start", self.coordinator, check=False).returncode, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in journal.iterdir()})


if __name__ == "__main__":
    unittest.main()
