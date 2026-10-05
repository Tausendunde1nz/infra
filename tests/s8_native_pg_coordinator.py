"""Isolated native integration fixture; not a live controller or fallback.

The only external interfaces are this container's PID 1 and a synthetic local
PostgreSQL Unix socket. No network/provider calls and no historical roots.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/source/scripts")
import tu1nz_s8_execution_contract as c
import tu1nz_s8_sealed_root as sealed
from tu1nz_s8_admission_channel import AdmissionChannel, request_once, properties
from tu1nz_s8_protected_journal import ProtectedJournal
from tu1nz_s8_journal_fence import APPEND, add_inode_protection


def sql(query):
    value = subprocess.run(["/usr/bin/psql", "-X", "-qAt", "--set=ON_ERROR_STOP=1",
        "postgresql://tu1nz_test@/tu1nz_s8_exec_native?host=/run/postgresql", "--command", query],
        capture_output=True, text=True, timeout=10, check=True)
    return value.stdout.strip()


def lease():
    # Only synthetic rows in the isolated database. No production identifiers
    # or payload columns; owner is represented as a digest for evidence.
    value = json.loads(sql("""SELECT json_build_object(
      'release',release_id,'owner',lease_owner_id,'expires',lease_expires_at,
      'revision',revision,'last_poll',last_successful_poll_at,'updated',updated_at,
      'code',last_event_path_code) FROM commercial_s10_2d_bot_polling_state"""))
    for key in ("expires", "last_poll", "updated"):
        if value[key] is not None:
            value[key] = datetime.fromisoformat(value[key]).isoformat()
    return value


def records(invocation, pid):
    result = subprocess.run(["/usr/bin/journalctl", "--no-pager", "--output=json",
         "_SYSTEMD_INVOCATION_ID=" + invocation, "_PID=" + str(pid)],
         capture_output=True, text=True, timeout=5, check=True)
    output = []
    for line in result.stdout.splitlines():
        item = json.loads(line)
        try:
            payload = json.loads(item.get("MESSAGE", ""))
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict) and payload.get("event") in {
            "S8_EXECUTION_ROOT_ATTESTED", "S8_ATOMIC_ADMISSION_ACCEPTED", "BOT_EVENT_PATH_RED",
            "S8_RUNTIME_STARTUP_RED", "S8_PUBLIC_TELEGRAM_READY"}:
            output.append(payload)
    return output


def main():
    c.require(os.environ.get("container") == "docker" and Path("/.dockerenv").is_file(),
              "ISOLATED_NATIVE_CONTAINER_REQUIRED")
    root = Path(sys.argv[1])
    mode = sys.argv[2]
    config = json.loads((root / "fixture.json").read_bytes())
    c.require(config["live_authority"] is False, "ISOLATED_NATIVE_CONTAINER_REQUIRED")
    if mode == "coordinate":
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        add_inode_protection(fd, APPEND)
        os.close(fd)
        journal = ProtectedJournal(root / "journal")
        channel = AdmissionChannel(root / "channel.sock", c.UNIT)
        now = lambda: datetime.now(timezone.utc)
        started = now()
        binding = dict(freeze_sha256="a" * 64, image_sha256=config["image_sha256"])
        grant = dict(schema="TU1NZ_S8_EXECUTION_GRANT_V1", slot=c.SLOT,
            incident_invocation=c.FAILED_INVOCATION, freeze_sha256=binding["freeze_sha256"],
            image_sha256=binding["image_sha256"], human_authorization_sha256="c" * 64,
            issued_at=started.isoformat(), expires_at=(started + timedelta(minutes=3)).isoformat())
        journal.once("operation.json", dict(grant_sha256=c.digest(grant), binding_sha256=c.digest(binding)))
        coordinator = c.process_identity(os.getpid())
        dispatch = subprocess.Popen(["systemd-run", "--quiet", "--wait", "--collect",
            "--unit=" + config["dispatch"], "--property=Requires=" + c.UNIT,
            "--property=After=" + c.UNIT, "/usr/bin/true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        permit = None
        try:
            def condition(invocation, _peer):
                c.consume_condition(journal, invocation=invocation, coordinator=coordinator, clock=now,
                    observe_lease=lease, binding=binding, grant=grant)
                return c.canonical(dict(phase="condition", invocation=invocation))

            def execution(invocation, _peer):
                nonlocal permit
                c.consume_execution(journal, invocation=invocation, clock=now, binding=binding, grant=grant)
                permit = c.canonical(c.permit_value(journal, invocation=invocation,
                    application=config["application"], source_hashes=config["sources"], binding=binding, grant=grant))
                return permit

            channel.accept_once("condition", condition)
            channel.accept_once("execute", execution)
            c.require(dispatch.wait(timeout=10) == 0, "NATIVE_DISPATCH_RED")
            previous = None
            accepted = None
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                state = properties(c.UNIT)
                pid = int(state["MainPID"])
                c.require(state["ActiveState"] == "active" and pid > 1, "NATIVE_RUNTIME_RED")
                evidence = records(channel.invocation, pid)
                roots = [v for v in evidence if v["event"] == "S8_EXECUTION_ROOT_ATTESTED"]
                admissions = [v for v in evidence if v["event"] == "S8_ATOMIC_ADMISSION_ACCEPTED"]
                c.require(not any(v["event"].endswith("RED") for v in evidence), "NATIVE_RUNTIME_RED")
                if len(admissions) == 1 and len(roots) == 1:
                    c.initial_receipt(admissions[0], permit, channel.invocation)
                    c.require(roots[0]["application"] == config["application"]
                              and roots[0]["image_sha256"] == config["image_sha256"], "NATIVE_ROOT_RED")
                    snapshot = lease()
                    c.require(snapshot["owner"] is not None, "NATIVE_OWNER_LOST")
                    snapshot["owner"] = hashlib.sha256(snapshot["owner"].encode()).hexdigest()
                    c.require(snapshot["owner"] == admissions[0]["owner_sha256"]
                              and c.utc(snapshot["expires"]) > now(), "NATIVE_OWNER_LOST")
                    if snapshot["last_poll"] is None or c.utc(snapshot["last_poll"]) < started:
                        time.sleep(.1)
                        continue
                    processes = (Path("/sys/fs/cgroup/system.slice") / c.UNIT / "cgroup.procs").read_text().split()
                    c.require(processes == [str(pid)], "NATIVE_CGROUP_PROCESS_RED")
                    observation = dict(invocation=channel.invocation, pid=pid,
                        start_ticks=c.process_identity(pid)["start_ticks"], poller_count=len(processes),
                        restarts=int(state["NRestarts"]), active=state["ActiveState"], sub=state["SubState"],
                        execution_root_verified=True, lease=snapshot, observed_at=now().isoformat())
                    # No synthetic poll substitution: pulse/renew are the real
                    # runtime SQL path. The external Telegram transport alone
                    # is a no-network empty-response stub in the App harness.
                    if c.poll_acceptance(observation, admissions[0], invocation=channel.invocation,
                                         after=started, previous=previous):
                        accepted = dict(initial=admissions[0], poll=observation, provider_calls=0,
                                        live_authority=False, production_entrypoint=False)
                        break
                    previous = observation
                else:
                    c.require(len(admissions) <= 1 and len(roots) <= 1, "NATIVE_DUPLICATE_RECEIPT")
                time.sleep(.3)
            c.require(accepted is not None, "NATIVE_RECEIPT_OR_POLL_MISSING")
            journal.once("accepted.json", accepted)
            journal.handoff()
        finally:
            channel.close()
            journal.close()
    elif mode in ("condition", "execute"):
        value = request_once(root / "channel.sock", coordinator_unit=config["coordinator"],
                             phase=mode, invocation=os.environ["INVOCATION_ID"])
        if mode == "condition":
            c.require(json.loads(value) == dict(phase=mode, invocation=os.environ["INVOCATION_ID"]),
                      "NATIVE_CONDITION_RED")
            return
        sealed.private_namespace()
        image = sealed.sealed_copy(Path("/capsule.squashfs"), config["image_sha256"])
        destination = root / "capsule"
        destination.mkdir(mode=0o700)
        mounted = sealed.MountedImage(image, destination).attach()
        sealed.bind_readonly(Path("/proc"), destination / "proc")
        for interface in ("/run/dbus/system_bus_socket", "/run/systemd/private", "/run/systemd/system", "/run/postgresql"):
            sealed.bind_readonly(Path(interface), destination / interface.lstrip("/"))
        sealed.bind_readonly(root / "isolation", destination / "run/s8-isolated-proof")
        sealed.private_permit(mounted, value)
        account = pwd.getpwnam("nobody")
        # Synthetic credentials only: expose metadata, never their values.
        credential_root = Path(os.environ["CREDENTIALS_DIRECTORY"])
        print(json.dumps(dict(event="S8_NATIVE_CREDENTIAL_METADATA", expected=[account.pw_uid, account.pw_gid],
            objects=[dict(kind="directory" if p.is_dir() else "file", uid=p.stat().st_uid,
                gid=p.stat().st_gid, mode=oct(p.stat().st_mode & 0o7777), nlink=p.stat().st_nlink,
                acl=subprocess.check_output(["getfacl", "-cpn", str(p)], text=True))
                for p in [credential_root, *sorted(credential_root.iterdir())]])), flush=True)
        sealed.private_credentials(mounted, Path(os.environ["CREDENTIALS_DIRECTORY"]),
                                   uid=account.pw_uid, gid=account.pw_gid)
        argv = ["/usr/bin/python3", "-I", "-B", "-S",
                "/application/tests/execution_root/native_admission_probe.py"]
        sealed._drop_exec(mounted, uid=account.pw_uid, gid=account.pw_gid,
                         image_sha256=config["image_sha256"], argv=argv,
                         environment={"INVOCATION_ID": os.environ["INVOCATION_ID"],
                            "CREDENTIALS_DIRECTORY": os.environ["CREDENTIALS_DIRECTORY"], "LANG": "C.UTF-8"})
    else:
        raise SystemExit("S8_NATIVE_MODE_RED")


if __name__ == "__main__":
    main()
