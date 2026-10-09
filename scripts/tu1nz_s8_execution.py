"""PID-1-loaded single-incident coordinator and helpers; no standalone retry.

The reviewed provisioner injects CONFIG into the frozen entry command. This
file cannot run from a checkout or synthesize its own grant/expected release.
All helper authority comes from one live peer and already durable records.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

import tu1nz_s8_execution_contract as c
import tu1nz_s8_anchor as anchor
import tu1nz_s8_sealed_root as sealed
import tu1nz_s8_execution_observer as observer
from tu1nz_s8_admission_channel import AdmissionChannel, properties, request_once
from tu1nz_s8_dispatch_boundary import receive_once
from tu1nz_s8_protected_journal import ProtectedJournal
from tu1nz_s8_runtime_interfaces import CONFIG_NAMES, mount_configuration
from tu1nz_s8_journal_fence import APPEND, IMMUTABLE, inode_flags


def stock(config):
    """No caller-supplied path choices or adoption of a previously made stock."""
    c.require(type(config) is dict and set(config) == {
        "schema", "root_identity", "state_identity", "files", "coordinator", "dispatcher",
        "binding", "grant", "baseline", "runtime_uid", "runtime_gid", "anchor"}
        and config["schema"] == "TU1NZ_S8_FROZEN_INVOCATION_V1", "INVOCATION_CONFIGURATION_RED")
    c.require(config["coordinator"] == "tu1nz-s8-execution-coordinator-r1.service", "COORDINATOR_BINDING_RED")
    c.require(anchor.validate(config["anchor"], binding=config["binding"], grant=config["grant"],
              dispatcher=config["dispatcher"]) == {k: v for k, v in config.items() if k != "anchor"},
              "ANCHOR_EXECUTION_OBJECTS_RED")
    root = observer.ROOT
    for path, expected, flags in ((root, config["root_identity"], APPEND|IMMUTABLE),
                                  (root/"state", config["state_identity"], APPEND)):
        meta = c.protected(path, directory=True, mode=0o700)
        c.require([meta.st_dev, meta.st_ino] == expected, "STOCK_IDENTITY_RED")
        fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        with c.descriptor_scope(fd):
            c.require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (meta.st_dev, meta.st_ino)
                      and inode_flags(fd) & flags == flags, "STOCK_PROTECTION_RED")
    required = {"capsule.squashfs", "freeze.json", "grant.json", "baseline.json", "historical-unit.txt",
                "resolv.conf", *CONFIG_NAMES}
    c.require(set(config["files"]) == required and set(os.listdir(root)) == required|{"stock-plan.json", "state"},
              "STOCK_OBJECT_SET_RED")
    for name in required:
        meta = c.protected(root/name, mode=0o600)
        spec = config["files"][name]
        c.require(meta.st_size == spec["size"], "STOCK_INPUT_RED")
        fd = os.open(root/name, os.O_RDONLY|os.O_NOFOLLOW)
        with c.descriptor_scope(fd): c.require(inode_flags(fd) & IMMUTABLE, "STOCK_PROTECTION_RED")
        # The image is hashed while copying to its sealed backing descriptor.
        # Every smaller command/permission input is authenticated here too.
        if name != "capsule.squashfs": observer.file_bytes(root/name, expected=spec["sha256"])
    account = pwd.getpwnam("chatops")
    c.require(config["runtime_uid"] == account.pw_uid > 0 and config["runtime_gid"] == account.pw_gid > 0,
              "RUNTIME_ACCOUNT_DRIFT")
    c.grant_check(config["grant"], config["binding"], datetime.now(timezone.utc))
    return root


def environment_unchanged(config):
    # Refuse fresh acceptance if PID 1 no longer reports the installed guard.
    # A point-in-time read is not the still-open durable namespace proof.
    observer.installed_start_guard(observer.service(c.UNIT))
    c.require(observer.history() == config["baseline"]["history"], "HISTORICAL_STATE_CHANGED")
    observer.file_bytes(observer.BASE_UNIT, expected=observer.BASE_UNIT_SHA256)
    current = observer.public_health()
    c.require(current["public"] == config["baseline"]["health"]["public"], "PUBLIC_INVOCATION_CHANGED")
    # Public reads do not upgrade the separately reported S9/S10/S11 states.
    data = observer.database()
    return data, current


def events(invocation, pid):
    raw = observer.command(["/usr/bin/journalctl", "--no-pager", "--output=json",
                            "_SYSTEMD_INVOCATION_ID="+invocation, "_PID="+str(pid)])
    output = []
    for line in raw.splitlines():
        row = json.loads(line)
        try: value = json.loads(row.get("MESSAGE", ""))
        except (ValueError, TypeError): continue
        if type(value) is dict and value.get("event") in {
            "S8_EXECUTION_ROOT_ATTESTED", "S8_ATOMIC_ADMISSION_ACCEPTED",
            "BOT_EVENT_PATH_RED", "S8_RUNTIME_STARTUP_RED"}:
            output.append(value)
    return output


def accept_runtime(config, invocation, permit, started):
    previous = None
    deadline = time.monotonic()+150
    while time.monotonic() < deadline:
        state = properties(c.UNIT)
        pid = int(state["MainPID"])
        c.require(state["ActiveState"] == "active" and state["InvocationID"] == invocation and pid > 1,
                  "RUNTIME_IDENTITY_RED")
        rows = events(invocation, pid)
        c.require(not any(row["event"].endswith("RED") for row in rows), "RUNTIME_EVENT_RED")
        receipts = [row for row in rows if row["event"] == "S8_ATOMIC_ADMISSION_ACCEPTED"]
        roots = [row for row in rows if row["event"] == "S8_EXECUTION_ROOT_ATTESTED"]
        c.require(len(receipts) <= 1 and len(roots) <= 1, "DUPLICATE_RUNTIME_RECEIPT")
        if receipts and roots:
            receipt = receipts[0]
            c.initial_receipt(receipt, permit, invocation)
            attestation = roots[0]
            c.require(attestation["image_sha256"] == config["binding"]["image_sha256"]
                      and attestation["application"] == config["binding"]["application"]
                      and attestation["pid"] == pid and attestation["invocation"] == invocation
                      and attestation["admission_accepted"] is False, "EXECUTION_ATTESTATION_RED")
            database = observer.database()
            lease = database["leases"][0]
            c.require(lease["owner"] == receipt["owner_sha256"] and c.utc(lease["expires"]) > datetime.now(timezone.utc),
                      "LEASE_OWNER_CHANGED")
            if lease["last_poll"] is None or c.utc(lease["last_poll"]) < started:
                time.sleep(1); continue
            identity = c.process_identity(pid)
            processes = (Path("/sys/fs/cgroup/system.slice")/c.UNIT/"cgroup.procs").read_text().split()
            c.require(processes == [str(pid)] and observer.recognized_pollers() == [identity], "COMPETING_POLLER")
            observation = dict(invocation=invocation, pid=pid, start_ticks=identity["start_ticks"],
                poller_count=1, restarts=int(state["NRestarts"]), active=state["ActiveState"], sub=state["SubState"],
                execution_root_verified=True, lease=lease, observed_at=database["observed_at"])
            if c.poll_acceptance(observation, receipt, invocation=invocation, after=started, previous=previous):
                _, health = environment_unchanged(config)
                c.require(properties(c.UNIT) == state and c.process_identity(pid) == identity, "ACCEPTANCE_PROCESS_DRIFT")
                return dict(initial_admission=receipt, subsequent_poll=observation, health=health,
                            s11_s12_acceptance=False, retry_allowed=False, r15_pause_compatibility="OPEN")
            previous = observation
        time.sleep(1)
    c.require(False, "FRESH_RECEIPT_OR_POLL_MISSING")


def coordinate(config):
    root = stock(config)
    state_root = root/"state"
    receive_once(state_root, coordinator=config["coordinator"], owner=config["dispatcher"], binding_sha256=c.digest(config))
    journal = ProtectedJournal(state_root/"runtime")
    channel = None
    primary = None
    try:
        journal.once("operation.json", dict(grant_sha256=c.digest(config["grant"]), binding_sha256=c.digest(config["binding"])))
        channel = AdmissionChannel(state_root/"channel.sock", c.UNIT)
        current = observer.failed_precondition(installed=True)
        c.require(current["history"] == config["baseline"]["history"]
                  and current["health"]["public"] == config["baseline"]["health"]["public"], "PRESTART_DRIFT")
        coordinator = c.process_identity(os.getpid())
        now = lambda: datetime.now(timezone.utc)
        started = now()
        dispatch = subprocess.Popen(["/usr/bin/systemd-run", "--quiet", "--wait", "--collect",
            "--unit=tu1nz-s8-one-shot-dependency-r1.service", "--property=Requires="+c.UNIT,
            "--property=After="+c.UNIT, "/usr/bin/true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        permit = None

        def condition(invocation, _peer):
            stock(config)
            c.consume_condition(journal, invocation=invocation, coordinator=coordinator, clock=now,
                observe_lease=lambda: environment_unchanged(config)[0]["leases"][0],
                binding=config["binding"], grant=config["grant"])
            return c.canonical(dict(phase="condition", invocation=invocation))

        def execution(invocation, _peer):
            nonlocal permit
            c.consume_execution(journal, invocation=invocation, clock=now, binding=config["binding"], grant=config["grant"])
            stock(config)
            permit = c.canonical(c.permit_value(journal, invocation=invocation,
                application=config["binding"]["application"], source_hashes=config["binding"]["sources"],
                binding=config["binding"], grant=config["grant"]))
            return permit

        channel.accept_once("condition", condition)
        channel.accept_once("execute", execution)
        c.require(dispatch.wait(timeout=15) == 0, "START_OUTCOME_UNKNOWN_NO_RETRY")
        accepted = accept_runtime(config, channel.invocation, permit, started)
        journal.once("accepted.json", accepted)
        journal.handoff()
        print(c.canonical(dict(event="S8_SINGLE_ADMISSION_ACCEPTED", freeze_sha256=config["binding"]["freeze_sha256"],
                               invocation=channel.invocation, s11_s12_acceptance=False)).decode(), flush=True)
    except BaseException as error:
        primary = error
        # Recording failure is secondary; it cannot prevent channel cleanup or
        # the failed coordinator exit, which stops its BindsTo runtime.
        try: journal.once("failed.json", dict(primary=c.failure_record(primary), retry_allowed=False))
        except BaseException as secondary:
            primary._s8_abort_errors = [c.failure_record(secondary)]
        raise
    finally:
        if primary is not None:
            c.close_preserving(primary, channel, journal)
        else:
            closed = c.ContractError("S8_EXECUTION_COORDINATOR_CLEANUP_RED")
            c.close_preserving(closed, channel, journal)
            if closed._s8_cleanup_errors: raise closed


def execute(config, value):
    root = stock(config)
    sealed.private_namespace()
    image_fd = sealed.sealed_copy(root/"capsule.squashfs", config["binding"]["image_sha256"])
    destination = root/"state/capsule"
    destination.mkdir(mode=0o700)  # Exists => consumed/ambiguous, never reused.
    mounted = sealed.MountedImage(image_fd, destination).attach()
    sealed.bind_null_device(mounted)
    sealed.bind_readonly(Path("/proc"), destination/"proc")
    for name in ("/run/dbus/system_bus_socket", "/run/systemd/private", "/run/systemd/system", "/run/postgresql"):
        sealed.bind_readonly(Path(name), destination/name.lstrip("/"))
    hashes = {name: config["files"][name]["sha256"] for name in CONFIG_NAMES}
    values = {name: observer.file_bytes(root/name, expected=hashes[name]) for name in CONFIG_NAMES}
    resolver = observer.file_bytes(root/"resolv.conf", expected=config["files"]["resolv.conf"]["sha256"])
    mount_configuration(mounted, values, hashes, resolver)
    sealed.private_permit(mounted, value)
    credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
    sealed.private_credentials(mounted, credentials, uid=config["runtime_uid"], gid=config["runtime_gid"])
    argv = ["/usr/bin/python3", "-I", "-B", "-S", "/control/tu1nz_s8_capsule_bootstrap.py",
        "--contract", "/etc/tu1nz/"+CONFIG_NAMES[0], "--copy", "/etc/tu1nz/"+CONFIG_NAMES[1],
        "--community-contract", "/etc/tu1nz/"+CONFIG_NAMES[2], "--community-copy", "/etc/tu1nz/"+CONFIG_NAMES[3],
        "--experience-contract", "/etc/tu1nz/"+CONFIG_NAMES[4], "--experience-copy", "/etc/tu1nz/"+CONFIG_NAMES[5],
        "--telegram-token", str(credentials/"s8_telegram_token"), "--database-dsn", str(credentials/"s8_database_dsn"),
        "--runtime-release-id", c.LEASE_RELEASE, "--latency-evidence-class", "REAL",
        "--recovery-admission", "/etc/tu1nz/s8-atomic-admission-r1/permit.json"]
    sealed.enter_capsule(mounted, uid=config["runtime_uid"], gid=config["runtime_gid"],
        image_sha256=config["binding"]["image_sha256"], argv=argv,
        environment={"INVOCATION_ID": os.environ["INVOCATION_ID"], "CREDENTIALS_DIRECTORY": str(credentials), "LANG": "C.UTF-8"})


def main():
    c.require(__file__ == "<frozen-s8/entry>" and "CONFIG" in globals()
              and len(sys.argv) == 2, "FROZEN_ENTRY_REQUIRED")
    config = globals()["CONFIG"]
    mode = sys.argv[1]
    if mode == "coordinate": return coordinate(config)
    c.require(mode in {"condition", "execute"}, "MODE_RED")
    root = stock(config)
    value = request_once(root/"state/channel.sock", coordinator_unit=config["coordinator"],
                         phase=mode, invocation=os.environ["INVOCATION_ID"])
    if mode == "condition":
        c.require(json.loads(value) == dict(phase=mode, invocation=os.environ["INVOCATION_ID"]), "CONDITION_RED")
        return
    execute(config, value)


if __name__ == "__main__":
    try: main()
    except BaseException as error:
        # No traceback/argv, credentials or provider messages in public logs.
        code = str(error)
        print(json.dumps(dict(event="S8_EXECUTION_ABORTED_NO_RETRY", error_type=type(error).__name__,
            code=code if re.fullmatch(r"S8_[A-Z0-9_]{1,160}", code) else "UNKNOWN",
            abort_errors=getattr(error,"_s8_abort_errors",[]),
            cleanup_errors=getattr(error,"_s8_cleanup_errors",[]))), flush=True)
        raise SystemExit(2)
