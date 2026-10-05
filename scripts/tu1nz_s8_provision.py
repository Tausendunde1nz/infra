"""One process: authenticate -> snapshot -> new stock -> one dispatch.

No prepare/resume/adopt/retry command exists. Any partial newly created name
remains consuming. Historical objects are read, never chmodded or repaired.
The source-only task never calls this function against a live host.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import time

import tu1nz_s8_execution_contract as c
import tu1nz_s8_execution_observer as observer
from tu1nz_s8_execution_release import SOURCE_NAMES, decode_tag
from tu1nz_s8_frozen_entry import MODULES, build
from tu1nz_s8_execution_units import COORDINATOR, render, runtime_dropin
from tu1nz_s8_new_stock import NewStock
from tu1nz_s8_dispatch_boundary import DispatchBoundary
from tu1nz_s8_admission_channel import properties, protect_process
from tu1nz_s8_runtime_interfaces import CONFIG_NAMES, configuration_inputs, resolver_input


def failure(error):
    value = str(error)
    import re
    return dict(type=type(error).__name__, code=value if re.fullmatch(r"S8_[A-Z0-9_]{1,160}", value) else "UNKNOWN")


def cleanup(*objects):
    errors = []
    for item in objects:
        if item is not None:
            try: item.close()
            except BaseException as error: errors.append(failure(error))
    return errors


class ProvisionAborted(c.ContractError):
    def __init__(self, primary, abort, cleanup_errors):
        super().__init__("S8_EXECUTION_PROVISION_ABORTED_NO_RETRY")
        self.evidence = dict(primary=primary, abort=abort, cleanup=cleanup_errors,
                             historical_cause="UNKNOWN", retry_allowed=False)


def plan(values):
    return {name: dict(sha256=hashlib.sha256(payload).hexdigest(), size=len(payload)) for name, payload in values.items()}


def transient_command(program):
    """Use the very same coordinator properties as the native unit renderer.

    No shell, persisted mutable coordinator file or automatic startup. The
    persistent runtime drop-in cannot run without this one live coordinator.
    After reboot it cannot reconstitute the original dispatcher handshake.
    """
    argv = ["/usr/bin/systemd-run", "--quiet", "--no-block", "--unit="+COORDINATOR]
    for line in render(frozen_program=program)[COORDINATOR].splitlines():
        if not line or line.startswith(("[", "#", "ExecStart=")): continue
        c.require("=" in line, "COORDINATOR_RENDER_RED")
        argv.append("--property="+line)
    return [*argv, "/usr/bin/python3", "-I", "-B", "-S", "-c", program, "coordinate"]


def abort_owned(boundary):
    """Stop only the invocation proved by our already durable live handoff.

    No receipt means the candidate could not pass its first handshake. Its
    bounded startup expires without admission. A foreign/changed invocation
    never receives a stop. This function does not reset or restore the unit.
    """
    if boundary is None or boundary.receipt is None:
        return "NO_HANDOFF_NO_ADMISSION_AUTHORITY"
    receipt = boundary.receipt
    before = properties(COORDINATOR)
    c.require(before["InvocationID"] == receipt["invocation"], "ABORT_OWNERSHIP_UNKNOWN")
    if before["MainPID"] != "0":
        c.require(c.process_identity(int(before["MainPID"])) == receipt["coordinator"], "ABORT_OWNERSHIP_UNKNOWN")
    observer.command(["/usr/bin/systemctl", "stop", COORDINATOR], timeout=40)
    current = properties(c.UNIT)
    c.require(current["MainPID"] == "0" and current["ActiveState"] in {"inactive", "failed"}, "ABORT_RUNTIME_STATE_UNKNOWN")
    return "OWNED_COORDINATOR_STOPPED_RUNTIME_INACTIVE_NO_RETRY"


def provision(*, tag_bytes, tag_object, grant_bytes, image_bytes, control_sources):
    """Only callable from an authenticated source bundle, with operator grant.

    Every argument is independently bound before the first mkdir. There is no
    injectable path, incident, unit, UID, shell command or observation adapter.
    Native tests patch external interfaces only inside isolated test processes;
    no such override/fixture mode is exported by this production contract.
    """
    c.require(os.geteuid() == os.getegid() == 0, "PROVISION_ROOT_REQUIRED")
    protect_process()
    release, freeze_bytes = decode_tag(tag_bytes, tag_object=tag_object)
    c.require(type(control_sources) is dict and set(control_sources) == set(SOURCE_NAMES), "CONTROL_SOURCE_SET_RED")
    for name, payload in control_sources.items():
        c.require(type(payload) is bytes and hashlib.sha256(payload).hexdigest() == release["control_sources"][name],
                  "CONTROL_SOURCE_BINDING_RED")
    c.require(type(image_bytes) is bytes and len(image_bytes) == release["image"]["size"]
              and hashlib.sha256(image_bytes).hexdigest() == release["image"]["sha256"], "IMAGE_BINDING_RED")
    grant = json.loads(grant_bytes)
    c.require(c.canonical(grant) == grant_bytes, "GRANT_CANONICAL_RED")
    binding = dict(freeze_sha256=hashlib.sha256(freeze_bytes).hexdigest(), image_sha256=release["image"]["sha256"],
                   application=release["application"], sources=release["sources"])
    c.grant_check(grant, binding, datetime.now(timezone.utc))
    baseline = observer.failed_precondition()
    c.require(properties(COORDINATOR)["ActiveState"] == "inactive", "COORDINATOR_ALREADY_EXISTS")
    account = pwd.getpwnam("chatops")
    c.require(account.pw_uid > 0 and account.pw_gid > 0, "RUNTIME_ACCOUNT_RED")
    configs = configuration_inputs({name: observer.file_bytes(Path("/etc/tu1nz")/name,
        expected=release["configurations"][name], limit=131072) for name in CONFIG_NAMES}, release["configurations"])
    # A symlink to one of these known root-owned OS resolver outputs is an
    # explicit interface, not an arbitrary pathname selected by live content.
    resolver_path = Path("/etc/resolv.conf").resolve(strict=True)
    c.require(resolver_path in {Path("/etc/resolv.conf"), Path("/run/systemd/resolve/stub-resolv.conf"),
                                Path("/run/systemd/resolve/resolv.conf")}, "DNS_SOURCE_PATH_RED")
    resolver = resolver_input(observer.file_bytes(resolver_path, limit=8192))
    base_unit = observer.file_bytes(observer.BASE_UNIT, expected=observer.BASE_UNIT_SHA256)
    values = dict(configs, **{"capsule.squashfs": image_bytes, "freeze.json": freeze_bytes, "grant.json": grant_bytes,
        "baseline.json": c.canonical(baseline), "historical-unit.txt": base_unit, "resolv.conf": resolver})
    root = observer.ROOT
    dropin = Path(str(observer.BASE_UNIT)+".d")
    # Re-observe immediately before consuming a new name. The later CAS, not
    # this point-in-time observation, decides the actual initial lease claim.
    second = observer.failed_precondition()
    c.require(second["history"] == baseline["history"] and second["health"]["public"] == baseline["health"]["public"],
              "PREFLIGHT_DRIFT")
    c.grant_check(grant, binding, datetime.now(timezone.utc))
    candidate = overlay = boundary = None
    try:
        candidate = NewStock(root, plan(values), state_directory=True)
        for name, payload in values.items(): candidate.put(name, payload)
        proof = candidate.seal()
        config = dict(schema="TU1NZ_S8_FROZEN_INVOCATION_V1", root_identity=list(proof["root_identity"]),
            state_identity=list(proof["state_identity"]), files=plan(values), coordinator=COORDINATOR,
            dispatcher=c.process_identity(os.getpid()), binding=binding, grant=grant, baseline=baseline,
            runtime_uid=account.pw_uid, runtime_gid=account.pw_gid)
        # CONFIG's dynamic object identities are newly established by watched
        # creation, never inherited from any historical path or old receipt.
        entry = ("CONFIG = "+repr(config)+"\n").encode()+control_sources["tu1nz_s8_execution"]
        modules = {name: control_sources[name] for name in MODULES}
        expected = {name: hashlib.sha256(payload).hexdigest() for name, payload in {**modules, "entry": entry}.items()}
        program = build(modules, entry, expected)
        overlay_bytes = runtime_dropin(frozen_program=program).encode()
        overlay = NewStock(dropin, plan({"00-atomic-admission.conf": overlay_bytes}))
        overlay.put("00-atomic-admission.conf", overlay_bytes)
        overlay.seal()
        # Only immutable complete files are handed to PID 1. No historical
        # base-unit edit, index action, marker removal, retry or reset exists.
        observer.command(["/usr/bin/systemctl", "daemon-reload"])
        before = observer.failed_precondition(installed=True)
        c.require(before["history"] == baseline["history"] and before["health"]["public"] == baseline["health"]["public"]
                  and before["s8"]["DropInPaths"] == str(dropin/"00-atomic-admission.conf")
                  and before["s8"]["Restart"] == "no" and before["s8"]["RefuseManualStart"] == "yes",
                  "INSTALLED_ADMISSION_CONTRACT_RED")
        c.grant_check(grant, binding, datetime.now(timezone.utc))
        boundary = DispatchBoundary(root/"state", COORDINATOR, c.digest(config))
        job = boundary.issue_once(lambda: subprocess.Popen(transient_command(program),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}))
        c.require(job.wait(timeout=10) == 0, "DISPATCH_OUTCOME_UNKNOWN_NO_RETRY")
        deadline = time.monotonic()+240
        while time.monotonic() < deadline:
            state = properties(COORDINATOR)
            c.require(state["InvocationID"] == boundary.receipt["invocation"], "COORDINATOR_INVOCATION_CHANGED")
            if state["ActiveState"] == "active" and state["SubState"] == "exited":
                accepted = json.loads(observer.file_bytes(root/"state/runtime/accepted.json"))
                c.require(accepted["retry_allowed"] is False and accepted["s11_s12_acceptance"] is False,
                          "FINAL_RECEIPT_RED")
                errors = cleanup(boundary, overlay, candidate)
                c.require(not errors, "PROVISION_CLEANUP_RED")
                return dict(status="S8_SINGLE_ADMISSION_ACCEPTED", acceptance=accepted,
                            freeze_sha256=binding["freeze_sha256"], tag_object=tag_object,
                            recovery=False, deployment=False, unlock=False)
            c.require(state["ActiveState"] == "activating", "COORDINATOR_FAILED_NO_RETRY")
            time.sleep(1)
        c.require(False, "COORDINATOR_OUTCOME_UNKNOWN_NO_RETRY")
    except BaseException as error:
        primary = failure(error)
        try: abort = dict(result=abort_owned(boundary))
        except BaseException as secondary: abort = dict(error=failure(secondary))
        errors = cleanup(boundary, overlay, candidate)
        raise ProvisionAborted(primary, abort, errors) from None
