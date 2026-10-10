"""Fixed incident's read-only observations, not a recovery or health override.

No raw journal records, credentials, messages or lease-owner identifiers leave
this adapter. The OS/PID-1/postgres peer-auth interfaces are explicit host TCB.
All Git reads disable optional locks; no index refresh or repository writes.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import tu1nz_s8_execution_contract as c
from tu1nz_s8_path_policy import PathChain, dropin_snapshot
from tu1nz_s8_historical_read import repository as historical_repository

ROOT = Path("/etc/tu1nz/s8-atomic-admission-r1")
HISTORY = Path("/etc/tu1nz/adult-commercial-s12-1-private/state")
BASE_UNIT = Path("/etc/systemd/system") / c.UNIT
BASE_UNIT_SHA256 = "fcad30a40a51ac9d45472cbe3e5eb607ccf117f820fe7f9a5d581f455aa63665"
HISTORY_HASHES = {
    "repository-barrier.json": "8e2bb8ec334584d2a87e7b1d5b0f01fcf9463ed37281510fa56a9e49d89250ae",
    "repository-barrier.r12-bindings.json": "68f815b7fccc483f9c74aa9535b23fffb865ed1a71fddfd30e708590d1393dbd",
    "repository-barrier.r12-abort.json": "ca5945059fb8cebc4c3ab91d803354d7eef3dae4c27f1af6edab10499dd28ca5",
    "deployment-attempted.json": "30189b22f290361e901ac4f6b0af95ebc75424014ff190fb86cc9600c5ab680c",
}
ABSENT_MARKERS = (
    "repository-barrier.r15-containment.json", "repository-barrier.r15-containment-progress.json",
    "repository-barrier.r15-contained.json", "repository-barrier.r15-containment-failed.json",
    "r13-followup-1.consumed.json",
)
HISTORICAL_ROOTS = {
    "/opt/tu1nz_repos/adult-publishing-core": c.HISTORICAL_APPLICATION,
    "/opt/tu1nz_repos/control": c.HISTORICAL_CONTROL,
}
PUBLIC_UNITS = ("tu1nz-adult-public-s7.service", "tu1nz-adult-public-s8-landing.service",
                "tu1nz-adult-public-s10-wms.service", "nginx.service")
SEPARATE_UNITS = ("tu1nz-adult-public-s9-health.service", "tu1nz-adult-public-s10-health.service",
                  "tu1nz-adult-public-s11-canary-controller.service")
S12_UNIT = "tu1nz-adult-commercial-s12-yoti-runtime.service"


def command(argv, *, input=None, timeout=15):
    result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0",
             "GIT_TERMINAL_PROMPT": "0", "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"})
    c.require(result.returncode == 0, "OBSERVATION_READ_RED")
    return result.stdout


def file_bytes(path, *, expected=None, limit=4*1024*1024):
    """Snapshot a protected regular inode; no adoption or metadata changes."""
    with PathChain(path.parent, leaf=path.name) as chain:
        result = _file_bytes(path, chain.fd, expected=expected, limit=limit)
        chain.check()
        return result


def _file_bytes(path, parent_fd, *, expected, limit):
    before = c.protected(path)
    c.require(0 < before.st_size <= limit, "INPUT_SIZE_RED")
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    with c.descriptor_scope(fd):
        c.require(c.fingerprint(before) == c.fingerprint(os.fstat(fd)), "INPUT_DRIFT")
        payload = bytearray()
        while len(payload) < before.st_size:
            part = os.read(fd, min(1024*1024, before.st_size-len(payload)))
            c.require(bool(part), "INPUT_SHORT_READ")
            payload.extend(part)
        c.require(c.fingerprint(before) == c.fingerprint(os.fstat(fd)) == c.fingerprint(path.lstat()), "INPUT_DRIFT")
        c.protected(path)
        c.require(expected is None or hashlib.sha256(payload).hexdigest() == expected, "INPUT_DIGEST_RED")
        return bytes(payload)


def service(unit):
    names = ("ActiveState", "SubState", "Result", "MainPID", "ControlPID", "ExecMainStatus", "NRestarts",
             "InvocationID", "NeedDaemonReload", "DropInPaths", "FragmentPath", "Restart", "RefuseManualStart")
    value = command(["/usr/bin/systemctl", "show", unit, "--no-pager", "--property="+",".join(names)])
    rows = [line.split("=", 1) for line in value.splitlines()]
    c.require(all(len(row) == 2 for row in rows) and len(rows) == len(dict(rows))
              and set(dict(rows)) == set(names), "OBSERVATION_ENVELOPE_RED")
    return dict(rows)


def installed_start_guard(state):
    """Reject an observed loss of the loaded interlock; not a durable fence.

    A protected drop-in inode need not remain visible to PID 1. This check
    grants no start authority and cannot prove check-to-use or post-process
    namespace protection. Those remain separate mandatory evidence gates.
    """
    c.require(state.get("FragmentPath") == str(BASE_UNIT)
              and state.get("NeedDaemonReload") == "no"
              and state.get("DropInPaths") == str(BASE_UNIT)+".d/00-atomic-admission.conf"
              and state.get("Restart") == "no" and state.get("RefuseManualStart") == "yes",
              "INSTALLED_ADMISSION_CONTRACT_RED")


def history():
    c.require(HISTORICAL_ROOTS == {
        '/opt/tu1nz_repos/adult-publishing-core': c.HISTORICAL_APPLICATION,
        '/opt/tu1nz_repos/control': c.HISTORICAL_CONTROL}, 'HISTORICAL_BINDING_UNAVAILABLE')
    c.require(set(HISTORY_HASHES) == {'repository-barrier.json', 'repository-barrier.r12-bindings.json',
        'repository-barrier.r12-abort.json', 'deployment-attempted.json'} and
        all(c.hex_value(value, 64) for value in HISTORY_HASHES.values()), 'HISTORICAL_BINDING_UNAVAILABLE')
    result = {name: hashlib.sha256(file_bytes(HISTORY/name, expected=wanted)).hexdigest()
              for name, wanted in HISTORY_HASHES.items()}
    for name in ABSENT_MARKERS:
        c.require(not os.path.lexists(HISTORY/name), "HISTORICAL_ATTEMPT_CHANGED")
    repositories = {}
    for text, expected in HISTORICAL_ROOTS.items():
        repositories[text] = historical_repository(Path(text), expected)
    return dict(hashes=result, repositories=repositories, absent_markers=list(ABSENT_MARKERS))


SQL = """
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='8s'; SET LOCAL lock_timeout='2s';
SELECT json_build_object(
 'read_only',current_setting('transaction_read_only'), 'observed_at',CURRENT_TIMESTAMP,
 'leases',(SELECT coalesce(json_agg(json_build_object(
   'release',release_id,'owner',CASE WHEN lease_owner_id IS NULL THEN NULL
     ELSE encode(sha256(convert_to(lease_owner_id::text,'UTF8')),'hex') END,
   'expires',lease_expires_at,'revision',revision,'last_poll',last_successful_poll_at,
   'updated',updated_at,'code',last_event_path_code)),'[]'::json) FROM commercial_s10_2d_bot_polling_state),
 's11',(SELECT json_build_object('enabled',enabled,'release_state',release_state,'promotion_state',promotion_state,
   'hard_gates_closed',NOT (community_user_content_publishing_enabled OR adult_media_enabled OR real_avs_enabled
    OR payments_enabled OR external_publishing_enabled OR controlled_beta_enabled OR production_enabled))
   FROM commercial_s11_runtime_control WHERE singleton),
 'acquisition',(SELECT json_build_object('active',wms_real_acquisition_ready,'baseline',real_acquisition_baseline_start)
   FROM commercial_s10_2d_runtime_control WHERE singleton));
ROLLBACK;
"""


def database():
    raw = command(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "--no-psqlrc", "-qAt",
                   "--set=ON_ERROR_STOP=1", "--dbname=tu1nz_adult_commercial_s3"], input=SQL)
    value = json.loads(raw)
    c.require(value["read_only"] == "on" and len(value["leases"]) == 1, "DATABASE_ENVELOPE_RED")
    for key in ("expires", "last_poll", "updated"):
        if value["leases"][0][key] is not None:
            value["leases"][0][key] = c.utc(value["leases"][0][key]).isoformat()
    c.require(value["s11"] == dict(enabled=False, release_state="S11_DISABLED", promotion_state="CANARY_RED",
                                   hard_gates_closed=True), "S11_OR_PRODUCT_STATE_CHANGED")
    c.require(value["acquisition"]["active"] is True
              and c.utc(value["acquisition"]["baseline"]) == c.utc("2026-09-18T00:41:06.710027+00:00"),
              "ACQUISITION_STATE_CHANGED")
    return value


def public_health():
    result = {}
    for unit in PUBLIC_UNITS:
        value = service(unit)
        c.require(value["ActiveState"] == "active" and value["SubState"] == "running"
                  and value["NRestarts"] == "0" and value["NeedDaemonReload"] == "no", "PUBLIC_SERVICE_RED")
        result[unit] = {k: value[k] for k in ("ActiveState", "SubState", "NRestarts", "InvocationID", "MainPID")}
    inactive = service(S12_UNIT)
    c.require(inactive["ActiveState"] == "inactive" and inactive["MainPID"] == "0", "S12_STATE_CHANGED")
    codes = {}
    for url, expected in (("https://wantmeseen.com/", "200"), ("https://wantmeseen.com/health", "200"),
                          ("https://wantmeseen.com/privacy", "200"), ("https://wantmeseen.com/terms", "200"),
                          ("https://wantmeseen.com/imprint", "200"), ("https://wantmeseen.de/", "308")):
        code = command(["/usr/bin/curl", "--silent", "--max-time", "10", "--output", "/dev/null",
                        "--write-out", "%{http_code}", url])
        c.require(code == expected, "PUBLIC_HTTP_RED")
        codes[url] = code
    # Separate observations, never silently cleared or included in S8 GREEN.
    reds = {unit: {k: v for k, v in service(unit).items() if k in
                  {"ActiveState", "SubState", "Result", "ExecMainStatus", "InvocationID"}} for unit in SEPARATE_UNITS}
    return dict(public=result, http=codes, separate_s9_s10_s11=reds, s12_active=False)


def recognized_pollers():
    result = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit(): continue
        try:
            before = (process/"stat").read_text().rpartition(")")[2].split()
            args = (process/"cmdline").read_bytes().split(b"\0")
            matches = any(a.endswith(b"/tu1nz-public-s8-telegram") or a == b"tu1nz_public_s8.runtime"
                          or a == b"/control/tu1nz_s8_capsule_bootstrap.py" for a in args)
            if matches:
                after = (process/"stat").read_text().rpartition(")")[2].split()
                c.require(before[19] == after[19], "PROCESS_OBSERVATION_RACE")
                result.append(c.process_identity(int(process.name)))
        except FileNotFoundError:
            continue
    # This identifies canonical entrypoints, not arbitrary renamed root code.
    # Atomic revision admission, not this snapshot, excludes foreign leases.
    return result


def failed_precondition(*, installed=False):
    c.require(os.geteuid() == 0, "PROTECTED_OBSERVER_REQUIRED")
    file_bytes(BASE_UNIT, expected=BASE_UNIT_SHA256)
    state = service(c.UNIT)
    c.require(state["ActiveState"] == "failed" and state["SubState"] == "failed"
              and state["Result"] == "exit-code" and state["ExecMainStatus"] == "2"
              and state["MainPID"] == state["ControlPID"] == state["NRestarts"] == "0"
              and state["InvocationID"] == c.FAILED_INVOCATION and state["NeedDaemonReload"] == "no"
              and state["FragmentPath"] == str(BASE_UNIT), "INCIDENT_STATE_CHANGED")
    if installed:
        installed_start_guard(state)
    c.require(not recognized_pollers(), "COMPETING_POLLER")
    if not installed:
        c.require(state["DropInPaths"] == "" and not os.path.lexists(ROOT), "PREEXISTING_EXECUTION_STOCK")
        dropin = dropin_snapshot(Path(str(BASE_UNIT)+".d"))
    else:
        dropin = None
    data = database()
    c.lease_admission(data["leases"][0])
    return dict(history=history(), health=public_health(), s8=state, database=data, dropin=dropin,
                observed_at=datetime.now(timezone.utc).isoformat())
