#!/usr/bin/env python3
"""Fixed-incident, one-shot S8 admission primitives. No implicit live authority.

Pure predicates plus a protected append-only journal. The reviewed adapter must
perform the real observations; caller-provided booleans are not live evidence.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SLOT = "s8-same-release-20261004-1"
UNIT = "tu1nz-adult-public-s8-telegram.service"
FREEZE_TAG = "s8-isolated-atomic-recovery-freeze-r3"
LEASE_RELEASE = "s10-2d-r3-5"
LEASE_REVISION = 277132
FAILED_INVOCATION = "faa9196594964c7999390b250111a4ed"
HISTORICAL_APPLICATION = ("93555d8a141caf8ace33522f9340d30bfc47d2bb", "1e8a644115127818f394b6f9d24f31826e04ecba")
HISTORICAL_CONTROL = ("b44a3a7e6162a2cc01ef0eb0da564bec68090adc", "477e63c6818d42473a9e4400b83faedead7524bc")
# The new execution pair must come from a fully verified coordinated freeze.
# No moving or historical Application candidate is a built-in execution grant.
LAST_POLL = "2026-10-04T08:49:01.753806+00:00"
LAST_UPDATE = "2026-10-04T08:51:02.165718+00:00"
MAX_GRANT_SECONDS = 86400
SYSTEMD_MODEL = "TU1NZ_S8_ADMIN_SYSTEMD_INTEGRITY_V1"
SYSTEMD_INVENTORY_SCOPES = (
    "configuration_selection", "loaded_execution", "ancestors_dac_acl_flags_mounts",
    "actors_credentials_namespaces_fds", "sudo_polkit_dbus_helpers", "maintenance_exclusion",
)


def security_model():
    """Source decision only. Neither a host acceptance nor runtime authority."""
    return dict(id=SYSTEMD_MODEL, administrative_namespace_integrity="TRUSTED_EXPLICIT_ROLES",
        source_decision_sha256="4f25541e8d56c012154f6880079faf481dc00abf7c455403a3247cc0fbd674f3",
        proposal_sha256="925c75e2486b1a7bb79c119497533e3894fd16989c55b8aeaa9cf0adae448d86",
        administrative_mistake_compromise="ACCEPTED_RESIDUAL_RISK_NOT_EQUIVALENT",
        blanket_root_exception=False, nonadmin_namespace_authority=False,
        original_q="HISTORICAL_OPEN_COMPONENT_VISIBILITY_FALSIFIED",
        original_full_bypass="NOT_PROVEN", host_acceptance="REQUIRED_BEFORE_LIVE_UNKNOWN_DENIES")


class ContractError(RuntimeError):
    pass


def failure_record(error):
    try: value = str(error)
    except BaseException: value = ""
    return dict(type=type(error).__name__, code=value if re.fullmatch(r"S8_[A-Z0-9_]{1,160}", value) else "UNKNOWN")


def close_descriptors(primary, *descriptors):
    """Attempt each transferred owned FD once; no ambiguous-close retry.

    The caller relinquishes these descriptors. Preserve a supplied primary;
    otherwise cleanup-only failure is RED. Redaction must not skip later FDs.
    """
    failure = primary if primary is not None else ContractError("S8_EXECUTION_DESCRIPTOR_CLEANUP_RED")
    errors = list(getattr(failure, "_s8_cleanup_errors", []))
    for fd in dict.fromkeys(descriptors):
        if fd is not None and fd >= 0:
            try: os.close(fd)
            except BaseException as error: errors.append(failure_record(error))
    failure._s8_cleanup_errors = errors
    if primary is None and errors: raise failure


@contextmanager
def descriptor_scope(*descriptors):
    """Scoped ownership with primary-preserving, independently attempted closes."""
    try:
        yield
    except BaseException as error:
        close_descriptors(error, *descriptors)
        raise
    else:
        close_descriptors(None, *descriptors)


def close_preserving(primary, *objects):
    """Release all resources without replacing the original failure."""
    errors = list(getattr(primary, "_s8_cleanup_errors", []))
    for item in objects:
        if item is not None:
            try: item.close()
            except BaseException as secondary:
                errors.append(failure_record(secondary))
                errors.extend(getattr(secondary, "_s8_cleanup_errors", []))
    primary._s8_cleanup_errors = errors


def close_members(owner, *names):
    """Attempt every owned resource exactly once, retaining all failures."""
    failure = ContractError("S8_EXECUTION_RESOURCE_CLEANUP_RED")
    for name in names:
        item = getattr(owner, name, None)
        setattr(owner, name, None)
        close_preserving(failure, item)
    if getattr(failure, "_s8_cleanup_errors", []):
        raise failure


@contextmanager
def resource_scope(*objects):
    """One ownership lifetime; cleanup cannot replace its body's failure."""
    try:
        yield
    except BaseException as error:
        close_preserving(error, *objects)
        raise
    else:
        failure = ContractError("S8_EXECUTION_RESOURCE_CLEANUP_RED")
        close_preserving(failure, *objects)
        if failure._s8_cleanup_errors: raise failure


def require(value, code):
    if not value:
        raise ContractError("S8_EXECUTION_" + code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hex_value(value, size):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{"+str(size)+"}", value) is not None and value != "0"*size


def utc(value):
    require(type(value) is str, "TIMESTAMP_RED")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(instant.utcoffset() is not None and instant.utcoffset().total_seconds() == 0, "TIMESTAMP_RED")
        return instant
    except (ValueError, TypeError, AttributeError):
        raise ContractError("S8_EXECUTION_TIMESTAMP_RED") from None


def administration_check(grant, now):
    """Validate an independently collected, operator-pinned host acceptance.

    This parser cannot discover omitted actors or prove truthful observations.
    The complete raw rights inventory and its independent acceptance are host
    TCB inputs, authenticated by the separately pinned human grant. No default,
    UID/capability inference, or Source/CI-generated live receipt is permitted.
    Rechecks bind the same receipt/time window; they are NOT a namespace fence.
    """
    value = grant["systemd_acceptance"]
    require(type(value) is dict and set(value) == {
        "schema", "model", "slot", "freeze_sha256", "host_sha256", "observed_at", "expires_at",
        "inventory_complete", "maintenance_excluded", "evidence", "actors"}, "SYSTEMD_ACCEPTANCE_RED")
    require(value["schema"] == "TU1NZ_S8_SYSTEMD_ACCEPTANCE_V1" and value["model"] == SYSTEMD_MODEL
            and value["slot"] == SLOT and value["freeze_sha256"] == grant["freeze_sha256"]
            and value["host_sha256"] == digest(grant["host"]), "SYSTEMD_ACCEPTANCE_BINDING_RED")
    require(value["inventory_complete"] is True and value["maintenance_excluded"] is True,
            "SYSTEMD_INVENTORY_INCOMPLETE")
    evidence = value["evidence"]
    require(type(evidence) is dict and set(evidence) == set(SYSTEMD_INVENTORY_SCOPES)
            and all(hex_value(v, 64) for v in evidence.values()), "SYSTEMD_EVIDENCE_UNKNOWN")
    observed, expires, issued = utc(value["observed_at"]), utc(value["expires_at"]), utc(grant["issued_at"])
    require(0 <= (issued-observed).total_seconds() <= 300
            and observed <= now < expires <= utc(grant["expires_at"]), "SYSTEMD_ACCEPTANCE_TIME_RED")
    actors = value["actors"]
    require(type(actors) is list and 2 <= len(actors) <= 4096, "SYSTEMD_ACTORS_UNKNOWN")
    identities, roles = set(), set()
    for actor in actors:
        require(type(actor) is dict and set(actor) == {
            "identity_sha256", "role", "authorization_sha256", "evidence_sha256", "uid",
            "namespace_write", "manager_api", "helper_api"}, "SYSTEMD_ACTOR_UNKNOWN")
        require(all(hex_value(actor[k], 64) for k in
                    ("identity_sha256", "authorization_sha256", "evidence_sha256"))
                and actor["identity_sha256"] not in identities
                and type(actor["uid"]) is int and 0 <= actor["uid"] < 2**32
                and type(actor["role"]) is str
                and actor["role"] in {"ADMINISTRATOR", "NONADMIN_SERVICE"}
                and all(type(actor[k]) is bool for k in ("namespace_write", "manager_api", "helper_api")),
                "SYSTEMD_ACTOR_UNKNOWN")
        identities.add(actor["identity_sha256"]); roles.add(actor["role"])
        if actor["role"] == "NONADMIN_SERVICE":
            require(not any(actor[k] for k in ("namespace_write", "manager_api", "helper_api")),
                    "SYSTEMD_NONADMIN_AUTHORITY_RED")
    require(roles == {"ADMINISTRATOR", "NONADMIN_SERVICE"}, "SYSTEMD_ROLES_UNKNOWN")


def grant_check(grant, binding, now):
    require(type(grant) is dict and set(grant) == {
        "schema","slot","incident_invocation","freeze_sha256","image_sha256",
        "human_authorization_sha256","issued_at","expires_at","host","provisioner","systemd_acceptance"}, "GRANT_RED")
    require(grant["schema"] == "TU1NZ_S8_EXECUTION_GRANT_V3" and grant["slot"] == SLOT
            and grant["incident_invocation"] == FAILED_INVOCATION, "GRANT_RED")
    require(type(grant["host"]) is dict and set(grant["host"]) == {
        "machine_sha256", "boot_id", "root_identity", "mount_sha256", "namespace_identity"}, "GRANT_HOST_RED")
    for name in ("machine_sha256", "mount_sha256"):
        require(hex_value(grant["host"][name], 64), "GRANT_HOST_RED")
    process = grant["provisioner"]
    require(type(process) is dict and set(process) == {"pid", "start_ticks", "uid", "boot_id"}
            and type(process["pid"]) is int and process["pid"] > 1
            and type(process["start_ticks"]) is int and process["start_ticks"] > 0
            and process["uid"] == 0 and process["boot_id"] == grant["host"]["boot_id"]
            and type(process["boot_id"]) is str
            and re.fullmatch(r"[0-9a-f-]{36}", process["boot_id"]) is not None, "GRANT_PROCESS_RED")
    for name in ("freeze_sha256","image_sha256","human_authorization_sha256"):
        require(hex_value(grant[name],64), "GRANT_RED")
    require(grant["freeze_sha256"] == binding["freeze_sha256"]
            and grant["image_sha256"] == binding["image_sha256"], "GRANT_BINDING_RED")
    issued, expires = utc(grant["issued_at"]), utc(grant["expires_at"])
    require(0 < (expires-issued).total_seconds() <= MAX_GRANT_SECONDS
            and issued <= now < expires, "GRANT_TIME_RED")
    administration_check(grant, now)


def lease_admission(row):
    require(row == dict(release=LEASE_RELEASE,owner=None,expires=None,revision=LEASE_REVISION,
                        last_poll=LAST_POLL,updated=LAST_UPDATE,code="BOT_POLLER_NOT_RUNNING"),
            "LEASE_CHANGED_NO_CLAIM")


def initial_receipt(receipt, permit, invocation):
    require(type(receipt) is dict and set(receipt) == {
        "event","slot","permit_sha256","invocation","expected_revision","claimed_revision","owner_sha256"},
        "INITIAL_RECEIPT_RED")
    require(receipt["event"] == "S8_ATOMIC_ADMISSION_ACCEPTED" and receipt["slot"] == SLOT
            and receipt["permit_sha256"] == hashlib.sha256(permit).hexdigest()
            and receipt["invocation"] == invocation
            and type(receipt["expected_revision"]) is int and receipt["expected_revision"] == LEASE_REVISION
            and type(receipt["claimed_revision"]) is int and receipt["claimed_revision"] == LEASE_REVISION+1
            and hex_value(receipt["owner_sha256"],64), "INITIAL_RECEIPT_RED")


def poll_acceptance(observation, receipt, *, invocation, after, previous=None):
    """Secondary proof only; cannot replace the separate initial receipt."""
    s = observation
    require(s["invocation"] == invocation and s["pid"] > 0 and s["start_ticks"] > 0
            and s["poller_count"] == 1 and s["restarts"] == 0 and s["active"] == "active"
            and s["sub"] == "running" and s["execution_root_verified"] is True, "RUNTIME_IDENTITY_RED")
    lease = s["lease"]
    now, poll = utc(s["observed_at"]), utc(lease["last_poll"])
    require(lease["release"] == LEASE_RELEASE and lease["owner"] == receipt["owner_sha256"]
            and lease["revision"] > receipt["claimed_revision"] and utc(lease["expires"]) > now
            and after <= poll <= now and (now-poll).total_seconds() < 90
            and lease["code"] in {"BOT_EVENT_PATH_GREEN","BOT_UPDATE_NOT_RECEIVED"}, "POLL_RED")
    if previous is None:
        return False
    require(all(s[key] == previous[key] for key in ("pid","start_ticks","invocation"))
            and lease["owner"] == previous["lease"]["owner"]
            and lease["revision"] >= previous["lease"]["revision"], "PROCESS_OR_OWNER_CHANGED")
    return poll > utc(previous["lease"]["last_poll"])


def protected(path, *, directory=False, mode=None, uid=0):
    m = path.lstat()
    require((stat.S_ISDIR(m.st_mode) if directory else stat.S_ISREG(m.st_mode))
            and m.st_uid == uid and m.st_gid == (0 if uid == 0 else os.getgid())
            and not m.st_mode & 0o022 and (directory or m.st_nlink == 1), "METADATA_RED")
    require(not os.listxattr(path, follow_symlinks=False), "ACL_OR_XATTR_RED")
    if mode is not None:
        require(stat.S_IMODE(m.st_mode) == mode, "MODE_RED")
    return m


def fingerprint(m):
    return (m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns,m.st_mode,m.st_uid,m.st_gid)


class Journal:
    """O_EXCL + fsync before authority. Partial objects remain consuming."""
    def __init__(self, root: Path, *, uid=0, directory_mode=0o700):
        require(directory_mode in (0o700, 0o755), "JOURNAL_DIRECTORY_MODE_RED")
        self.root, self.uid, self.directory_mode = root, uid, directory_mode
        first = protected(root,directory=True,mode=directory_mode,uid=uid)
        self.fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            require(fingerprint(first) == fingerprint(os.fstat(self.fd)), "JOURNAL_DRIFT")
        except BaseException as error:
            fd, self.fd = self.fd, None
            close_descriptors(error, fd)
            raise
        self.identity = first.st_dev, first.st_ino

    def check(self):
        require(self.fd is not None, "JOURNAL_NO_AUTHORITY")
        m = protected(self.root,directory=True,mode=self.directory_mode,uid=self.uid)
        require((m.st_dev,m.st_ino) == self.identity, "JOURNAL_DRIFT")

    @contextmanager
    def locked(self):
        self.check()
        try:
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise ContractError("S8_EXECUTION_CONCURRENT_OPERATION") from None
        try:
            yield self
        except BaseException as error:
            try: fcntl.flock(self.fd,fcntl.LOCK_UN)
            except BaseException as cleanup:
                error._s8_cleanup_errors = [*getattr(error, "_s8_cleanup_errors", []), failure_record(cleanup)]
            raise
        else:
            try: fcntl.flock(self.fd,fcntl.LOCK_UN)
            except BaseException as cleanup:
                error = ContractError("S8_EXECUTION_JOURNAL_UNLOCK_RED")
                error._s8_cleanup_errors = [failure_record(cleanup)]
                raise error from None

    def once(self, name, value):
        require(re.fullmatch(r"[a-z-]+\.json",name), "JOURNAL_NAME_RED")
        self.check()
        try:
            fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        except FileExistsError:
            raise ContractError("S8_EXECUTION_ALREADY_CONSUMED_NO_RETRY") from None
        with descriptor_scope(fd):
            data = canonical(value)
            require(0 < len(data) <= 1048576, "JOURNAL_SIZE_RED")
            while data:
                count = os.write(fd,data)
                require(count > 0,"JOURNAL_WRITE_RED"); data = data[count:]
            os.fsync(fd)
        os.fsync(self.fd)
        self.check()
        return self.read(name)

    def read(self,name):
        require(re.fullmatch(r"[a-z-]+\.json",name), "JOURNAL_NAME_RED")
        self.check()
        first = protected(self.root/name,mode=0o600,uid=self.uid)
        require(0 < first.st_size <= 1048576,"JOURNAL_SIZE_RED")
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
        with descriptor_scope(fd):
            require(fingerprint(first)==fingerprint(os.fstat(fd)), "JOURNAL_DRIFT")
            data = bytearray()
            while len(data) < first.st_size:
                part = os.read(fd,first.st_size-len(data))
                require(bool(part),"JOURNAL_SHORT_READ"); data.extend(part)
            require(fingerprint(first)==fingerprint(os.fstat(fd))==fingerprint((self.root/name).lstat()),
                    "JOURNAL_DRIFT")
            self.check()
            value = json.loads(data)
            require(canonical(value)==bytes(data),"JOURNAL_FORMAT_RED")
            return value

    def close(self):
        fd, self.fd = self.fd, None
        close_descriptors(None, fd)


def process_identity(pid):
    base = Path("/proc")/str(pid)
    before = (base/"stat").read_text().rpartition(")")[2].split()
    owner = base.stat().st_uid
    after = (base/"stat").read_text().rpartition(")")[2].split()
    require(before[19] == after[19] and after[0] not in {"Z","X","T","t"}, "COORDINATOR_IDENTITY_RED")
    return dict(pid=pid,start_ticks=int(after[19]),uid=owner,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())


def consume_condition(journal, *, invocation, coordinator, clock, observe_lease, binding, grant):
    # The slot is spent BEFORE any other checks, even if all later work fails.
    journal.once("activation.json",dict(slot=SLOT,invocation=invocation))
    require(hex_value(invocation,32) and invocation != FAILED_INVOCATION,"INVOCATION_RED")
    require(process_identity(coordinator["pid"]) == coordinator and coordinator["uid"] == 0,
            "COORDINATOR_GONE")
    grant_check(grant,binding,clock())
    lease_admission(observe_lease())
    grant_check(grant,binding,clock())
    require(process_identity(coordinator["pid"]) == coordinator,"COORDINATOR_GONE")
    return True


def consume_execution(journal, *, invocation, clock, binding, grant):
    """Separate durable boundary immediately before exec, never a retry ticket."""
    journal.once("execution.json",dict(slot=SLOT,invocation=invocation))
    activation=journal.read("activation.json")
    require(activation==dict(slot=SLOT,invocation=invocation),"ACTIVATION_BINDING_RED")
    grant_check(grant,binding,clock())


def permit_value(journal, *, invocation, application, source_hashes, binding, grant):
    """No I/O or authority creation; adapter must publish once under its fence."""
    require(type(application) is dict and set(application)=={"commit","tree"}
            and all(hex_value(value,40) for value in application.values()),"APPLICATION_BINDING_RED")
    require(set(source_hashes)=={"runtime.py","polling.py","recovery_admission.py"}
            and all(hex_value(value,64) for value in source_hashes.values()),"SOURCE_BINDING_RED")
    activation=journal.read("activation.json")
    require(activation==dict(slot=SLOT,invocation=invocation),"ACTIVATION_BINDING_RED")
    operation=journal.read("operation.json")
    require(operation["grant_sha256"]==digest(grant) and operation["binding_sha256"]==digest(binding),
            "OPERATION_BINDING_RED")
    return dict(schema="TU1NZ_S8_ATOMIC_PERMIT_V1",slot=SLOT,expected_revision=LEASE_REVISION,
                release_id=LEASE_RELEASE,invocation=invocation,
                application_commit=application["commit"],application_tree=application["tree"],
                freeze_sha256=binding["freeze_sha256"],human_authorization_sha256=grant["human_authorization_sha256"],
                operation_sha256=digest(operation),activation_sha256=digest(activation),
                issued_at=grant["issued_at"],expires_at=grant["expires_at"],sources=source_hashes)
