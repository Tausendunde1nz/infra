"""Fixed, non-resumable admission anchor. Readers never create or repair it.

The anchor is below the host root mount, not below movable configuration
parents. Flags protect it from ordinary file writers, including UID 0, NOT
from a kernel administrator able to clear flags, replace mounts or rewind
memory/disks. A restored receipt is evidence only, never a new live handoff.
"""
import hashlib
import json
import os
from pathlib import Path
import re

import tu1nz_s8_execution_contract as c
from tu1nz_s8_journal_fence import APPEND, IMMUTABLE, inode_flags
from tu1nz_s8_path_policy import PathChain

ROOT = Path("/tu1nz-s8-admission-anchor-v1")
SCHEMA = "TU1NZ_S8_HOST_ANCHOR_V1"
ALLOWED_FLAGS = 0x80000 | APPEND | IMMUTABLE  # extents is not authority


def host(*, require_host_namespace=True):
    """OS bootstrap trust, additionally bound by the protected human grant.

    No hostname, network address or private machine identifier is emitted.
    Boot and mount identity deliberately make restoration fail closed rather
    than offering post-reboot continuation of this one-shot operation.
    """
    with PathChain(Path("/etc"), leaf="machine-id"):
        path = Path("/etc/machine-id")
        before = c.protected(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            c.require(c.fingerprint(before) == c.fingerprint(os.fstat(fd)), "ANCHOR_HOST_DRIFT")
            raw = os.read(fd, 34)
            c.require(re.fullmatch(b"[0-9a-f]{32}\n?", raw) is not None
                      and c.fingerprint(before) == c.fingerprint(os.fstat(fd)) == c.fingerprint(path.lstat()),
                      "ANCHOR_HOST_RED")
        finally: os.close(fd)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    c.require(re.fullmatch(r"[0-9a-f-]{36}", boot) is not None, "ANCHOR_BOOT_RED")
    # Refuse a private/surrogate mount namespace. Mount administration, PID 1
    # and the procfs view are part of the explicitly bounded OS trust base.
    namespace = os.stat("/proc/self/ns/mnt")
    if require_host_namespace:
        c.require((namespace.st_dev, namespace.st_ino) ==
                  (os.stat("/proc/1/ns/mnt").st_dev, os.stat("/proc/1/ns/mnt").st_ino), "ANCHOR_NAMESPACE_RED")
    root = c.protected(Path("/"), directory=True)
    mounts = [line for line in Path("/proc/self/mountinfo").read_text().splitlines()
              if line.split()[4] == "/"]
    c.require(len(mounts) == 1, "ANCHOR_ROOT_MOUNT_RED")
    return dict(machine_sha256=hashlib.sha256(raw.strip()).hexdigest(), boot_id=boot,
                root_identity=[root.st_dev, root.st_ino],
                mount_sha256=hashlib.sha256(mounts[0].encode()).hexdigest(),
                namespace_identity=[namespace.st_dev, namespace.st_ino])


def grant_host(grant, *, owner=False, sandboxed=False):
    current = host(require_host_namespace=not sandboxed)
    if sandboxed:
        # PID 1 intentionally makes a private read-only namespace for its
        # children. Its mount IDs/options differ, but the underlying host
        # root, boot and machine must not. This read grants no authority: the
        # fixed inode-bound anchor AND live authenticated PID-1 peer handoff
        # are independently required before any actual start/initial claim.
        c.require(all(grant["host"][key] == current[key] for key in
                  ("machine_sha256", "boot_id", "root_identity")), "ANCHOR_HOST_BINDING_RED")
    else:
        c.require(grant["host"] == current, "ANCHOR_HOST_BINDING_RED")
    process = grant["provisioner"]
    c.require(c.process_identity(process["pid"]) == process and process["uid"] == 0,
              "ANCHOR_PROVISIONER_GONE")
    if owner:
        c.require(process == c.process_identity(os.getpid()), "ANCHOR_GRANT_OTHER_PROCESS")


def absent():
    """Only an absence check. It does not return a reusable bootstrap ticket."""
    with PathChain(Path("/"), leaf=ROOT.name):
        c.require(not os.path.lexists(ROOT), "ANCHOR_EXISTS_NO_ADOPTION_NO_RETRY")


def checked_file(path, expected):
    before = c.protected(path, mode=0o600)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        c.require(0 < before.st_size <= 1048576 and c.fingerprint(before) == c.fingerprint(os.fstat(fd)),
                  "ANCHOR_RECORD_RED")
        flags = inode_flags(fd)
        c.require(flags & IMMUTABLE and not flags & ~ALLOWED_FLAGS, "ANCHOR_RECORD_UNPROTECTED")
        data = bytearray()
        while len(data) < before.st_size:
            part = os.read(fd, before.st_size-len(data))
            c.require(bool(part), "ANCHOR_SHORT_READ"); data.extend(part)
        c.require(c.fingerprint(before) == c.fingerprint(os.fstat(fd)) == c.fingerprint(path.lstat())
                  and hashlib.sha256(data).hexdigest() == expected, "ANCHOR_RECORD_DRIFT")
        value = json.loads(data)
        c.require(c.canonical(value) == bytes(data), "ANCHOR_RECORD_FORMAT_RED")
        return value
    finally: os.close(fd)


def validate(proof, *, binding, grant, dispatcher):
    """Positive object/byte/live-owner binding, not adoption or fresh admission.

    Called before every actual coordinator/helper admission decision. Even a
    byte-perfect backup cannot reconstruct the live dispatcher handshake.
    """
    grant_host(grant, sandboxed=True)
    c.require(dispatcher == grant["provisioner"] and proof["host"] == grant["host"], "ANCHOR_OWNER_RED")
    paths = ((ROOT, proof["root_identity"], APPEND | IMMUTABLE),
             (ROOT/"state", proof["state_identity"], APPEND),
             (ROOT/"state"/c.SLOT, proof["slot_identity"], APPEND | IMMUTABLE))
    with PathChain(ROOT):
        for path, expected, required in paths:
            meta = c.protected(path, directory=True, mode=0o700)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                flags = inode_flags(fd)
                c.require([meta.st_dev, meta.st_ino] == expected == [os.fstat(fd).st_dev, os.fstat(fd).st_ino]
                          and flags & required == required and not flags & ~ALLOWED_FLAGS,
                          "ANCHOR_OBJECT_BINDING_RED")
            finally: os.close(fd)
        c.require(set(os.listdir(ROOT)) == {"anchor.json", "stock-plan.json", "state"}
                  and set(os.listdir(ROOT/"state")) == {c.SLOT}
                  and set(os.listdir(ROOT/"state"/c.SLOT)) == {"intent.json", "objects.json"},
                  "ANCHOR_OBJECT_SET_RED")
        record = checked_file(ROOT/"anchor.json", proof["record_sha256"])
        c.require(record == dict(schema=SCHEMA, slot=c.SLOT, host=grant["host"],
                  binding=binding, grant_sha256=c.digest(grant), provisioner=dispatcher,
                  retry_allowed=False, restore_authority=False), "ANCHOR_RELEASE_BINDING_RED")
        intent = checked_file(ROOT/"state"/c.SLOT/"intent.json", proof["intent_sha256"])
        c.require(intent == dict(anchor_sha256=proof["record_sha256"], slot=c.SLOT,
                  grant_sha256=c.digest(grant), provisioner=dispatcher), "ANCHOR_INTENT_RED")
        return checked_file(ROOT/"state"/c.SLOT/"objects.json", proof["objects_sha256"])
