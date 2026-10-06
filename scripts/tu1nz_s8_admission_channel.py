"""PID-1-bound local handoff, never a standalone admission or retry endpoint.

The frozen coordinator remains the only journal writer. Helpers cannot write
records, adopt a journal or mint a permit. Kernel peer credentials, the exact
PID-1 role and a stable start identity are all required for each single phase.
The complete release/provisioning adapter is responsible for verifying the
frozen units and execution roots before opening this channel.
"""
from __future__ import annotations

import array
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess

from tu1nz_s8_execution_contract import canonical, hex_value, process_identity, require

MAX_MESSAGE = 32768


def protect_process():
    # Root file writers are not implicitly allowed to duplicate our descriptors
    # or change this process's memory. Privileged ptrace/kernel administration
    # remains the explicitly stated OS trust boundary.
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            "PROCESS_HANDLE_PROTECTION_RED")


def properties(unit):
    require(re.fullmatch(r"tu1nz-[a-z0-9-]+\.service", unit), "UNIT_NAME_RED")
    result = subprocess.run([
        "/usr/bin/systemctl", "show", unit, "--no-pager",
        "--property=MainPID,ControlPID,InvocationID,ActiveState,SubState,NRestarts",
    ], capture_output=True, text=True, timeout=5, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    require(result.returncode == 0, "PID1_READ_RED")
    rows = [line.split("=", 1) for line in result.stdout.splitlines()]
    require(all(len(row) == 2 for row in rows) and len(rows) == len(dict(rows))
            and set(dict(rows)) == {"MainPID", "ControlPID", "InvocationID", "ActiveState", "SubState", "NRestarts"},
            "PID1_ENVELOPE_RED")
    return dict(rows)


def peer(connection):
    pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(pid > 1 and uid == 0 and gid == 0, "CHANNEL_PEER_RED")
    identity = process_identity(pid)
    require(identity["uid"] == 0, "CHANNEL_PEER_RED")
    return identity


def bind_peer(connection, *, unit, phase, invocation):
    require(phase in {"condition", "execute", "coordinate"} and hex_value(invocation, 32),
            "CHANNEL_PHASE_RED")
    identity = peer(connection)
    before = properties(unit)
    pid_key = "ControlPID" if phase == "condition" else "MainPID"
    expected_states = {"activating"} if phase in {"condition", "coordinate"} else {"active"}
    require(before[pid_key] == str(identity["pid"]) and before["InvocationID"] == invocation
            and before["ActiveState"] in expected_states and before["NRestarts"] == "0",
            "CHANNEL_PID1_ROLE_RED")
    cgroups = (Path("/proc") / str(identity["pid"]) / "cgroup").read_text().splitlines()
    require(any(line.split(":", 2)[-1] == "/system.slice/" + unit for line in cgroups),
            "CHANNEL_CGROUP_RED")
    require(process_identity(identity["pid"]) == identity and properties(unit) == before,
            "CHANNEL_PEER_CHANGED")
    return identity


def sealed_message(payload):
    require(type(payload) is bytes and 0 < len(payload) <= MAX_MESSAGE, "CHANNEL_SIZE_RED")
    fd = os.memfd_create("tu1nz-s8-admission", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        remaining = payload
        while remaining:
            count = os.write(fd, remaining)
            require(count > 0, "CHANNEL_WRITE_RED")
            remaining = remaining[count:]
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
        require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == 15, "CHANNEL_SEAL_RED")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_sealed(fd):
    require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == 15, "CHANNEL_SEAL_RED")
    m = os.fstat(fd)
    require(m.st_uid == 0 and m.st_gid == 0 and m.st_nlink == 0
            and 0 < m.st_size <= MAX_MESSAGE, "CHANNEL_METADATA_RED")
    data = os.pread(fd, MAX_MESSAGE + 1, 0)
    require(len(data) == m.st_size, "CHANNEL_SIZE_RED")
    return data


class AdmissionChannel:
    def __init__(self, path: Path, runtime_unit: str):
        require(os.geteuid() == 0, "PRIVILEGED_CHANNEL_REQUIRED")
        protect_process()
        self.runtime_unit = runtime_unit
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.server.settimeout(30)
        self.phase = "condition"
        self.invocation = None
        self.closed = False
        try:
            # Existing socket/path is an interruption, not a reason to unlink.
            self.server.bind(str(path))
            os.chmod(path, 0o600)
            self.server.listen(1)
        except BaseException:
            self.server.close()
            raise

    def accept_once(self, phase, authorize):
        require(not self.closed and phase == self.phase, "CHANNEL_ALREADY_CONSUMED")
        # Spent before accept, reads, verification and callback. A caller cannot
        # retry this object after timeout, rejection, unknown send or SIGKILL.
        self.phase = "execute" if phase == "condition" else "closed"
        try:
            connection, _ = self.server.accept()
            with connection:
                connection.settimeout(10)
                data, ancillary, flags, _ = connection.recvmsg(MAX_MESSAGE + 1, 0)
                require(not ancillary and flags == 0 and 0 < len(data) <= MAX_MESSAGE,
                        "CHANNEL_MESSAGE_RED")
                value = json.loads(data)
                require(type(value) is dict and set(value) == {"phase", "invocation"}
                        and value["phase"] == phase and canonical(value) == data,
                        "CHANNEL_MESSAGE_RED")
                invocation = value["invocation"]
                identity = bind_peer(connection, unit=self.runtime_unit, phase=phase, invocation=invocation)
                require(self.invocation in (None, invocation), "CHANNEL_INVOCATION_CHANGED")
                self.invocation = invocation
                # The coordinator callback must durably consume the exact
                # phase BEFORE it returns any response or permit bytes.
                response = authorize(invocation, identity)
                require(bind_peer(connection, unit=self.runtime_unit, phase=phase, invocation=invocation)
                        == identity, "CHANNEL_PEER_CHANGED")
                descriptor = sealed_message(response)
                try:
                    require(connection.sendmsg([b"S8-SEALED-ONE-SHOT"], [
                        (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))
                    ]) == len(b"S8-SEALED-ONE-SHOT"), "CHANNEL_SEND_UNKNOWN_NO_RETRY")
                finally:
                    os.close(descriptor)
            return invocation
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True
        self.server.close()
        # Never unlink a socket to manufacture a reusable phase.


def request_once(path: Path, *, coordinator_unit, phase, invocation):
    """Single client exchange; never reconnects or falls back to normal mode."""
    require(phase in {"condition", "execute"}, "CHANNEL_PHASE_RED")
    protect_process()
    descriptors = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        coordinator_invocation = properties(coordinator_unit)["InvocationID"]
        identity = bind_peer(connection, unit=coordinator_unit, phase="coordinate",
                             invocation=coordinator_invocation)
        data = canonical(dict(phase=phase, invocation=invocation))
        require(connection.send(data) == len(data), "CHANNEL_SEND_UNKNOWN_NO_RETRY")
        try:
            data, ancillary, flags, _ = connection.recvmsg(64, socket.CMSG_SPACE(4))
            for level, kind, value in ancillary:
                require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, "CHANNEL_RIGHTS_RED")
                received = array.array("i")
                received.frombytes(value[:len(value) - len(value) % received.itemsize])
                descriptors.extend(received)
            require(data == b"S8-SEALED-ONE-SHOT" and flags == 0 and len(descriptors) == 1,
                    "CHANNEL_RIGHTS_RED")
            require(bind_peer(connection, unit=coordinator_unit, phase="coordinate",
                              invocation=coordinator_invocation) == identity, "CHANNEL_PEER_CHANGED")
            return read_sealed(descriptors[0])
        finally:
            for fd in descriptors:
                os.close(fd)
