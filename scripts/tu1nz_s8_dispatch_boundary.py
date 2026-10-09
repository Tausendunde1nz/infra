"""Durable consumption BEFORE issuing a PID-1 coordinator start request.

The original dispatcher provides one live, kernel-authenticated handshake.
Neither an old record nor a new coordinator invocation can replay it. Even an
interruption before the coordinator's first Python instruction consumes the
dispatch name. This is a construction primitive, not a live command or grant.
"""
from __future__ import annotations

import array
import json
import os
from pathlib import Path
import re
import socket

from tu1nz_s8_execution_contract import canonical, close_descriptors, close_members, close_preserving, descriptor_scope, digest, hex_value, process_identity, require, resource_scope
from tu1nz_s8_admission_channel import (
    bind_peer, peer, properties, protect_process, read_sealed, sealed_message,
)
from tu1nz_s8_protected_journal import ProtectedJournal


class DispatchBoundary:
    def __init__(self, parent: Path, coordinator: str, binding_sha256: str):
        require(re.fullmatch(r"tu1nz-[a-z0-9-]+\.service", coordinator)
                and hex_value(binding_sha256, 64), "DISPATCH_CONFIGURATION_RED")
        protect_process()
        self.coordinator = coordinator
        self.owner = process_identity(os.getpid())
        self.journal = ProtectedJournal(parent / "dispatch")
        self.server = None
        self.used = False
        self.receipt = None
        self.intent = dict(coordinator=coordinator, owner=self.owner, binding_sha256=binding_sha256)
        try:
            # The directory itself is already a consuming object. This sealed
            # record is durable before the callback can contact PID 1.
            self.journal.once("dispatch-intent.json", self.intent)
            self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self.server.settimeout(30)
            self.server.bind(str(parent / "dispatch.sock"))
            os.chmod(parent / "dispatch.sock", 0o600)
            self.server.listen(1)
        except BaseException as error:
            close_preserving(error, self)
            raise

    def issue_once(self, start):
        require(not self.used, "DISPATCH_ALREADY_CONSUMED")
        self.used = True
        with resource_scope(self):
            self.journal.check()
            # No retry or second call after an exception/ambiguous result.
            result = start()
            connection, _ = self.server.accept()
            with resource_scope(connection):
                connection.settimeout(10)
                raw, ancillary, flags, _ = connection.recvmsg(4096, 0)
                value = json.loads(raw)
                require(not ancillary and flags == 0 and canonical(value) == raw
                        and set(value) == {"invocation", "binding_sha256"}
                        and value["binding_sha256"] == self.intent["binding_sha256"],
                        "DISPATCH_REQUEST_RED")
                identity = bind_peer(connection, unit=self.coordinator, phase="coordinate",
                                     invocation=value["invocation"])
                receipt = dict(intent_sha256=digest(self.intent), coordinator=identity,
                               invocation=value["invocation"], binding_sha256=value["binding_sha256"])
                self.journal.once("dispatch-handoff.json", receipt)
                # The original caller may stop only this exact owned PID-1
                # invocation on an uncertain result. No receipt => no such
                # authority; the coordinator cannot pass its live handoff.
                self.receipt = receipt
                require(bind_peer(connection, unit=self.coordinator, phase="coordinate",
                                  invocation=value["invocation"]) == identity, "DISPATCH_PEER_DRIFT")
                descriptor = sealed_message(canonical(receipt))
                with descriptor_scope(descriptor):
                    require(connection.sendmsg([b"S8-DISPATCH-ONCE"], [
                        (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))
                    ]) == len(b"S8-DISPATCH-ONCE"), "DISPATCH_SEND_UNKNOWN_NO_RETRY")
            self.journal.handoff()
            return result

    def close(self):
        close_members(self, "server", "journal")
        # No unlink, flag removal, reset or adoption API.


def receive_once(parent: Path, *, coordinator: str, owner: dict, binding_sha256: str):
    """Only the original live dispatcher can supply the one sealed handoff."""
    protect_process()
    require(process_identity(owner["pid"]) == owner and owner["uid"] == 0,
            "DISPATCH_OWNER_GONE")
    state = properties(coordinator)
    require(state["MainPID"] == str(os.getpid()) and state["ActiveState"] == "activating"
            and state["NRestarts"] == "0", "DISPATCH_COORDINATOR_ROLE_RED")
    descriptors = []
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    with resource_scope(connection):
        connection.settimeout(10)
        try:
            connection.connect(str(parent / "dispatch.sock"))
        except OSError:
            require(False, "DISPATCH_NO_LIVE_HANDOFF")
        require(peer(connection) == owner, "DISPATCH_OWNER_DRIFT")
        request = canonical(dict(invocation=state["InvocationID"], binding_sha256=binding_sha256))
        require(connection.send(request) == len(request), "DISPATCH_SEND_UNKNOWN_NO_RETRY")
        primary = None
        try:
            raw, ancillary, flags, _ = connection.recvmsg(64, socket.CMSG_SPACE(4))
            for level, kind, value in ancillary:
                require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, "DISPATCH_RIGHTS_RED")
                received = array.array("i")
                received.frombytes(value[:len(value) - len(value) % received.itemsize])
                descriptors.extend(received)
            require(raw == b"S8-DISPATCH-ONCE" and flags == 0 and len(descriptors) == 1,
                    "DISPATCH_RIGHTS_RED")
            payload = read_sealed(descriptors[0])
            value = json.loads(payload)
            intent = dict(coordinator=coordinator, owner=owner, binding_sha256=binding_sha256)
            require(canonical(value) == payload and value == dict(intent_sha256=digest(intent),
                    coordinator=process_identity(os.getpid()), invocation=state["InvocationID"],
                    binding_sha256=binding_sha256), "DISPATCH_BINDING_RED")
            require(peer(connection) == owner and properties(coordinator) == state,
                    "DISPATCH_PEER_DRIFT")
            return value
        except BaseException as error:
            primary = error
            raise
        finally:
            owned, descriptors = descriptors, []
            close_descriptors(primary, *owned)
