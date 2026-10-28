"""Bounded synthetic report transport. No guard, object repair or admission API.

The guest only reads one fixed report through an existing Docker exec channel.
The runner creates its own 0700 export directory; it is never mounted/chowned
by the guest. Raw bytes are retained even when validation or measurement is RED.
"""
import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

MAX_LOG = 16 * 1024 * 1024
EXPORT_SECONDS = 30
REAP_SECONDS = 2
REPORT = "/var/tmp/s8-primary-observation.jsonl"
FIXTURE_REPORT = "/s8-native-profile/s8-primary-observation.jsonl"
EXPECTED_PHASES = {"root-created", "root-sealed", "slot-created", "intent-sealed", "objects-sealed",
                   "/var/tmp:known_foreign_chmod", "/s8-native-profile:known_foreign_chmod"}


def evidence_diagnostics(raw, recorder_errors=()):
    """Same acceptance conditions as c3ca4cb; finite reasons instead of silence."""
    codes = []
    def fail(code):
        if code not in codes: codes.append(code)
    if recorder_errors: fail("RECORDER_ERROR")
    if len(raw) > MAX_LOG: fail("REPORT_SIZE_LIMIT")
    if not raw: fail("REPORT_EMPTY")
    if not raw.endswith(b"\n"): fail("REPORT_NO_FINAL_NEWLINE")
    # Do not parse an oversized report. The original validator rejected it too.
    if len(raw) > MAX_LOG:
        return dict(evidence_complete=False, codes=codes)
    try:
        rows = [json.loads(line) for line in raw.splitlines()]
    except (ValueError, UnicodeError):
        fail("REPORT_JSON_INVALID")
        return dict(evidence_complete=False, codes=codes)
    try:
        end = [r for r in rows if r["operation"] == "measurement_end"]
        begins = [r["case"] for r in rows if r["operation"] == "case_begin"]
        ends = [r["case"] for r in rows if r["operation"] == "case_end"]
        if len(end) != 1: fail("END_RECORD_COUNT")
        else:
            if rows[-1] != end[0]: fail("END_RECORD_NOT_LAST")
            if end[0]["tests"] != 3: fail("END_TEST_COUNT")
        if len(begins) != 3: fail("CASE_COUNT")
        if len(set(begins)) != 3: fail("CASE_NOT_UNIQUE")
        if begins != ends: fail("CASE_END_MISMATCH")
        forks = [r for r in rows if r["operation"] == "fork_parent"]
        exits = [r for r in rows if r["operation"] == "child_exit"]
        if len(forks) != 7: fail("FORK_COUNT")
        if len(exits) != 7: fail("CHILD_END_COUNT")
        if len({r["child_pid"] for r in forks}) != 7: fail("CHILD_PID_NOT_UNIQUE")
        if {r["phase"] for r in forks} != EXPECTED_PHASES: fail("EXPECTED_PHASES_MISMATCH")
        if {r["child_pid"] for r in forks} != {r["caller_pid"] for r in exits}: fail("CHILD_PID_SET_MISMATCH")
        for fork in forks:
            ended = [r for r in exits if r["caller_pid"] == fork["child_pid"]]
            if len(ended) != 1: fail("CHILD_END_BINDING")
            elif ended[0]["phase"] != fork["phase"]: fail("CHILD_PHASE_MISMATCH")
        for row in rows:
            if row.get("observation_invalid"):
                fail("OBSERVATION_INVALID")
                known = {"INOTIFY_HEADER_SHORT", "INOTIFY_NAME_TRUNCATED", "INOTIFY_NAME_ENCODING",
                         "INOTIFY_OVERFLOW", "INOTIFY_WATCH_LOST", "INOTIFY_UNMOUNT",
                         "INOTIFY_WD_UNBOUND", "INOTIFY_OBJECT_UNBOUND", "WATCH_METADATA_UNAVAILABLE"}
                for detail in row.get("observation_codes", []):
                    fail(detail if detail in known else "OBSERVATION_DETAIL_UNKNOWN")
            if row.get("observer_errors"): fail("OBSERVER_RECORDED_ERROR")
            if row["operation"] == "child_exit" and row["code"] == 99:
                errors = [r for r in rows if r.get("caller_pid") == row["caller_pid"]
                          and r["operation"] == "child_first_unexpected_exception"]
                if len(errors) != 1: fail("CHILD99_EXCEPTION_COUNT")
                else:
                    if rows.index(errors[0]) > rows.index(row): fail("CHILD_EXCEPTION_AFTER_EXIT")
                    if errors[0]["phase"] != row["phase"]: fail("CHILD_EXCEPTION_PHASE_MISMATCH")
    except (KeyError, TypeError, ValueError, IndexError):
        fail("REPORT_SCHEMA_INVALID")
    return dict(evidence_complete=bool(rows) and not codes, codes=codes)


def validate_log(raw, recorder_errors=()):
    return evidence_diagnostics(raw, recorder_errors)["evidence_complete"]


def send_report(path, output, limit=MAX_LOG):
    """Read-only sender, including a bounded prefix when oversized/changed."""
    fd = None; sent = 0; before = None; code = "REPORT_UNAVAILABLE"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            code = "REPORT_OBJECT_INVALID"
        else:
            code = "STREAM_COMPLETE"
            while sent < min(before.st_size, limit):
                data = os.read(fd, min(65536, min(before.st_size, limit) - sent))
                if not data:
                    code = "REPORT_SHORT_READ"; break
                view = memoryview(data)
                while view:
                    count = output.write(view)
                    if count is None or count <= 0: raise OSError()
                    sent += count; view = view[count:]
            output.flush()
            after = os.fstat(fd)
            if before.st_size > limit: code = "REPORT_SIZE_LIMIT"
            elif (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                code = "REPORT_CHANGED"
    except OSError as error:
        if fd is not None: code = "REPORT_READ_OR_STREAM_ERROR"
        elif error.errno == errno.ENOENT: code = "REPORT_MISSING"
        elif error.errno == errno.ELOOP: code = "REPORT_OBJECT_INVALID"
        else: code = "REPORT_UNAVAILABLE"
    finally:
        if fd is not None:
            try: os.close(fd)
            except OSError: code = "REPORT_READ_OR_STREAM_ERROR"
    return dict(code=code, bytes_sent=sent, source_size=None if before is None else before.st_size)


def final_exit(measurement_exit, export_exit, evidence_complete, launcher_exit=0):
    # Never turn an original nonzero measurement/timeout into success.
    if measurement_exit: return measurement_exit
    if launcher_exit: return launcher_exit
    if measurement_exit is None: return 74
    if export_exit: return export_exit
    return 0 if evidence_complete else 74


def receive_report(process, export_dir, measurement_exit, limit=MAX_LOG, launcher_exit=0,
                   timeout=EXPORT_SECONDS, diagnostics=evidence_diagnostics):
    """A producer's stdout is only report bytes; stderr is bounded fixed JSON.

    No event is parsed away or rewritten in the saved raw prefix. Any truncation
    or unavailable bytes are explicit PARTIAL evidence and cannot produce PASS.
    """
    errors = []; stderr = bytearray(); stderr_overflow = False; fd = directory = None
    directory_valid = False
    saved = 0; copied = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        directory = os.open(export_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise PermissionError()
        directory_valid = True
        fd = os.open("observation.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        for stream, channel in ((process.stdout, "raw"), (process.stderr, "status")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, channel)
        aborted = False
        while selector.get_map() and not aborted:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                errors.append("EXPORT_DEADLINE"); break
            for key, _ in selector.select(remaining):
                try: data = os.read(key.fd, 65536)
                except BlockingIOError: continue
                if not data:
                    selector.unregister(key.fileobj); continue
                if key.data == "status":
                    space = max(0, 4096 - len(stderr))
                    stderr.extend(data[:space])
                    if len(data) > space: stderr_overflow = True
                    continue
                piece = data[:max(0, limit - saved)]
                oversized = len(piece) != len(data)
                view = memoryview(piece)
                while view:
                    count = os.write(fd, view)
                    if count <= 0: raise OSError()
                    copied.extend(view[:count]); saved += count; view = view[count:]
                if oversized:
                    errors.append("EXPORT_SIZE_LIMIT"); aborted = True; break
        os.fsync(fd)
    except OSError:
        errors.append("EXPORT_IO_ERROR")
    finally:
        selector.close()
        if fd is not None:
            try: os.close(fd)
            except OSError: errors.append("EXPORT_IO_ERROR")
        process.stdout.close()
        process.stderr.close()
    sender_exit = None
    try:
        if errors:
            try: process.terminate()
            except OSError: errors.append("SENDER_TERMINATE_ERROR")
        process.wait(timeout=REAP_SECONDS if errors else max(0, deadline - time.monotonic()))
        sender_exit = process.returncode
    except subprocess.TimeoutExpired:
        errors.append("SENDER_REAP_DEADLINE")
        try: process.kill()
        except OSError: errors.append("SENDER_KILL_ERROR")
        try:
            process.wait(timeout=REAP_SECONDS)
            sender_exit = process.returncode
        except subprocess.TimeoutExpired: errors.append("SENDER_UNREAPED")
    if stderr_overflow: errors.append("SENDER_STATUS_SIZE_LIMIT")
    sender = None
    try:
        candidate = json.loads(stderr)
        allowed = {"STREAM_COMPLETE", "REPORT_MISSING", "REPORT_UNAVAILABLE", "REPORT_OBJECT_INVALID", "REPORT_SIZE_LIMIT",
                   "REPORT_SHORT_READ", "REPORT_CHANGED", "REPORT_READ_OR_STREAM_ERROR"}
        if (set(candidate) != {"code", "bytes_sent", "source_size"} or candidate["code"] not in allowed
                or type(candidate["bytes_sent"]) is not int or candidate["bytes_sent"] < 0
                or (candidate["source_size"] is not None and
                    (type(candidate["source_size"]) is not int or candidate["source_size"] < 0))):
            raise ValueError()
        sender = candidate
    except (ValueError, TypeError):
        errors.append("SENDER_STATUS_INVALID")
    if sender_exit != 0: errors.append("SENDER_NONZERO")
    if sender is not None:
        if sender["code"] != "STREAM_COMPLETE": errors.append(sender["code"])
        if sender["bytes_sent"] != saved: errors.append("EXPORT_BYTE_COUNT_MISMATCH")
        if sender["code"] == "STREAM_COMPLETE" and sender["source_size"] != saved: errors.append("SOURCE_BYTE_COUNT_MISMATCH")
    try:
        diagnostic = diagnostics(bytes(copied))
        if type(diagnostic["evidence_complete"]) is not bool or not isinstance(diagnostic["codes"], list):
            raise ValueError()
    except Exception:
        # A profile validator cannot prevent preservation/framing of raw RED
        # evidence or replace the original measurement exit status.
        diagnostic = dict(evidence_complete=False, codes=["PROFILE_VALIDATOR_ERROR"])
    export_exit = 74 if errors else 0
    complete = not errors and diagnostic["evidence_complete"]
    result = dict(measurement_exit=measurement_exit, measurement_started=measurement_exit is not None,
        launcher_exit=launcher_exit, sender_exit=sender_exit, export_exit=export_exit,
        report_state="COMPLETE" if complete else "PARTIAL", bytes_saved=saved,
        raw_sha256=hashlib.sha256(copied).hexdigest(), transport_codes=sorted(set(errors)),
        evidence_complete=complete, evidence_codes=diagnostic["codes"], sender=sender,
        final_exit=final_exit(measurement_exit, export_exit, complete, launcher_exit))
    # Create-only status beside the raw bytes, including a negative outcome.
    try:
        if not directory_valid: raise OSError()
        status_fd = os.open("transport.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(status_fd, "wb") as stream:
            stream.write((json.dumps(result, sort_keys=True) + "\n").encode()); stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    except OSError:
        result["transport_codes"].append("EXPORT_STATUS_IO_ERROR")
        result["export_exit"] = 74; result["evidence_complete"] = False; result["report_state"] = "PARTIAL"
        result["final_exit"] = final_exit(measurement_exit, 74, False, launcher_exit)
    finally:
        if directory is not None:
            try: os.close(directory)
            except OSError:
                result["transport_codes"].append("EXPORT_DIRECTORY_CLOSE_ERROR")
                result["export_exit"] = 74; result["evidence_complete"] = False; result["report_state"] = "PARTIAL"
                result["final_exit"] = final_exit(measurement_exit, 74, False, launcher_exit)
    return result, bytes(copied)


def docker_export(container, export_dir, measurement_exit, fixture=False, launcher_exit=0,
                  diagnostics=evidence_diagnostics):
    if not re.fullmatch("[0-9a-f]{64}", container): raise ValueError("CONTAINER_ID_REQUIRED")
    command = ["docker", "exec", container, "python3", "-B", "tests/s8_evidence_export.py", "--send"]
    if fixture: command.append("--fixture")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    return receive_report(process, export_dir, measurement_exit, launcher_exit=launcher_exit,
                          diagnostics=diagnostics)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--send", action="store_true"); parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--container"); parser.add_argument("--export-dir")
    parser.add_argument("--measurement-exit", type=int)
    parser.add_argument("--launcher-exit", type=int, default=0)
    args = parser.parse_args()
    if args.send:
        if not (sys.platform == "linux" and os.geteuid() == 0 and os.environ.get("container") == "docker"
                and Path("/.dockerenv").is_file()): return 74
        status = send_report(FIXTURE_REPORT if args.fixture else REPORT, sys.stdout.buffer)
        print(json.dumps(status, sort_keys=True), file=sys.stderr, flush=True)
        return 0 if status["code"] == "STREAM_COMPLETE" else 74
    if not (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and (args.measurement_exit is None or 0 <= args.measurement_exit <= 255)
            and 0 <= args.launcher_exit <= 255): return 74
    try:
        result, raw = docker_export(args.container or "", args.export_dir, args.measurement_exit, args.fixture, args.launcher_exit)
    except (OSError, ValueError, TypeError):
        result, raw = dict(measurement_exit=args.measurement_exit, launcher_exit=args.launcher_exit,
            export_exit=74, report_state="PARTIAL", evidence_complete=False,
            transport_codes=["EXPORT_START_ERROR"], final_exit=final_exit(args.measurement_exit, 74, False, args.launcher_exit)), b""
    print("S8_PRIMARY_TRANSPORT " + json.dumps(result, sort_keys=True), flush=True)
    # Base64 preserves even a partial final UTF-8 sequence through hosted logs.
    print("S8_PRIMARY_RAW_B64_BEGIN", flush=True)
    encoded = base64.b64encode(raw).decode("ascii")
    for offset in range(0, len(encoded), 4096): print("S8_PRIMARY_RAW_B64 " + encoded[offset:offset + 4096])
    print("S8_PRIMARY_RAW_B64_END", flush=True)
    return result["final_exit"]


if __name__ == "__main__": raise SystemExit(main())
