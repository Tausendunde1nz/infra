#!/usr/bin/python3 -I
"""One-shot read-only inventory; NOT a sudo broker or installation module.

No caller arguments, no raw file contents, process arguments, environment values,
journal messages or command stderr are emitted. Output is JSON on stdout only.
Unknown policy statements remain explicitly unreviewed; hashes are not approval.
"""
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

VERSION = "1.0.0"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
ROOTS = ("/etc/sudoers.d", "/etc/polkit-1", "/usr/share/polkit-1/rules.d")
TARGETS = ("/etc/sudoers", "/etc/group", "/etc/gshadow", "/etc/nsswitch.conf",
           "/usr/bin/pandoc", "/bin/mkdir", "/bin/chown", "/usr/bin/tee",
           "/opt/docs/upload_log.txt", "/opt/tu1nz_repos/infra/t1nz_create_golden.sh",
           "/usr/local/bin/t1nz_create_golden.sh", "/var/run/docker.sock",
           "/run/containerd/containerd.sock", "/etc/docker/daemon.json")
SAFE_RULE = re.compile(r"chatops\s+ALL\s*=\s*\((?:ALL|root)(?:\s*:\s*ALL)?\)\s*"
                       r"NOPASSWD:\s*(?:/usr/bin/pandoc|/bin/mkdir,\s*/bin/chown|"
                       r"/usr/bin/tee\s+-a\s+/opt/docs/upload_log\.txt|"
                       r"/opt/tu1nz_repos/infra/t1nz_create_golden\.sh)\s*")


def policy_lines(data):
    """Only exact previously observed literal grants may leave protected input."""
    records = []
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        value = line.strip()
        if not value or (value.startswith("#") and not value.startswith("#include")):
            continue
        item = {"line": number, "sha256": hashlib.sha256(line.encode()).hexdigest(),
                "classification": "UNREVIEWED"}
        if SAFE_RULE.fullmatch(value):
            item.update(classification="KNOWN_UNSAFE_GRANT", definition=value)
        records.append(item)
    return records


def command(args, timeout=20):
    """Fixed callers only. Anonymous bounded-lifetime output, never raw stderr."""
    start = time.monotonic_ns()
    result = {"program": args[0], "timeout": False}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            p = subprocess.Popen(args, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                 env=ENV, start_new_session=True, cwd="/")
        except OSError as exc:
            return dict(result, exception=type(exc).__name__, complete=False)
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            result["timeout"] = True
        finally:
            # Also remove descendants after an early parent exit.
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        result.update(returncode=p.returncode, stderr_bytes=err.tell(),
                      stdout_bytes=out.tell(), duration_ns=time.monotonic_ns()-start)
        out.seek(0)
        data = out.read(4 * 1024 * 1024 + 1)
        result["truncated"] = len(data) > 4 * 1024 * 1024
        result["complete"] = not result["timeout"] and not result["truncated"] and p.returncode == 0 and not result["stderr_bytes"]
        return result, data[:4 * 1024 * 1024]


def metadata(path):
    item = {"path": path}
    try:
        s = os.lstat(path)
        item.update(uid=s.st_uid, gid=s.st_gid, mode=oct(stat.S_IMODE(s.st_mode)),
                    inode=s.st_ino, device=s.st_dev,
                    type="symlink" if stat.S_ISLNK(s.st_mode) else "directory" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "special")
        if stat.S_ISREG(s.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                after = os.fstat(f.fileno())
                if (after.st_dev, after.st_ino) != (s.st_dev, s.st_ino):
                    raise RuntimeError("drift")
                if after.st_size <= 2 * 1024 * 1024:
                    data = f.read(2 * 1024 * 1024 + 1)
                    item["sha256"] = hashlib.sha256(data).hexdigest()
                    if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
                        item["policy_lines"] = policy_lines(data)
                else:
                    item["content_status"] = "OVER_LIMIT"
        acl = command(("/usr/bin/getfacl", "-n", "-c", "-P", "--", path))
        if isinstance(acl, tuple):
            status, data = acl
            # Numeric ACL grammar only; no comments, filenames or arbitrary text.
            lines = data.decode("ascii", "replace").splitlines()
            item["acl"] = [v for v in lines if re.fullmatch(r"(?:default:)?(?:user|group|mask|other):[0-9]*:[rwx-]{3}(?:\s+#effective:[rwx-]{3})?", v)]
            item["acl_status"] = status
        else:
            item["acl_status"] = acl
    except (OSError, RuntimeError) as exc:
        item["error"] = type(exc).__name__
    return item


def process_inventory(uid):
    rows = []
    for name in sorted(os.listdir("/proc")):
        if not name.isdecimal():
            continue
        try:
            with open("/proc/"+name+"/status") as f:
                fields = dict(line.split(":", 1) for line in f if ":" in line)
            uids = [int(v) for v in fields["Uid"].split()]
            if uid not in uids:
                continue
            # No comm/argv/environment: user-chosen names may themselves contain secrets.
            rows.append({"pid": int(name), "uids": uids,
                         "gids": [int(v) for v in fields["Gid"].split()],
                         "groups": [int(v) for v in fields["Groups"].split()],
                         "cap_eff": fields.get("CapEff", "").strip()})
        except (OSError, KeyError, ValueError):
            rows.append({"pid": int(name), "status": "RACED_OR_UNREADABLE"})
    return rows


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        return 3
    os.environ.clear()
    os.environ.update(ENV)
    result = {"version": VERSION, "status": "INCOMPLETE", "sections": [],
              "note": "Unknown policies require review; no completeness claim."}
    try:
        paths = set(TARGETS)
        for root in ROOTS:
            paths.add(root)
            for directory, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
                paths.update(os.path.join(directory, n) for n in files)
        for path in tuple(paths):
            parent = os.path.dirname(path)
            while parent and parent != "/":
                paths.add(parent)
                parent = os.path.dirname(parent)
        for path in sorted(paths):
            result["sections"].append(metadata(path))
        result["chatops_processes"] = process_inventory(pwd.getpwnam("chatops").pw_uid)
        # Capability and setuid inventories need separate reviewed scope after this gate.
        result["remaining_scope"] = ["polkit semantics", "sudo include/alias resolution",
                                     "capabilities/setuid filesystem coverage",
                                     "process restart and rollback plan"]
    except BaseException as exc:
        result["exception"] = type(exc).__name__
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    sys.exit(main())
