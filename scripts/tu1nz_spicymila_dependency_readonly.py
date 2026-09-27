"""Read-only privileged dependency gap collector. Never starts services or sends requests.
Run only after Daniel's explicit readiness confirmation. JSON contains metadata only.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

TERMS = ("tausendunde1nz_net", "172.25.0.3", "172.25.0.2",
         "spicymila_bot", "telegram_bot_mommyramona", "docker network connect",
         "watch_spicymila", "watch_mommyramona", "8090", "8081")
ROOTS = ("/etc/nginx", "/etc/systemd/system", "/usr/local/bin",
         "/etc/cron.d", "/var/spool/cron/crontabs")
EXTRA = ("/etc/crontab", "/opt/telegram_chatbot/.env")

def summarize(text):
    lines = text.splitlines()
    return {"line_count": len(lines),
            "references": {term: [i + 1 for i, line in enumerate(lines) if term in line]
                           for term in TERMS if term in text},
            "active_reference_lines": [i + 1 for i, line in enumerate(lines)
                if line.strip() and not line.lstrip().startswith("#")
                and any(term in line for term in TERMS)]}

def file_metadata(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 2_000_000:
            return {"path": str(path), "skipped": "nonregular or oversized"}
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(2_000_001)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            return {"path": str(path), "unstable_read": True}
        return {"path": str(path), "uid": before.st_uid, "gid": before.st_gid,
                "mode": oct(stat.S_IMODE(before.st_mode)),
                "sha256": hashlib.sha256(data).hexdigest(), **summarize(data.decode(errors="replace"))}
    finally:
        os.close(fd)

def journal_metadata():
    # Journal messages are reduced in memory; no raw message, argument, URL or payload is emitted.
    command = ["/usr/bin/journalctl", "--no-pager", "-o", "json",
               "--since", "2025-10-12", "-u", "docker.service", "-u", "cron.service"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    matches = []; total = 0; first = None; last = None
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        total += 1; timestamp = row.get("__REALTIME_TIMESTAMP")
        first = first or timestamp; last = timestamp
        hits = [term for term in TERMS if term in str(row.get("MESSAGE", ""))]
        if hits:
            matches.append({"timestamp_us": timestamp, "terms": hits})
    return {"returncode": result.returncode, "record_count": total,
            "first_us": first, "last_us": last, "matches": matches}

def nat_metadata():
    result = subprocess.run(["/usr/sbin/iptables-save", "-t", "nat"],
                            capture_output=True, text=True, timeout=15)
    rows = []
    for line in result.stdout.splitlines():
        port = re.search(r"--dport (8090|8081)(?: |$)", line)
        target = re.search(r"--to-destination (172\.[0-9.]+:[0-9]+)", line)
        if port and target:
            rows.append({"host_port": int(port[1]), "destination": target[1]})
    return {"returncode": result.returncode, "bot_dnat": rows}


def self_test():
    secret = "DO_NOT_EMIT_SECRET_OR_MESSAGE"
    fixture = "# watch_spicymila disabled\nTOKEN=" + secret + "\ncall spicymila_bot secret=" + secret
    result = summarize(fixture)
    assert result["active_reference_lines"] == [3]
    assert result["references"]["watch_spicymila"] == [1]
    assert result["references"]["spicymila_bot"] == [3]
    assert secret not in json.dumps(result)
    assert summarize("password=" + secret)["references"] == {}
    assert summarize("")["line_count"] == 0
    print("PASS: metadata-only redaction, comments and empty input")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    if os.geteuid() != 0:
        raise SystemExit("Readiness-confirmed sudo required; no collection performed")
    files = set(EXTRA)
    for root in ROOTS:
        for base, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(base) / name).is_symlink()]
            files.update(str(Path(base) / name) for name in names)
    rows = []
    for name in sorted(files):
        try:
            rows.append(file_metadata(Path(name)))
        except OSError as exc:
            rows.append({"path": name, "errno": exc.errno})
    print(json.dumps({"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "mode": "read-only; no raw file contents", "files": rows,
                      "journal": journal_metadata(), "nat": nat_metadata()}, indent=2))

if __name__ == "__main__":
    main()
