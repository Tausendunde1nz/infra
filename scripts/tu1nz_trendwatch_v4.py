"""Non-root Trendwatch core. Deployment is gated on the remaining inventory.

Delivery is deliberately at-most-one-attempt per slot. An interrupted/ambiguous
HTTP outcome stays UNCERTAIN; automatic retry could duplicate a real message.
No root context is supported. Tests use injected transports, never the network.
"""
import contextlib
import datetime
import errno
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat

SLOTS = {"morning": 8, "midday": 12, "afternoon": 15, "evening": 19}
TITLE = "AI Pet Transform"
SCORE = 0.62
FALLBACK = "Kein interessanter YouTube LIVE-Trend gefunden"
TRENDS = ("🔥 Aktuelle Trends 🔥\n\n"
          "• 🐾 AI Pet Transform (platform: TikTok, score: 0.62)\n"
          "• 📈 AI Meme Boom (platform: Instagram, score: 0.27)\n"
          "• 🎧 New Remix Trend (platform: YouTube, score: 0.44)")


class UnsafeState(ValueError):
    pass


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def slot_key(context, day):
    if context not in SLOTS or not isinstance(day, datetime.date):
        raise UnsafeState("slot")
    return day.isoformat() + "-" + context


def message(live_title, label, keyword):
    if keyword not in ("soundcore+mini", "bluetooth+lautsprecher"):
        raise UnsafeState("product")
    if not isinstance(live_title, str) or len(live_title) > 500:
        raise UnsafeState("title")
    if not isinstance(label, str) or not 1 <= len(label) <= 100:
        raise UnsafeState("label")
    url = ("https://www.amazon.de/s?k=" + keyword +
           "&tag=tu1nz21-21&ref=tu1nz_affiliate&cat=remix&q=" + keyword)
    return ("\n" + html.escape(TRENDS) + "\n\n🎥 Aktueller YouTube LIVE Trend\n• " +
            html.escape(live_title or FALLBACK) + "\n\n\n🎯 AFFILIATE-TIPP\n\n" +
            "👉 Produkt: " + html.escape(keyword) + "\n📌 Kategorie: " +
            html.escape(label) + "\n🛒 Jetzt ansehen: " + html.escape(url))


class State:
    """Private directory, descriptor-relative access, explicit modes, no links.

    No caller-controlled path is passed to this component by a deployed service.
    In tests the caller supplies only its isolated fixture directory.
    """
    def __init__(self, path):
        if os.geteuid() == 0:
            raise UnsafeState("root_forbidden")
        self.path = Path(path).absolute()
        if self.path.is_symlink():
            raise UnsafeState("directory_link")
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            s = os.fstat(self.fd)
            if s.st_uid != os.geteuid() or s.st_gid != os.getegid() or stat.S_IMODE(s.st_mode) != 0o700:
                raise UnsafeState("directory_metadata")
            if hasattr(os, "listxattr") and any("posix_acl" in a for a in os.listxattr(self.fd)):
                raise UnsafeState("directory_acl")
            self.identity = (s.st_dev, s.st_ino)
            self.lock = self._open("lock", os.O_RDWR | os.O_CREAT)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            if hasattr(self, "lock"):
                os.close(self.lock)
            os.close(self.fd)
            raise

    def _same(self):
        s = os.stat(self.path, follow_symlinks=False)
        if not stat.S_ISDIR(s.st_mode) or (s.st_dev, s.st_ino) != self.identity:
            raise UnsafeState("directory_swapped")

    def _open(self, name, flags):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
            raise UnsafeState("filename")
        self._same()
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or
                s.st_uid != os.geteuid() or s.st_gid != os.getegid() or stat.S_IMODE(s.st_mode) != 0o600):
            os.close(fd)
            raise UnsafeState("file_metadata")
        if hasattr(os, 'listxattr') and any('posix_acl' in a for a in os.listxattr(fd)):
            os.close(fd)
            raise UnsafeState('file_acl')
        return fd

    def read(self, name):
        try:
            fd = self._open(name, os.O_RDONLY)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as f:
            data = f.read(65537)
            if len(data) > 65536:
                raise UnsafeState("state_size")
        return data

    def write(self, name, data):
        if not isinstance(data, bytes) or len(data) > 65536:
            raise UnsafeState("state_size")
        self.read(name)  # Refuse existing links, hardlinks, unsafe owner/mode/type.
        temporary = ".new-" + secrets.token_hex(16)
        fd = self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self._same()
            self.read(name)  # Recheck immediately before replace, under exclusive lock.
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def close(self):
        os.close(self.lock)
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def load_record(raw, key):
    if raw is None:
        return None
    try:
        record = json.loads(raw)
    except (ValueError, UnicodeError):
        raise UnsafeState("invalid_json") from None
    if (not isinstance(record, dict) or set(record) != {"slot", "state", "message_sha256"}
            or record["slot"] != key or record["state"] not in {"UNCERTAIN", "SENT"}
            or not isinstance(record["message_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["message_sha256"])):
        raise UnsafeState("invalid_record")
    return record


def run_slot(state, context, day, live_title, label, transport, credentials):
    key = slot_key(context, day)
    name = key + ".json"
    old = load_record(state.read(name), key)
    if old:
        return "ALREADY_SENT" if old["state"] == "SENT" else "DELIVERY_UNCERTAIN_NO_RETRY"
    # Validation precedes all mutations. No credential material is included in errors.
    if (not isinstance(credentials, dict) or set(credentials) != {"token", "destination"}
            or not all(isinstance(v, str) and v for v in credentials.values())):
        raise UnsafeState("credentials_missing")
    keyword = ("soundcore+mini", "bluetooth+lautsprecher")[int(hashlib.sha256(key.encode()).hexdigest(), 16) % 2]
    body = message(live_title, label, keyword)
    record = {"slot": key, "state": "UNCERTAIN", "message_sha256": hashlib.sha256(body.encode()).hexdigest()}
    state.write("today_title.txt", (TITLE + "\n").encode())
    state.write(name, encode(record))
    # Transport must confirm Telegram ok==true, not merely HTTP 200.
    # No retry on exception or negative acknowledgement: delivery may have happened.
    try:
        accepted = transport(body, credentials)
    except Exception:
        return "DELIVERY_UNCERTAIN_NO_RETRY"
    if accepted is not True:
        return "DELIVERY_UNCERTAIN_NO_RETRY"
    record["state"] = "SENT"
    state.write(name, encode(record))
    return "SENT"


def missed_slots(records, day, hour):
    missing = []
    for context, scheduled in SLOTS.items():
        key = slot_key(context, day)
        if scheduled <= hour and key not in records:
            missing.append(context)
    return missing


def render_service(context):
    if context not in SLOTS:
        raise UnsafeState("context")
    # Candidate only: the deployment adapter remains blocked on protected inventory.
    return ("[Unit]\nDescription=TU1NZ isolated Trendwatch " + context + "\n"
            "Wants=network-online.target\nAfter=network-online.target\n\n"
            "[Service]\nType=oneshot\nUser=tu1nz-trendwatch\nGroup=tu1nz-trendwatch\n"
            "UMask=0027\nStateDirectory=tu1nz-trendwatch\nStateDirectoryMode=0700\n"
            "NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
            "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n"
            "ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
            "RestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictRealtime=yes\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
            "ReadWritePaths=/var/lib/tu1nz-trendwatch\n"
            "LoadCredential=telegram-token:/etc/tu1nz/trendwatch-credentials/telegram-token\n"
            "LoadCredential=telegram-destination:/etc/tu1nz/trendwatch-credentials/telegram-destination\n"
            "ExecStart=/usr/local/libexec/tu1nz-trendwatch-v4 " + context + "\n"
            "TimeoutStartSec=45\nRestart=no\n")
