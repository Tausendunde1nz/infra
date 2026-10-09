"""Fixed read-only configuration and DNS interfaces for the sealed S8 root.

Content is copied from authenticated in-memory release inputs, never imported
from an arbitrary host path. No credential, permit or provider call is made.
DNS is an explicit per-operation snapshot, not Docker's build resolver.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat

from tu1nz_s8_execution_contract import descriptor_scope, require
from tu1nz_s8_sealed_root import require_private_namespace, run


CONFIG_NAMES = (
    "adult-commercial-s8-public-telegram.json", "adult-commercial-s8-copy.json",
    "adult-commercial-s10-2d-community.json", "adult-commercial-s10-2d-community-copy.json",
    "adult-commercial-s11-interactive-experience.json", "adult-commercial-s11-interactive-copy.json",
)


def configuration_inputs(values: dict[str, bytes], expected: dict[str, str]):
    require(type(values) is dict and set(values) == set(CONFIG_NAMES)
            and type(expected) is dict and set(expected) == set(CONFIG_NAMES), "CONFIGURATION_SET_RED")
    for name, payload in values.items():
        require(type(payload) is bytes and 0 < len(payload) <= 131072
                and hashlib.sha256(payload).hexdigest() == expected[name], "CONFIGURATION_BINDING_RED")
    return values.copy()


def resolver_input(payload: bytes):
    """Preserve a bounded validated OS resolver snapshot; no shell/NSS hooks.

    Search domains and options are retained only from this explicit grammar.
    Unknown options fail closed instead of silently changing DNS semantics.
    """
    require(type(payload) is bytes and 0 < len(payload) <= 8192, "DNS_INPUT_RED")
    try:
        text = payload.decode("ascii")
    except UnicodeError:
        require(False, "DNS_INPUT_RED")
    require("\0" not in text and "\r" not in text, "DNS_INPUT_RED")
    servers = []
    search = False
    option_seen = False
    for line in text.splitlines():
        fields = re.split(r"[#;]", line, maxsplit=1)[0].split()
        if not fields: continue
        if fields[0] == "nameserver" and len(fields) == 2:
            try: address = ipaddress.ip_address(fields[1])
            except ValueError: require(False, "DNS_INPUT_RED")
            require(not address.is_unspecified and not address.is_multicast, "DNS_INPUT_RED")
            servers.append(address)
        elif fields[0] in {"search", "domain"}:
            require(not search and 1 < len(fields) <= (2 if fields[0] == "domain" else 7), "DNS_INPUT_RED")
            search = True
            for domain in fields[1:]:
                # systemd-resolved uses '.' for the root/no-search domain.
                # Only that exact token is special; empty interior labels and
                # repeated terminal separators must still fail closed.
                if domain == ".":
                    continue
                require(len(domain) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                        for label in domain.removesuffix(".").split(".")), "DNS_INPUT_RED")
        elif fields[0] == "options":
            require(not option_seen and 1 < len(fields) <= 9, "DNS_INPUT_RED")
            option_seen = True
            for value in fields[1:]:
                require(value in {"edns0", "trust-ad", "rotate", "single-request", "single-request-reopen"}
                        or re.fullmatch(r"(?:timeout:[1-5]|attempts:[1-3]|ndots:[0-5])", value), "DNS_INPUT_RED")
        else:
            require(False, "DNS_INPUT_RED")
    require(0 < len(servers) <= 3 and len(servers) == len(set(servers)), "DNS_INPUT_RED")
    return payload


def _write(directory: Path, name: str, payload: bytes):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with descriptor_scope(fd):
        os.fchmod(fd, 0o644)
        remaining = payload
        while remaining:
            size = os.write(fd, remaining)
            require(size > 0, "CONFIGURATION_WRITE_RED")
            remaining = remaining[size:]
        os.fsync(fd)


def mount_configuration(mounted, values, expected, resolver):
    """Publication is a readonly private tmpfs plus fixed per-file mounts.

    No live/source object is changed, no .pth/library directory is exposed and
    the original empty image directory is the only accepted mountpoint.
    """
    require_private_namespace()
    require(mounted.mounted and os.geteuid() == 0, "CONFIGURATION_MOUNT_RED")
    values = configuration_inputs(values, expected)
    resolver_input(resolver)
    root = mounted.destination
    target = root / "run/s8-configuration"
    before = target.lstat()
    require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
            and not before.st_mode & 0o022 and before.st_dev == root.stat().st_dev
            and not any(target.iterdir()),
            "CONFIGURATION_MOUNTPOINT_RED")
    run(["/usr/bin/mount", "-t", "tmpfs", "-o", "rw,size=2m,mode=0755,nodev,nosuid,noexec",
         "s8-private-configuration", str(target)])
    for name in CONFIG_NAMES: _write(target, name, values[name])
    _write(target, "resolv.conf", resolver)
    directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    with descriptor_scope(directory): os.fsync(directory)
    run(["/usr/bin/mount", "-o", "remount,ro,nodev,nosuid,noexec", str(target)])
    # The image prescribes an empty regular resolver mountpoint. Docker's
    # omitted runtime resolver must never become a hidden build dependency.
    targets = {name: root / "etc/tu1nz" / name for name in CONFIG_NAMES}
    targets["resolv.conf"] = root / "etc/resolv.conf"
    for name, destination in targets.items():
        m = destination.lstat()
        require(stat.S_ISREG(m.st_mode) and m.st_uid == m.st_gid == 0
                and m.st_nlink == 1 and m.st_size == 0 and m.st_dev == root.stat().st_dev,
                "CONFIGURATION_FILE_MOUNTPOINT_RED")
        run(["/usr/bin/mount", "--bind", str(target / name), str(destination)])
        run(["/usr/bin/mount", "-o", "remount,bind,ro,nodev,nosuid,noexec", str(destination)])
    for point in (target, *targets.values()):
        options = set(run(["/usr/bin/findmnt", "--noheadings", "--raw", "--output", "OPTIONS",
                           "--mountpoint", str(point)]).split(","))
        require({"ro", "nodev", "nosuid", "noexec"} <= options, "CONFIGURATION_READONLY_RED")
    require(targets["resolv.conf"].read_bytes() == resolver, "DNS_PUBLICATION_RED")
    require(configuration_inputs({name: targets[name].read_bytes() for name in CONFIG_NAMES}, expected) == values,
            "CONFIGURATION_PUBLICATION_RED")
