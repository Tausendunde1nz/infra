#!/usr/bin/env python3
"""Kernel-enforced immutable execution image; no service or provider actions.

The host's image is untrusted until copied, hashed and sealed. Runtime reads
only the sealed backing object through SquashFS in its private mount namespace.
Changing/renaming/chmodding the original image cannot change that object.
The kernel, namespace/device administration and privileged ptrace are the host
TCB, not adversaries this user-space launcher could safely defeat.
"""
from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess


class SealedRootError(RuntimeError):
    pass


_PRIVATE_NAMESPACE = None


def require(ok, code):
    if not ok:
        raise SealedRootError("S8_EXECUTION_" + code)


def run(argv, *, pass_fds=()):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                       pass_fds=pass_fds, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    require(p.returncode == 0, "KERNEL_COMMAND_RED")
    return p.stdout.strip()


def private_namespace():
    """Only for the dedicated launcher/isolated test child, never its caller."""
    global _PRIVATE_NAMESPACE
    before = os.stat("/proc/self/ns/mnt")
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0,
            "PROCESS_HANDLE_PROTECTION_RED")
    require(libc.unshare(0x00020000) == 0, "PRIVATE_MOUNT_NAMESPACE_REQUIRED")
    run(["/usr/bin/mount", "--make-rprivate", "/"])
    after = os.stat("/proc/self/ns/mnt")
    require((before.st_dev,before.st_ino) != (after.st_dev,after.st_ino),
            "PRIVATE_MOUNT_NAMESPACE_REQUIRED")
    # Do not add CAP_SYS_PTRACE merely to read PID 1's namespace. The observed
    # successful unshare transition proves ownership of this new namespace.
    _PRIVATE_NAMESPACE = (os.getpid(),after.st_dev,after.st_ino)


def require_private_namespace():
    current = os.stat("/proc/self/ns/mnt")
    require(_PRIVATE_NAMESPACE == (os.getpid(),current.st_dev,current.st_ino),
            "PRIVATE_MOUNT_NAMESPACE_REQUIRED")


def sealed_copy(path: Path, sha256: str, *, owner=0, limit=1024*1024*1024):
    require(re.fullmatch("[0-9a-f]{64}", sha256), "IMAGE_DIGEST_RED")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == owner and not before.st_mode & 0o022
            and 0 < before.st_size <= limit, "IMAGE_INPUT_RED")
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    target = os.memfd_create("tu1nz-s8-execution", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        fingerprint = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_uid,s.st_gid,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
        require(fingerprint(before) == fingerprint(os.fstat(source)), "IMAGE_INPUT_DRIFT")
        h = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            data = os.read(source, min(remaining, 1024*1024))
            require(bool(data), "IMAGE_SHORT_READ")
            h.update(data); remaining -= len(data)
            while data:
                written = os.write(target, data)
                require(written > 0, "IMAGE_COPY_RED")
                data = data[written:]
        require(h.hexdigest() == sha256 and fingerprint(before) == fingerprint(os.fstat(source))
                == fingerprint(path.lstat()), "IMAGE_INPUT_DRIFT")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(target, fcntl.F_ADD_SEALS, seals)
        require(fcntl.fcntl(target, fcntl.F_GET_SEALS) == seals, "IMAGE_SEAL_RED")
        os.lseek(target, 0, os.SEEK_SET)
        return target
    except BaseException:
        os.close(target)
        raise
    finally:
        os.close(source)


class MountedImage:
    """An owned loop attachment only; no global detach/unmount operations."""
    def __init__(self, image_fd: int, destination: Path):
        self.fd, self.destination, self.loop, self.loop_fd = image_fd, destination, None, None
        self.mounted = False
        self.attached = False
        self.original_device = None

    def attach(self):
        require(os.geteuid() == 0, "PRIVILEGED_MOUNT_REQUIRED")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        require(fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) == seals, "IMAGE_SEAL_RED")
        require_private_namespace()
        m = self.destination.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022
                and not any(self.destination.iterdir()), "MOUNTPOINT_RED")
        self.original_device = m.st_dev
        control = os.open("/dev/loop-control", os.O_RDWR | os.O_CLOEXEC)
        try:
            number = fcntl.ioctl(control, 0x4C82)  # LOOP_CTL_GET_FREE
        finally:
            os.close(control)
        require(0 <= number < 1048576, "LOOP_IDENTITY_RED")
        self.loop = f"/dev/loop{number}"
        # No mknod, module loading or changes to somebody else's loop device.
        self.loop_fd = os.open(self.loop, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        device = os.fstat(self.loop_fd)
        require(stat.S_ISBLK(device.st_mode) and device.st_rdev == os.makedev(7,number),
                "LOOP_IDENTITY_RED")
        info = bytearray(232)
        struct.pack_into("I", info, 52, 1 | 4)  # READ_ONLY | AUTOCLEAR
        # Atomic LOOP_CONFIGURE: no gap between attachment and AUTOCLEAR.
        config = struct.pack("II", self.fd, 0) + bytes(info) + bytes(64)
        fcntl.ioctl(self.loop_fd, 0x4C0A, config)
        self.attached = True
        self._check_loop()
        run(["/usr/bin/mount", "-t", "squashfs", "-o", "ro,nodev,nosuid",
             f"/proc/self/fd/{self.loop_fd}", str(self.destination)], pass_fds=(self.loop_fd,))
        self.mounted = True
        self._check_loop()
        info = run(["/usr/bin/findmnt", "--noheadings", "--raw", "--output", "FSTYPE,OPTIONS",
                    "--mountpoint", str(self.destination)])
        require(info.startswith("squashfs ") and "ro" in info.split()[1].split(","), "MOUNT_READONLY_RED")
        return self

    def _check_loop(self):
        info = fcntl.ioctl(self.loop_fd, 0x4C05, bytes(232))
        dev, ino = struct.unpack_from("QQ", info)
        flags = struct.unpack_from("I", info, 52)[0]
        backing = os.fstat(self.fd)
        require((dev, ino) == (backing.st_dev, backing.st_ino) and flags & 5 == 5,
                "LOOP_IDENTITY_RED")

    def close(self):
        # Retain proof until detach. Do not touch a device whose identity changed.
        if self.loop_fd is not None and self.attached:
            self._check_loop()
            current = self.destination.stat().st_dev
            expected = os.fstat(self.loop_fd).st_rdev
            require(current in (self.original_device, expected), "MOUNT_IDENTITY_RED")
            # Also handles a mount command whose successful output was lost.
            if current == expected:
                run(["/usr/bin/umount", str(self.destination)])
                self.mounted = False
        if self.loop_fd is not None:
            os.close(self.loop_fd)  # AUTOCLEAR releases only our attachment.
            self.loop_fd = None


def bind_readonly(source: Path, destination: Path):
    """Private-namespace bind, never a writable host-directory exposure."""
    require_private_namespace()
    require(not source.is_symlink() and not destination.is_symlink(), "BIND_OBJECT_RED")
    require(source.is_dir()==destination.is_dir(), "BIND_OBJECT_RED")
    run(["/usr/bin/mount","--bind",str(source),str(destination)])
    run(["/usr/bin/mount","-o","remount,bind,ro,nodev,nosuid,noexec",str(destination)])


def private_permit(mounted: MountedImage, payload: bytes):
    """Single private readonly permit, no mutable shared publication file.

    The coordinator already consumed its durable execution record before this
    payload was returned. This namespace is private and the process is not
    dumpable; creating a permit here does not create another execution ticket.
    The App's existing nlink=1/root metadata checks remain unchanged.
    """
    require_private_namespace()
    require(os.geteuid()==0 and mounted.mounted and type(payload) is bytes
            and 0 < len(payload) <= 16384, "PERMIT_BOUNDARY_RED")
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(3,0,0,0,0)==0,"PROCESS_HANDLE_PROTECTION_RED")
    value=json.loads(payload)
    require(type(value) is dict and json.dumps(value,sort_keys=True,separators=(",",":")).encode()==payload,
            "PERMIT_FORMAT_RED")
    destination=mounted.destination/"etc/tu1nz/s8-atomic-admission-r1"
    m=destination.lstat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid==0 and not m.st_mode&0o022
            and m.st_dev==mounted.destination.stat().st_dev,"PERMIT_MOUNTPOINT_RED")
    run(["/usr/bin/mount","-t","tmpfs","-o","rw,size=64k,mode=0755,nosuid,nodev,noexec",
         "s8-private-permit",str(destination)])
    fd=os.open(destination/"permit.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    try:
        os.fchmod(fd,0o644)
        remaining=payload
        while remaining:
            count=os.write(fd,remaining)
            require(count>0,"PERMIT_WRITE_RED");remaining=remaining[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    # Remount only after the sole writable descriptor is closed. No handle,
    # shared path or writable mount escapes into the unprivileged poller.
    run(["/usr/bin/mount","-o","remount,ro,nosuid,nodev,noexec",str(destination)])
    properties=run(["/usr/bin/findmnt","--noheadings","--raw","--output","FSTYPE,OPTIONS",
                    "--mountpoint",str(destination)])
    require(properties.startswith("tmpfs ") and "ro" in properties.split()[1].split(","),
            "PERMIT_READONLY_RED")


def private_credentials(mounted: MountedImage, source: Path, *, uid: int, gid: int):
    """Copy only PID-1's fixed credentials into a private readonly RAM mount.

    systemd 255 presents uid-owned 0400 credentials. The existing Application
    contract accepts a uid-owned 0600 private file. This is a newly constructed
    private object with prescribed metadata, never chmod/chown of the original
    credential or an expansion of the Application's secret reader policy.
    No secret hash, bytes, path contents or token-bearing error is emitted.
    """
    require_private_namespace()
    unit="tu1nz-adult-public-s8-telegram.service"
    expected=Path("/run/credentials")/unit
    require(os.geteuid()==0 and mounted.mounted and uid>0 and gid>0
            and source==expected and os.environ.get("CREDENTIALS_DIRECTORY")==str(source),
            "CREDENTIAL_INTERFACE_RED")
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(3,0,0,0,0)==0,"PROCESS_HANDLE_PROTECTION_RED")
    before=source.lstat()
    require(stat.S_ISDIR(before.st_mode) and before.st_uid==uid and before.st_gid==gid
            and stat.S_IMODE(before.st_mode)==0o500 and not source.is_symlink(),
            "CREDENTIAL_METADATA_RED")
    destination=mounted.destination/str(expected).lstrip("/")
    target=destination.lstat()
    require(stat.S_ISDIR(target.st_mode) and target.st_uid==0 and not target.st_mode&0o022
            and target.st_dev==mounted.destination.stat().st_dev,"CREDENTIAL_MOUNTPOINT_RED")
    names={"s8_telegram_token":256,"s8_database_dsn":4096}
    require(set(os.listdir(source))==set(names),"CREDENTIAL_SET_RED")
    run(["/usr/bin/mount","-t","tmpfs","-o","rw,size=64k,mode=0755,nosuid,nodev,noexec",
         "s8-private-credentials",str(destination)])
    for name,limit in names.items():
        origin=source/name
        m=origin.lstat()
        require(stat.S_ISREG(m.st_mode) and (m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode),m.st_nlink)
                ==(uid,gid,0o400,1) and 0<m.st_size<=limit,"CREDENTIAL_METADATA_RED")
        fd=os.open(origin,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            mark=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mode,st.st_uid,st.st_gid,st.st_mtime_ns,st.st_ctime_ns)
            require(mark(os.fstat(fd))==mark(m),"CREDENTIAL_INPUT_DRIFT")
            payload=os.read(fd,limit+1)
            require(len(payload)==m.st_size and mark(os.fstat(fd))==mark(m)==mark(origin.lstat()),
                    "CREDENTIAL_INPUT_DRIFT")
        finally:
            os.close(fd)
        output=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            remaining=payload
            while remaining:
                count=os.write(output,remaining)
                require(count>0,"CREDENTIAL_COPY_RED");remaining=remaining[count:]
            os.fchown(output,uid,gid);os.fchmod(output,0o600);os.fsync(output)
        finally:
            os.close(output)
    require((source.stat().st_dev,source.stat().st_ino)==(before.st_dev,before.st_ino),"CREDENTIAL_INPUT_DRIFT")
    run(["/usr/bin/mount","-o","remount,ro,nosuid,nodev,noexec",str(destination)])
    properties=run(["/usr/bin/findmnt","--noheadings","--raw","--output","FSTYPE,OPTIONS",
                    "--mountpoint",str(destination)])
    require(properties.startswith("tmpfs ") and "ro" in properties.split()[1].split(","),
            "CREDENTIAL_READONLY_RED")


def enter_capsule(mounted: MountedImage, *, uid: int, gid: int, image_sha256: str,
                  argv: list[str], environment: dict[str,str]):
    """Final irreversible exec boundary, only AFTER durable execution consume.

    The canonical caller supplies fixed read-only mounts first. No host Python,
    library or package paths survive chroot. This function never starts a shell,
    uses a normal-claim fallback, retries exec or writes a permission receipt.
    """
    require(mounted.mounted and uid>0 and gid>0 and uid!=os.geteuid(), "IDENTITY_RED")
    mounted._check_loop()
    require(re.fullmatch("[0-9a-f]{64}",image_sha256),"IMAGE_DIGEST_RED")
    require(argv[:5]==["/usr/bin/python3","-I","-B","-S","/control/tu1nz_s8_capsule_bootstrap.py"],
            "EXEC_ARGUMENTS_RED")
    require("--recovery-admission" in argv and "--configure-only" not in argv
            and "--health-only" not in argv and "--diagnostic-mode" not in argv,"EXEC_ARGUMENTS_RED")
    _drop_exec(mounted,uid=uid,gid=gid,image_sha256=image_sha256,argv=argv,environment=environment)


def _drop_exec(mounted, *, uid, gid, image_sha256, argv, environment):
    """Internal common privilege boundary, not a CLI or permission source.

    Production is reached only through enter_capsule's fixed argv checks. The
    isolated native harness uses this same boundary to test real permission/
    SQL code with provider-only stubs; it cannot mint a production permit.
    """
    require_private_namespace()
    require(mounted.mounted and os.geteuid()==0 and uid>0 and gid>0,"IDENTITY_RED")
    mounted._check_loop()
    # FD is sealed and intentionally retained for independent process attestation.
    os.set_inheritable(mounted.fd,True)
    env={key:environment[key] for key in ("INVOCATION_ID","CREDENTIALS_DIRECTORY","LANG") if key in environment}
    env.update(PATH="/usr/bin:/bin",TU1NZ_S8_SEALED_FD=str(mounted.fd),TU1NZ_S8_SEALED_SHA256=image_sha256)
    os.chroot(mounted.destination)
    os.chdir("/application")
    os.setgroups([]);os.setgid(gid);os.setuid(uid)
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(38,1,0,0,0)==0,"NO_NEW_PRIVILEGES_RED")
    # setuid normally clears capabilities. Check, do not assume a securebits state.
    fields=dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(fields[key].strip(),16)==0 for key in ("CapInh","CapPrm","CapEff","CapAmb")),
            "CAPABILITY_DROP_RED")
    # No inherited writable journal, source or device handles in the poller.
    maximum=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    require(3 <= mounted.fd < maximum <= 1048576,"FD_BOUNDARY_RED")
    os.closerange(3,mounted.fd)
    os.closerange(mounted.fd+1,maximum)
    os.execve(argv[0],argv,env)
