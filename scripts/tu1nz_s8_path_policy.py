"""Exact observed parent ACL profiles, never a general ACL/group exemption.

Only traversal of historical stock is allowed through the repository parent.
Its default ACL is NOT an admissible creation policy. Endpoints, newly made
stock and all unspecified ancestors still use the original strict predicate.
Path witnesses observe exchanges, including an exchange followed by restore;
they do not infer historical identity from a current inode or content hash.
"""
import ctypes
import os
from pathlib import Path
import stat
import struct

from tu1nz_s8_execution_contract import protected, require

ACCESS = "system.posix_acl_access"
DEFAULT = "system.posix_acl_default"
UNDEFINED = 0xffffffff

# tag, permission bits, qualifier. POSIX ACL entries are kernel-canonical.
CONFIG_ACCESS = ((1, 7, UNDEFINED), (2, 1, 994), (2, 1, 995),
                 (2, 1, 996), (4, 5, UNDEFINED), (16, 5, UNDEFINED), (32, 0, UNDEFINED))
REPOSITORY_ACCESS = ((1, 5, UNDEFINED), (2, 1, 995), (2, 1, 996),
                     (2, 7, 1001), (4, 7, UNDEFINED), (8, 7, 1001),
                     (16, 5, UNDEFINED), (32, 0, UNDEFINED))
REPOSITORY_DEFAULT = ((1, 7, UNDEFINED), (2, 7, 1001), (4, 7, UNDEFINED),
                      (8, 5, 1001), (16, 7, UNDEFINED), (32, 0, UNDEFINED))
PROFILES = {
    Path("/etc/tu1nz"): (0o750, CONFIG_ACCESS, None),
    Path("/opt/tu1nz_repos"): (0o2550, REPOSITORY_ACCESS, REPOSITORY_DEFAULT),
}


def acl_bytes(entries):
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def no_nonowner_write(entries):
    masks = [perm for tag, perm, _ in entries if tag == 16]
    require(len(masks) == 1, "PARENT_ACL_MASK_RED")
    for tag, perm, _ in entries:
        if tag in {2, 4, 8, 32}:
            effective = perm & masks[0] if tag in {2, 4, 8} else perm
            require(not effective & 2, "PARENT_EFFECTIVE_WRITE_RED")


def _parent_metadata(path, *, creation=False):
    """No metadata is normalized; unknown xattrs/defaults remain RED."""
    path = Path(path)
    require(path.is_absolute(), "PARENT_PATH_RED")
    if path not in PROFILES:
        return protected(path, directory=True)
    mode, access, default = PROFILES[path]
    require(not creation or default is None, "PARENT_DEFAULT_CREATION_FORBIDDEN")
    m = path.lstat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and m.st_gid == 1001
            and stat.S_IMODE(m.st_mode) == mode, "PARENT_METADATA_RED")
    expected = {ACCESS: acl_bytes(access)}
    if default is not None:
        expected[DEFAULT] = acl_bytes(default)
    require(set(os.listxattr(path, follow_symlinks=False)) == set(expected), "PARENT_XATTR_RED")
    for name, value in expected.items():
        require(os.getxattr(path, name, follow_symlinks=False) == value, "PARENT_ACL_PROFILE_RED")
    no_nonowner_write(access)
    return m


def parent_metadata(path, *, creation=False):
    """Validate both DAC/ACL metadata and the observed inode's flag policy.

    EXTENTS/INDEX describe storage, APPEND/IMMUTABLE restrict operations. No
    encryption, verity, inherited special policy or unknown flag is adopted.
    This reads existing ancestors; it never changes their protections.
    """
    from tu1nz_s8_journal_fence import inode_flags
    path = Path(path)
    before = _parent_metadata(path, creation=creation)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(identity(before) == identity(os.fstat(fd)), "PARENT_IDENTITY_RED")
        require(not inode_flags(fd) & ~(0x80000 | 0x1000 | 0x20 | 0x10), "PARENT_FLAGS_RED")
        require(identity(before) == identity(os.fstat(fd)) ==
                identity(_parent_metadata(path, creation=creation)), "PARENT_IDENTITY_RED")
        return before
    finally:
        os.close(fd)


def identity(m):
    # Child creation changes parent times/size, not this protection identity.
    return (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid)


def dropin_snapshot(root):
    """Current empty-object admission evidence, not historical provenance.

    Emptiness is only one prerequisite. All durable slot markers are checked
    separately by the provisioner; no absence/emptiness result is a grant.
    """
    from tu1nz_s8_execution_contract import fingerprint
    from tu1nz_s8_journal_fence import inode_flags
    with PathChain(root.parent, leaf=root.name) as parent:
        if not os.path.lexists(root):
            return dict(state="ABSENT")
        with PathChain(root) as chain:
            m = protected(root, directory=True, mode=0o755)
            require(identity(m) == identity(os.fstat(chain.fd)) and not os.listdir(chain.fd),
                    "DROPIN_NOT_EMPTY_OR_REBOUND")
            flags = inode_flags(chain.fd)
            # Extents is a storage-format flag, not authority. No protected,
            # encrypted, verity, inherited or otherwise unknown flag is adopted.
            require(flags in (0, 0x80000), "DROPIN_FLAGS_RED")
            require(fingerprint(m) == fingerprint(root.lstat()) == fingerprint(os.fstat(chain.fd)),
                    "DROPIN_DRIFT")
            return dict(state="EXISTING_EMPTY", origin="UNKNOWN", fingerprint=list(fingerprint(m)),
                        inode_flags=flags, owner=0, group=0, mode="0755", acl="NONE", entries=[])


class PathChain:
    """FD-anchored, continuously watched ancestry for one synchronous use.

    Permissions/ACLs are validated at every check; inode and event evidence
    must BOTH agree. No background watcher or interrupted lifetime is trusted.
    A selected leaf may be watched read-only; unrelated siblings are ignored.
    """
    def __init__(self, directory, *, creation=False, leaf=None):
        directory = Path(directory)
        require(directory.is_absolute() and ".." not in directory.parts, "PARENT_PATH_RED")
        self.descriptors, self.nodes = [], []
        self.failed = False
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        self.events = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        require(self.events >= 0, "PARENT_WATCH_REQUIRED")
        self.owner = os.getpid()
        try:
            paths = [*reversed(directory.parents), directory]
            for index, path in enumerate(paths):
                fd = os.open(path.name if index else "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=self.descriptors[-1] if index else None)
                self.descriptors.append(fd)
                wd = libc.inotify_add_watch(self.events, os.fsencode("/proc/self/fd/"+str(fd)), 0x00000fce)
                require(wd >= 0 and wd not in {row[0] for row in self.nodes}, "PARENT_WATCH_REQUIRED")
                target = paths[index+1].name if index+1 < len(paths) else leaf
                m = parent_metadata(path, creation=creation and index+1 == len(paths))
                require(identity(m) == identity(os.fstat(fd)), "PARENT_IDENTITY_RED")
                self.nodes.append((wd, path, fd, identity(m), os.fsencode(target) if target else None,
                                   creation and index+1 == len(paths)))
                self.check()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.descriptors[-1]

    def check(self):
        require(not self.failed and self.events is not None and self.owner == os.getpid(), "PARENT_WITNESS_LOST")
        try:
            for _, path, fd, expected, _, creation in self.nodes:
                require(identity(parent_metadata(path, creation=creation)) == identity(os.fstat(fd)) == expected,
                        "PARENT_IDENTITY_RED")
            by_watch = {row[0]: row[4] for row in self.nodes}
            while True:
                try: payload = os.read(self.events, 65536)
                except BlockingIOError: break
                offset = 0
                while offset < len(payload):
                    require(len(payload)-offset >= 16, "PARENT_EVENT_RED")
                    wd, mask, _, size = struct.unpack_from("iIII", payload, offset)
                    offset += 16
                    require(offset+size <= len(payload) and wd in by_watch
                            and not mask & (0x4000 | 0x8000), "PARENT_EVENT_RED")
                    name = payload[offset:offset+size].split(b"\0", 1)[0]
                    offset += size
                    require(bool(name) and name != by_watch[wd], "PARENT_CHANGED_NO_RETRY")
        except BaseException:
            self.failed = True
            raise

    def close(self):
        if self.events is not None:
            os.close(self.events)
            self.events = None
        while self.descriptors:
            os.close(self.descriptors.pop())

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        try:
            if kind is None: self.check()
        finally:
            self.close()
