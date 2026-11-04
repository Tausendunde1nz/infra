"""Finite read-only early exclusion check for the approved mainserver R4.

No CLI path arguments, enumeration, claims, file creation or service actions.
This observation is necessary preflight evidence, never an execution admission.
Import is inert. Protected use requires the separately hash-bound reader scope
and independent review. Historical readers/claims are not used by this code.
"""
import hashlib
import json
import os
import re
import resource
import signal
import stat
import sys

MACHINE = 'a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae'
TX = 'public-rights-20261014-1'
BOOT = '/etc/tu1nz/public-web-bootstrap-r3/20261014-1'
STAGING = '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1'
LIGHTING = '/opt/tu1nz_repos/lighting-halloween-r1/20261014-1'
RUNTIME_PARENT = '/opt/tu1nz_repos/public-web-runtime-r5'
RUNTIME = RUNTIME_PARENT+'/93555d8a141caf8ace33522f9340d30bfc47d2bb'
UNITS = ('tu1nz-adult-public-s7.service', 'tu1nz-adult-public-s8-landing.service',
         'tu1nz-adult-public-s10-wms.service')
TARGETS = (BOOT, STAGING, LIGHTING, LIGHTING+'/writer-preparation-r2', RUNTIME_PARENT, RUNTIME,
           '/usr/local/bin/tu1nz_public_web_isolate_r1.py') + tuple(
    '/etc/systemd/system/'+u+'.d/'+n for u in UNITS for n in
    ('zz-public-isolation-r1.conf', 'zzz-public-runtime-r5.conf', 'zzzz-tu1nz-bootstrap-r3.conf'))
MAX_OUTPUT = 65536


class Denied(Exception):
    pass


def require(value, code):
    if not value:
        raise Denied(code)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)


def metadata(s):
    return dict(device=s.st_dev, inode=s.st_ino, type=stat.S_IFMT(s.st_mode),
                mode=oct(stat.S_IMODE(s.st_mode)), uid=s.st_uid, gid=s.st_gid)


class FixedPaths:
    """Hold ancestors without following links; prove absence at the first gap.

    root_fd exists only for isolated local tests. main always supplies '/'.
    No directory listing or reads of target contents are supported.
    """
    def __init__(self, root_fd):
        self.fds = {'/': os.dup(root_fd)}
        self.observed = {}
        self.edges = []
        self.targets = []

    def close(self):
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()

    @staticmethod
    def parts(path):
        require(type(path) is str and path.startswith('/') and path != '/', 'INVALID_FIXED_PATH')
        parts = path[1:].split('/')
        require(all(p and p not in ('.', '..') for p in parts) and len(parts) <= 12,
                'INVALID_FIXED_COMPONENT')
        return parts

    def inspect(self, path):
        parts = self.parts(path)
        parent = '/'
        for index, name in enumerate(parts):
            fd = self.fds[parent]
            current = parent.rstrip('/')+'/'+name
            try:
                s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                self.targets.append((fd, name, None))
                return {'state': 'ABSENT', 'first_absent_component': current,
                        'held_parent': parent}
            self.observed[current] = metadata(s)
            if index == len(parts)-1:
                self.targets.append((fd, name, identity(s)))
                return {'state': 'PRESENT', **metadata(s)}
            require(stat.S_ISDIR(s.st_mode), 'NON_DIRECTORY_OR_SYMLINK_ANCESTOR')
            if current not in self.fds:
                flags = getattr(os, 'O_PATH', os.O_RDONLY)|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
                child = os.open(name, flags, dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == identity(s), 'ANCESTOR_CHANGED_DURING_OPEN')
                    require(len(self.fds) < 40, 'DESCRIPTOR_BOUND')
                except BaseException:
                    os.close(child)
                    raise
                self.fds[current] = child
                self.edges.append((fd, name, child, identity(s)))
            else:
                require(identity(os.fstat(self.fds[current])) == identity(s), 'ANCESTOR_REPLACED')
            parent = current
        raise Denied('UNREACHABLE_PATH_STATE')

    def read_identity(self, path, limit):
        row = self.inspect(path)
        require(row['state'] == 'PRESENT' and row['type'] == stat.S_IFREG, 'IDENTITY_NOT_REGULAR')
        parent, name = path.rsplit('/', 1)
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME,
                     dir_fd=self.fds[parent or '/'])
        try:
            before = os.fstat(fd)
            require(metadata(before) == {k: row[k] for k in metadata(before)}, 'IDENTITY_OPEN_CHANGED')
            raw = os.read(fd, limit+1)
            require(len(raw) <= limit and os.read(fd, 1) == b'', 'IDENTITY_SIZE')
            after = os.fstat(fd)
            require((identity(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (identity(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'IDENTITY_CHANGED')
            return raw
        finally:
            os.close(fd)

    def check(self):
        for parent, name, child, expected in self.edges:
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected ==
                    identity(os.fstat(child)), 'ANCESTOR_REPLACED_AT_END')
        for parent, name, expected in self.targets:
            try:
                current = identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError:
                current = None
            require(current == expected, 'TARGET_CHANGED_AT_END')


def main():
    require(len(sys.argv) == 1 and sys.platform == 'linux' and os.geteuid() == 0,
            'FIXED_LINUX_ROOT_ENTRY_REQUIRED')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024, 256*1024*1024))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Denied('WALL_TIME_BOUND')))
    signal.alarm(15)
    namespaces = {}
    for name in ('mnt', 'pid', 'user'):
        own = os.readlink('/proc/self/ns/'+name)
        require(own == os.readlink('/proc/1/ns/'+name), 'INITIAL_HOST_NAMESPACE_REQUIRED')
        namespaces[name] = own
    root = os.open('/', os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    paths = FixedPaths(root)
    os.close(root)
    try:
        machine = hashlib.sha256(paths.read_identity('/etc/machine-id', 128)).hexdigest()
        require(machine == MACHINE, 'WRONG_HOST')
        boot = paths.read_identity('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        require(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot),
                'BOOT_FORMAT')
        rows = {path: paths.inspect(path) for path in TARGETS}
        paths.check()
        report = {'schema': 'TU1NZ_MAIN_SERVER_R4_EARLY_CLAIM_READ_V1', 'transaction': TX,
                  'machine_sha256': machine, 'boot_id': boot, 'namespaces': namespaces,
                  'targets': rows, 'observed_ancestors': paths.observed,
                  'result': 'NECESSARY_ABSENCES_OBSERVED' if all(
                      r['state'] == 'ABSENT' for r in rows.values()) else 'REQUIRED_ABSENCE_NOT_MET',
                  'limits': 'METADATA_ONLY_POINT_OBSERVATION_NOT_WRITER_EXCLUSION_OR_EXECUTION_ADMISSION'}
        raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()+b'\n'
        require(len(raw) <= MAX_OUTPUT, 'OUTPUT_BOUND')
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    finally:
        paths.close()
        signal.alarm(0)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        code = str(error) if isinstance(error, Denied) else 'UNCONFIRMED_READ'
        require(re.fullmatch('[A-Z_]{1,64}', code), 'ERROR_FORMAT')
        print(json.dumps({'schema': 'TU1NZ_MAIN_SERVER_R4_EARLY_CLAIM_READ_V1',
                          'result': 'UNKNOWN', 'code': code}))
        raise SystemExit(1)
