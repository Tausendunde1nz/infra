"""Real production probe component in a NEW network-none synthetic PID1 guest.

This is NOT the full entry integration and never claims actual Host acceptance.
No private capture, application release, credential or network is supplied.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, '/source/scripts')
import tu1nz_public_operator_fs as fs
import tu1nz_public_operator_probes as probes
import tu1nz_public_operator_io as io


def main():
    assert os.geteuid() == 0 and Path('/.dockerenv').exists()
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert all(p.name == 'lo' or not int((p/'flags').read_text(), 16) & 1
               for p in Path('/sys/class/net').iterdir() if p.is_dir())
    for path in ('/source', '/control-source'):
        options = subprocess.check_output(['findmnt', '-n', '-o', 'VFS-OPTIONS', '-T', path]).decode().split(',')
        assert options[0] == 'ro'
    assert not Path('/opt/tu1nz_repos').exists()
    import pwd
    try:
        pwd.getpwnam('chatops')
    except KeyError:
        subprocess.run(['groupadd', '--gid', '1001', 'chatops'], check=True)
        subprocess.run(['useradd', '--uid', '1001', '--gid', '1001', '--no-create-home', 'chatops'], check=True)
    source_entry = Path('/control-source/managed/bin/tu1nz-lighting-halloween-deploy-r1').read_bytes()
    assert io.sha(source_entry) == io.CONTROL_PINS['entry']
    import types
    entry = types.ModuleType('probe_bound_entry'); entry.__file__ = '<bound-source>'
    exec(compile(source_entry, entry.__file__, 'exec'), entry.__dict__)
    paths = fs.Paths(entry, deadline=time.monotonic()+120)
    for path in ('/opt/tu1nz_repos', '/opt/tu1nz_repos/public-web-isolation-r1',
                 '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1'):
        paths.create_directory(path)
    dependencies = {}
    objects = set()
    python = Path('/usr/bin/python3').resolve()
    inputs = [python, *(p for p in Path('/usr/lib/python3.12').rglob('*')
                        if p.is_file() and not p.is_symlink() and p.suffix in ('.py', '.so'))]
    for path in inputs:
        raw = path.read_bytes(); destination = str(path)
        dependencies[destination] = {'source': str(path.resolve()), 'sha256': io.sha(raw)}
        if path == python or path.suffix == '.so':
            r = subprocess.run(['ldd', str(path)], capture_output=True, text=True, check=True)
            for line in r.stdout.splitlines():
                for word in line.split():
                    if word.startswith('/'):
                        objects.add(word)
    for name in objects:
        path = Path(name)
        dependencies[name] = {'source': str(path.resolve()), 'sha256': io.sha(path.read_bytes())}
    dependencies['/usr/bin/python3'] = {'source': str(python), 'sha256': io.sha(python.read_bytes())}
    class Channel:
        def __init__(self): self.records = []
        def record(self, kind, value):
            self.records.append({'kind': kind, 'value': value})
    channel = Channel()
    authority = SimpleNamespace(b={'source_release': {'probe_dependencies': dependencies,
                                                     'python_binary': str(python)}})
    source = SimpleNamespace(bytes={'runtime': Path('/source/scripts/tu1nz_public_web_isolate_r1.py').read_bytes()})
    assert io.sha(source.bytes['runtime']) == io.ASSETS['runtime']
    proof = probes.Probes(paths, source, authority, channel, deadline=time.monotonic()+120)
    digest = proof.run()
    print(json.dumps({'component': 'REAL_PRODUCTION_PROBE_CODE', 'profiles': len(proof.reports),
                      'proof_sha256': digest, 'records': channel.records, 'host_acceptance': False}, sort_keys=True))


if __name__ == '__main__': main()
