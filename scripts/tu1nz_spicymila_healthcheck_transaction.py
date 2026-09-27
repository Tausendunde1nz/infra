#!/usr/bin/env python3
"""Scoped, operator-gated spicymila healthcheck recreation. No build or pull."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import urllib.request

SOURCE = Path('/opt/spicymila_bot/docker-compose.yml')
NAME = 'spicymila_bot'
OLD = 'http://127.0.0.1:8090/health'
NEW = 'http://127.0.0.1:8080/health'

class Refuse(RuntimeError):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(ok, reason):
    if not ok:
        raise Refuse(reason)

def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid()
                and stat.S_IMODE(s.st_mode) == 0o600, 'private-file metadata drift')
        return f.read()

def normalized(container, candidate=False):
    result = {k: copy.deepcopy(container[k]) for k in ('Config', 'HostConfig', 'Mounts', 'Image')}
    config = result['Config']
    if config.get('Hostname') == container['Id'][:12]:
        config['Hostname'] = '<docker-generated>'
    for key in ('com.docker.compose.config-hash', 'com.docker.compose.replace'):
        config.get('Labels', {}).pop(key, None)
    if candidate:
        require(config['Healthcheck']['Test'] == ['CMD', 'curl', '-fsS', NEW], 'candidate command drift')
        config['Healthcheck']['Test'][-1] = OLD
    config['Env'] = sorted(config.get('Env', []))
    result['networks'] = {name: {'NetworkID': value['NetworkID'], 'Aliases': sorted(value.get('Aliases') or [])}
                          for name, value in container['NetworkSettings']['Networks'].items()}
    result['published_ports'] = container['NetworkSettings']['Ports']
    return result

def require_compose_network_coverage(resolved, baseline):
    service_networks = resolved['services'][NAME].get('networks', {})
    declared = set()
    for key in service_networks:
        network = resolved.get('networks', {}).get(key, {})
        require(bool(network.get('name')), 'unresolved Compose network name')
        declared.add(network['name'])
    actual = set(baseline['NetworkSettings']['Networks'])
    require(declared == actual, 'out-of-Compose network attachment; recreation blocked')

class Runtime:
    def __init__(self, backup, manifest_sha):
        self.backup = Path(backup)
        metadata = self.backup.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and not self.backup.is_symlink()
                and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
                'private backup directory required')
        raw = read_private(self.backup / 'activation-manifest.json')
        require(sha(raw) == manifest_sha, 'manifest checksum drift')
        self.manifest = json.loads(raw)
        require(self.manifest['source'] == str(SOURCE), 'unexpected source')
        for name, digest in self.manifest['sha256'].items():
            require(Path(name).name == name and sha(read_private(self.backup / name)) == digest,
                    'backup checksum drift')
        self.original = read_private(self.backup / 'compose.original.yml')
        self.candidate = read_private(self.backup / 'compose.candidate.yml')
        require(self.original.count(OLD.encode()) == 1 and
                self.candidate == self.original.replace(OLD.encode(), NEW.encode(), 1), 'nonminimal diff')
        self.baseline = json.loads(read_private(self.backup / 'container.inspect.json'))[0]
        self.others = json.loads(read_private(self.backup / 'other-containers.json'))
        self.compose = ['docker', 'compose', '--project-directory', str(SOURCE.parent),
                        '-p', NAME, '-f', str(SOURCE)]

    def run(self, args, timeout=60):
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        require(p.returncode == 0, 'external command failed; output withheld')
        return p.stdout

    def inspect(self):
        return json.loads(self.run(['docker', 'inspect', NAME]))[0]

    def event(self, name, value):
        # Immutable, private event files, never arbitrary stdout/stderr or secrets.
        path = self.backup / (name + '-' + str(time.time_ns()) + '.json')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

    def metadata(self):
        s = SOURCE.lstat()
        require(stat.S_ISREG(s.st_mode) and not SOURCE.is_symlink(), 'source type drift')
        return {'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
                'acl': self.run(['getfacl', '-cpn', str(SOURCE)]).decode()}

    def check_shared(self):
        ids = self.run(['docker', 'ps', '-aq']).decode().split()
        all_containers = json.loads(self.run(['docker', 'inspect', *ids]))
        other = {d['Name']: {'id': d['Id'], 'image': d['Image'], 'started': d['State']['StartedAt'],
                 'restarts': d['RestartCount'], 'ports': d['HostConfig']['PortBindings']}
                 for d in all_containers if d['Name'] != '/' + NAME}
        require(other == self.others, 'other-container drift')
        protection = json.loads(read_private(self.backup / 'host-protection.json'))
        listeners = sorted(' '.join(line.split()[i] for i in (0, 4, 5))
                           for line in self.run(['ss', '-H', '-lntu']).decode().splitlines())
        require(listeners == protection['listeners'], 'listener drift')
        for path, digest in protection['nginx_hashes'].items():
            require(sha(Path(path).read_bytes()) == digest, 'proxy configuration drift')
        for path, expected in protection['nginx_metadata_only'].items():
            st = Path(path).stat()
            actual = {'inode': st.st_ino, 'size': st.st_size, 'mtime_ns': st.st_mtime_ns,
                      'uid': st.st_uid, 'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode)}
            require(actual == expected, 'protected proxy metadata drift')
        for route, expected in protection['proxy_routes'].items():
            require(route in ('/spicy/health', '/spicymila/health'), 'unexpected proxy route')
            data = self.run(['curl', '-sS', '--max-time', '5', '--resolve',
                            'api.mychatbuddy.dev:443:127.0.0.1', '-w', '\n%{http_code}',
                            'https://api.mychatbuddy.dev' + route])
            body, status = data.rsplit(b'\n', 1)
            require(status.decode() == expected['status'] and sha(body) == expected['body_sha256'],
                    'proxy health changed')
        for service in ('ssh', 'tailscaled', 'docker', 'nginx'):
            require(self.run(['systemctl', 'is-active', service]).strip() == b'active', 'service not active')
        with urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets', timeout=5) as f:
            targets = json.load(f)['data']['activeTargets']
        for job in ('node', 'cadvisor'):
            selected = [x for x in targets if x.get('labels', {}).get('job') == job]
            require(len(selected) == 1 and selected[0]['health'] == 'up', 'monitoring not up')

    def preflight(self):
        require(self.metadata() == {k: self.manifest[k] for k in ('uid', 'gid', 'mode', 'acl')},
                'source metadata drift')
        raw = SOURCE.read_bytes()
        require(raw in (self.original, self.candidate), 'source content drift')
        candidate = raw == self.candidate
        resolved = json.loads(self.run(self.compose + ['config', '--format', 'json']))
        wanted = json.loads(read_private(self.backup / ('compose.resolved.candidate.json' if candidate
                                                       else 'compose.resolved.original.json')))
        require(resolved == wanted, 'resolved Compose/environment drift')
        require_compose_network_coverage(resolved, self.baseline)
        d = self.inspect()
        require(normalized(d, candidate) == normalized(self.baseline), 'effective container configuration drift')
        require(d['State']['Running'] and d['RestartCount'] == 0, 'running/restart precondition failed')
        image = json.loads(self.run(['docker', 'image', 'inspect', d['Config']['Image']]))[0]
        require(image['Id'] == self.manifest['image_id'], 'image tag/digest drift')
        if not candidate:
            # A successful rollback produces a new id; only a recorded rollback allows that.
            allowed = {self.manifest['container_id']}
            for p in self.backup.glob('ROLLED_BACK-*.json'):
                allowed.add(json.loads(read_private(p))['container_id'])
            require(d['Id'] in allowed, 'original container identity drift')
        # Resolve env_file before hashing: config --hash alone omits that resolution in v2.40.3.
        resolved_file = self.backup / ('compose.resolved.candidate.json' if candidate else 'compose.resolved.original.json')
        expected_hash = self.run(['docker', 'compose', '--project-directory', str(SOURCE.parent),
                                 '-p', NAME, '-f', str(resolved_file), 'config', '--hash', NAME]).decode().split()[-1]
        require(d['Config']['Labels']['com.docker.compose.config-hash'] == expected_hash, 'resolved service hash drift')
        source_hash = self.run(['docker', 'exec', NAME, 'python', '-c',
            "import hashlib; print(hashlib.sha256(open('/app/main.py','rb').read()).hexdigest())"]).decode().strip()
        require(source_hash == '8e241fb2e1130489420642e350846958942dfd530e94d82b9b46e1dc98b60dc2', 'application source drift')
        for line in self.run(['docker', 'diff', NAME]).decode().splitlines():
            kind, path = line.split(' ', 1)
            harmless_file = kind == 'A' and path.startswith('/usr/local/lib/python3.11/') and '/__pycache__/' in path and path.endswith('.pyc')
            harmless_dir = kind == 'C' and path in ('/usr', '/usr/local', '/usr/local/lib', '/usr/local/lib/python3.11',
                 '/usr/local/lib/python3.11/__pycache__', '/usr/local/lib/python3.11/http', '/usr/local/lib/python3.11/http/__pycache__')
            require(harmless_file or harmless_dir, 'unexpected writable-layer state; recreation blocked')
        self.check_shared()
        return candidate

    def write(self, candidate):
        wanted_metadata = {k: self.manifest[k] for k in ('uid', 'gid', 'mode', 'acl')}
        require(self.metadata() == wanted_metadata, 'concurrent Compose metadata edit')
        expected = self.original if candidate else self.candidate
        target = self.candidate if candidate else self.original
        require(SOURCE.read_bytes() == expected, 'concurrent Compose edit')
        fd, name = tempfile.mkstemp(prefix='.healthcheck-', dir=SOURCE.parent)
        try:
            os.close(fd)
            shutil.copy2(SOURCE, name)
            with open(name, 'wb') as f:
                f.write(target)
                f.flush()
                os.fsync(f.fileno())
            s = os.stat(name)
            require((s.st_uid, s.st_gid) == (self.manifest['uid'], self.manifest['gid']), 'temporary ownership drift')
            require(SOURCE.read_bytes() == expected and self.metadata() == wanted_metadata, 'concurrent Compose edit')
            os.replace(name, SOURCE)
            directory = os.open(SOURCE.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
            require(self.metadata() == {k: self.manifest[k] for k in ('uid', 'gid', 'mode', 'acl')},
                    'installed metadata drift')
        finally:
            if os.path.exists(name): os.unlink(name)

    def recreate(self, candidate):
        expected = 'compose.resolved.candidate.json' if candidate else 'compose.resolved.original.json'
        require(json.loads(self.run(self.compose + ['config', '--format', 'json'])) ==
                json.loads(read_private(self.backup / expected)), 'pre-recreate resolved configuration drift')
        image = json.loads(self.run(['docker', 'image', 'inspect', self.baseline['Config']['Image']]))[0]
        require(image['Id'] == self.manifest['image_id'], 'pre-recreate image drift')
        self.run(self.compose + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never',
                                '--force-recreate', NAME], timeout=120)
        require(normalized(self.inspect(), candidate) == normalized(self.baseline), 'post-recreate configuration drift')

    def probe(self, candidate, expected_id=None):
        d = self.inspect()
        require(normalized(d, candidate) == normalized(self.baseline), 'configuration changed')
        require(d['State']['Running'] and d['RestartCount'] == 0, 'container stopped/restarted')
        if expected_id: require(d['Id'] == expected_id, 'container replaced during observation')
        self.run(['docker', 'exec', NAME, 'curl', '-fsS', '--max-time', '3', NEW], timeout=5)
        with urllib.request.urlopen(OLD, timeout=5) as f:
            require(f.status == 200 and f.read(64).strip() == b'ok', 'host health endpoint failed')
        return d

    def observe(self):
        deadline = time.monotonic() + 150
        identity = self.inspect()['Id']
        while True:
            d = self.inspect()
            require(d['Id'] == identity and d['State']['Running'] and d['RestartCount'] == 0, 'startup stopped/restarted')
            require(normalized(d, True) == normalized(self.baseline), 'startup configuration drift')
            if d['State'].get('Health', {}).get('Status') == 'healthy': break
            require(time.monotonic() < deadline, 'healthy deadline exceeded')
            time.sleep(5)
        start = time.monotonic()
        while True:
            d = self.probe(True, identity)
            require(d['State']['Health']['Status'] == 'healthy', 'health regressed')
            self.check_shared()
            if time.monotonic() - start >= 181:
                logs = d['State']['Health'].get('Log', [])
                require(len(logs) >= 3 and all(x['ExitCode'] == 0 for x in logs[-3:]), 'insufficient healthy cycles')
                return {'container_id': identity, 'stable_seconds': time.monotonic() - start}
            time.sleep(10)

    def rollback(self):
        require(self.metadata() == {k: self.manifest[k] for k in ('uid', 'gid', 'mode', 'acl')}, 'rollback metadata drift')
        current = self.inspect()
        original_config = normalized(current) == normalized(self.baseline)
        candidate_config = current['Config']['Healthcheck']['Test'] == ['CMD', 'curl', '-fsS', NEW] and normalized(current, True) == normalized(self.baseline)
        require(original_config or candidate_config, 'rollback refuses foreign container configuration')
        raw = SOURCE.read_bytes()
        require(raw in (self.original, self.candidate), 'rollback refuses foreign Compose content')
        if raw == self.candidate: self.write(False)
        d = self.inspect()
        if normalized(d) != normalized(self.baseline) or not d['State']['Running']:
            self.recreate(False)
        deadline = time.monotonic() + 30
        while True:
            try:
                d = self.probe(False)
                break
            except (Refuse, OSError):
                require(time.monotonic() < deadline, 'rollback endpoint did not recover')
                time.sleep(2)
        self.event('ROLLED_BACK', {'container_id': d['Id'], 'compose_sha256': sha(self.original)})
        try:
            self.check_shared()
        except Refuse:
            self.event('UNRELATED_DRIFT', {'bot_rollback_verified': True, 'overall_validation_passed': False})


def activate(runtime):
    candidate = runtime.preflight()
    runtime.event('STARTING', {'health_port_from': 8090, 'health_port_to': 8080})
    try:
        if not candidate:
            runtime.write(True)
            runtime.recreate(True)
        result = runtime.observe()
        runtime.event('ALREADY_APPLIED' if candidate else 'SUCCESS', result)
        return 'ALREADY_APPLIED' if candidate else 'APPLIED'
    except BaseException:
        try:
            runtime.rollback()
        except BaseException:
            runtime.event('ROLLBACK_FAILED', {'manual_recovery_required': True})
            raise Refuse('rollback failed; manual recovery required') from None
        raise Refuse('activation failed; original configuration restored') from None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backup', required=True)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--mode', choices=('check', 'apply', 'rollback'), default='check')
    p.add_argument('--operator-ready', action='store_true')
    a = p.parse_args()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    require(a.mode == 'check' or a.operator_ready, 'explicit operator readiness required')
    r = Runtime(a.backup, a.manifest_sha256)
    fd = os.open(r.backup / 'transaction.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.mode == 'check': print('CANDIDATE' if r.preflight() else 'ORIGINAL_READY')
        elif a.mode == 'apply': print(activate(r))
        else: r.rollback(); print('ROLLED_BACK')

if __name__ == '__main__':
    try: main()
    except Exception as e:
        print('STOP: ' + type(e).__name__ + '; no secret output')
        raise SystemExit(1)
