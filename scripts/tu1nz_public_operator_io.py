"""Bounded private framing, durable receipts and authenticated source loading.

Only standard-library code. No socket/SSH launch or Host mutation at import.
The caller supplies authenticated code bytes, not executable paths from a Host.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import select
import stat
import sys
import time
import types
from contextlib import contextmanager
import urllib.error
import urllib.parse
import urllib.request

MAX_FRAME = 4*1024*1024
CONTROL_PINS = {
    'entry': '538e157629414f717039de1f4b3d0b388fde16718df74dc54c16dde1ac3826c7',
    'guard': 'eb01c7d260f7ad83b7d3437fe78768549a091289ecff99cae68f05689c224b58'}
MODULES = {'io': 'tu1nz_public_operator_io', 'fs': 'tu1nz_public_operator_fs',
           'client': 'tu1nz_public_operator',
           'observe': 'tu1nz_public_operator_observe', 'probes': 'tu1nz_public_operator_probes',
           'runtime_guard': 'tu1nz_public_operator_runtime_guard',
           'host': 'tu1nz_public_operator_host', 'r3': 'tu1nz_public_bootstrap_r3',
           'owner': 'tu1nz_bound_owner_supervisor', 'entry': 'tu1nz_bound_lighting_entry',
           'guard': 'tu1nz_bound_writer_guard'}
ASSETS = {'runtime': '2884c2531e73480513d533844cab9ac1a906e13fd4fdb104ab1d49759f3e9b01',
          'dropin_s7': 'df605ffec37e59d1c3c535a93879e7e155447967c6cd97a2f83ca866f841c16b',
          'dropin_s8_landing': '1e84f8904b4ce292e8b002ad373b27ea5d6592ddaaca4c07c68e990452133213',
    'dropin_wms': 'ce23c6382e50b740fb22f5a085d15fb0f96cd7fc15afcc1deaf23e04aff8bcf3'}
PUBLIC_HOSTS = frozenset(('tu1nz.com', 'www.tu1nz.com', 'wantmeseen.com', 'www.wantmeseen.com',
                          'lighting.tu1nz.com'))


class Hold(RuntimeError):
    def __init__(self, code):
        if not re.fullmatch('PUBLIC_OPERATOR_[A-Z0-9_]{1,96}', code):
            code = 'PUBLIC_OPERATOR_ERROR_SCHEMA_RED'
        self.primary = 'PUBLIC_BOOTSTRAP_'+code
        super().__init__(code)


def require(value, code):
    if not value:
        raise Hold('PUBLIC_OPERATOR_'+code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            require(k not in value, 'DUPLICATE_KEY')
            value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('PUBLIC_OPERATOR_JSON_CONSTANT')))


def measured_http(endpoint, *, deadline, location):
    require(set(endpoint) == {'stage', 'location', 'url', 'method', 'host_header', 'status', 'body_sha256'}
            and endpoint['location'] == location, 'HTTP_EXPECTED_SCHEMA')
    u = urllib.parse.urlsplit(endpoint['url'])
    require(not u.username and not u.password and not u.query and not u.fragment and
            u.path in ('', '/', '/adult', '/adult/', '/health', '/adult/health', '/privacy', '/terms',
                       '/imprint', '/adult/privacy', '/adult/terms', '/adult/imprint'), 'HTTP_SCOPE')
    require(endpoint['method'] in ('GET', 'HEAD') and
            (u.path not in ('', '/', '/adult', '/adult/') or endpoint['method'] == 'HEAD'
             or u.hostname == 'lighting.tu1nz.com'), 'NO_ANALYTICS_OR_PROVIDER_TEST')
    if location == 'host':
        require(u.scheme == 'http' and u.hostname in ('127.0.0.1', 'localhost', '::1') and
                endpoint['host_header'] in PUBLIC_HOSTS | {None}, 'HOST_HTTP_LOOPBACK_ONLY')
    else:
        require(location == 'client' and u.scheme == 'https' and u.hostname in PUBLIC_HOSTS and
                u.port in (None, 443) and endpoint['host_header'] is None, 'CLIENT_HTTP_SCOPE')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise Hold('PUBLIC_OPERATOR_HTTP_REDIRECT_NOT_ADMITTED')
    request = urllib.request.Request(endpoint['url'], method=endpoint['method'],
        headers={'User-Agent': 'TU1NZ-bound-readonly-admission/1',
                 **({'Host': endpoint['host_header']} if endpoint['host_header'] else {})})
    require(deadline > time.monotonic(), 'HTTP_DEADLINE')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=min(2, deadline-time.monotonic()))
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024*1024+1)
        require(len(raw) <= 1024*1024 and time.monotonic() < deadline, 'HTTP_OUTPUT_OR_DEADLINE')
        measured = {'status': response.status, 'body_sha256': sha(raw), 'bytes': len(raw)}
    require(measured['status'] == endpoint['status'] and measured['body_sha256'] == endpoint['body_sha256'],
            'ACTUAL_HTTP_DIFFERENT_OR_UNKNOWN')
    return measured


def private_read(path, limit=MAX_FRAME):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.geteuid()
                and stat.S_IMODE(a.st_mode) == 0o600 and a.st_size <= limit, 'PRIVATE_INPUT')
        raw = os.pread(fd, a.st_size+1, 0); b = os.fstat(fd); c = os.lstat(path)
        require(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_mtime_ns, a.st_ctime_ns, a.st_size) ==
                (b.st_dev, b.st_ino, b.st_mtime_ns, b.st_ctime_ns, b.st_size) and
                (a.st_dev, a.st_ino) == (c.st_dev, c.st_ino), 'PRIVATE_INPUT_CHANGED')
        return raw
    finally:
        os.close(fd)


class Wire:
    def __init__(self, incoming, outgoing, *, deadline):
        self.incoming, self.outgoing, self.deadline = incoming, outgoing, deadline
        self.sequence = 0

    def _read(self, count):
        out = bytearray()
        while len(out) < count:
            remaining = self.deadline-time.monotonic()
            require(remaining > 0 and select.select([self.incoming], [], [], remaining)[0], 'WIRE_DEADLINE')
            chunk = os.read(self.incoming, count-len(out))
            require(chunk, 'WIRE_LOST_NO_RETRY')
            out.extend(chunk)
        return bytes(out)

    def receive(self):
        length = int.from_bytes(self._read(4), 'big')
        require(0 < length <= MAX_FRAME, 'FRAME_SIZE')
        return parse(self._read(length))

    def send(self, value):
        raw = canonical(value)
        require(0 < len(raw) <= MAX_FRAME, 'FRAME_SIZE')
        packet = memoryview(len(raw).to_bytes(4, 'big')+raw)
        while packet:
            remaining = self.deadline-time.monotonic()
            require(remaining > 0 and select.select([], [self.outgoing], [], remaining)[1], 'WIRE_DEADLINE')
            size = os.write(self.outgoing, packet)
            require(size > 0, 'WIRE_LOST_NO_RETRY')
            packet = packet[size:]


def exclusive(parent, name, raw):
    require('/' not in name and name not in ('.', '..') and len(raw) <= MAX_FRAME, 'RECORD_BOUND')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            size = os.write(fd, view); require(size > 0, 'SHORT_WRITE'); view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        require(os.read(fd, len(raw)+1) == raw, 'RECORD_READBACK')
    finally:
        os.close(fd)


class Source:
    """In-memory exact old components plus new reviewed operator modules.

    The old guard's unchanged function bodies are loaded without its historical
    filesystem import bootstrap. Its sole dependency is the exact pinned entry
    module. No historical/locked repository import, sys.path or HOME fallback.
    """
    def __init__(self, encoded, hashes):
        require(set(encoded) == set(hashes) == set(MODULES) | set(ASSETS), 'SOURCE_MEMBERS')
        self.bytes = {n: base64.b64decode(v, validate=True) for n, v in encoded.items()}
        require(sum(map(len, self.bytes.values())) <= 3*1024*1024 and
                all(sha(raw) == hashes[n] for n, raw in self.bytes.items()), 'SOURCE_HASH')
        require(all(hashes[k] == h for k, h in CONTROL_PINS.items()), 'UNCHANGED_CONTROL_COMPONENT')
        require(all(hashes[k] == h for k, h in ASSETS.items()), 'UNCHANGED_RUNTIME_COMPONENT')
        require(hashes['r3'] == '0b302ec29184cf036800452cfd55e347a1ffa78e160766a729d998285a8ee6ca',
                'UNCHANGED_ORDERING_COMPONENT')
        self.modules = {}

    def load(self, name):
        if name in self.modules:
            return self.modules[name]
        require(name in MODULES, 'MODULE_NAME')
        module = types.ModuleType('public_operator_bound_'+name)
        module.__file__ = '<authenticated-memory:'+name+'>'
        self.modules[name] = module
        sys.modules[module.__name__] = module  # dataclass resolves this exact module.
        sys.modules[MODULES[name]] = module
        if name == 'guard':
            entry = self.load('entry'); tree = ast.parse(self.bytes[name])
            nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
            module.__dict__['d'] = entry
            module.__dict__['WEB'] = str(entry.HOST_ROOT)
            module.__dict__['BACKUP'] = str(entry.HOST_STAGING_ROOT)
            module.__dict__['FIELDS'] = frozenset(('device', 'inode', 'uid', 'gid', 'mode', 'type',
                'nlink', 'size', 'mtime_ns', 'ctime_ns', 'attrs', 'flags'))
            code = compile(ast.Module(body=nodes, type_ignores=[]), module.__file__, 'exec')
        else:
            code = compile(self.bytes[name], module.__file__, 'exec')
        exec(code, module.__dict__)
        return module


class LinkedRecords:
    """Client write+fsync+readback precedes every confirmed Host record/effect.

    Server output is trusted only through the authenticated code/SSH session;
    a JSON file cannot be substituted for this live bidirectional exchange.
    """
    def __init__(self, wire, binding):
        self.wire, self.binding = wire, binding
        self.sequence = 0; self.previous = binding; self.host_fd = None; self.prior = []
        self.ceiling = wire.deadline
        self.return_confirmed = False; self.approval_bound = False

    @contextmanager
    def limit(self, deadline):
        prior = self.wire.deadline
        self.wire.deadline = min(prior, deadline)
        try:
            require(time.monotonic() < self.wire.deadline, 'LINKED_CUSTODY_DEADLINE')
            yield
            require(time.monotonic() < self.wire.deadline, 'LINKED_CUSTODY_DEADLINE')
        finally:
            self.wire.deadline = min(prior, self.ceiling)

    def cap(self, deadline):
        self.ceiling = min(self.ceiling, deadline)
        self.wire.deadline = min(self.wire.deadline, self.ceiling)

    def bounded(self, deadline):
        parent = self
        class Bound:
            def record(self, kind, value):
                with parent.limit(deadline): return parent.record(kind, value)
        return Bound()

    def record(self, kind, value):
        require(self.sequence < 512 and kind.replace('_', '').isalnum(), 'LINKED_RECORD_BOUND')
        self.sequence += 1
        payload = {'sequence': self.sequence, 'binding': self.binding, 'previous': self.previous,
                   'kind': kind, 'value': value}
        raw = canonical(payload); require(len(raw) <= 65536, 'LINKED_RECORD_SIZE')
        digest = sha(raw)
        self.wire.send({'type': 'durable_record', 'record': payload, 'sha256': digest})
        ack = self.wire.receive()
        expected = {'type': 'persisted', 'sequence': self.sequence, 'sha256': digest}
        held = ack == {**expected, 'control': 'HOLD_BEFORE_OWNER_EFFECT'} and kind == 'owner_object_intent'
        require(ack == expected or held,
                'CLIENT_CUSTODY_ACK_LOST')
        if self.host_fd is not None:
            exclusive(self.host_fd, str(self.sequence).zfill(3)+'-'+kind+'.json', raw)
        else:
            self.prior.append((str(self.sequence).zfill(3)+'-'+kind+'.json', raw))
        self.previous = digest
        # A durable, chain-preserving DENIAL cannot grant an effect. It is a
        # classified operator interruption BEFORE owner_transition can fchown;
        # no fake ACK/lost confirmation is repaired into another permission.
        if held: raise Hold('PUBLIC_OPERATOR_REQUESTED_OWNER_BOUNDARY_HOLD')
        return digest

    def attach(self, fd):
        require(self.host_fd is None, 'HOST_MIRROR_ALREADY_ATTACHED')
        self.host_fd = os.dup(fd)
        for name, raw in self.prior:
            exclusive(self.host_fd, name, raw)
        self.prior.clear()
        self.check()

    def check(self):
        self.wire.send({'type': 'custody_check', 'sequence': self.sequence, 'sha256': self.previous})
        require(self.wire.receive() == {'type': 'custody_current', 'sequence': self.sequence,
                                      'sha256': self.previous}, 'CUSTODY_LOST')

    def http(self, endpoint):
        if endpoint['location'] == 'host':
            measured = measured_http(endpoint, deadline=self.wire.deadline, location='host')
        else:
            self.wire.send({'type': 'http_read', 'endpoint': endpoint})
            measured = self.wire.receive()
            require(set(measured) == {'status', 'body_sha256', 'bytes'} and
                    measured['status'] == endpoint['status'] and
                    measured['body_sha256'] == endpoint['body_sha256'] and
                    type(measured['bytes']) is int and 0 <= measured['bytes'] <= 1024*1024,
                    'CLIENT_HTTP_MEASUREMENT_RED')
        return measured
