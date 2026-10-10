"""Bounded SHA-1 Git decoding inside the non-dumpable capture process.

No Git subprocess, configuration execution, network, index or worktree access.
Only held, leased inputs can be consulted. Unsupported representations deny
the capture, never trigger an external decoder or object fetch.
"""
import hashlib
import mmap
import os
import re
import struct
import zlib

import tu1nz_s8_execution_contract as c

OBJECT_BOUND = 4*1024*1024
PACK_BOUND = 256*1024*1024
INDEX_BOUND = 32*1024*1024
COUNT_BOUND = 100000
KINDS = {1:b'commit', 2:b'tree', 3:b'blob', 4:b'tag'}


def require(value, code='HISTORICAL_OBJECT_INVALID'):
    c.require(value, code)


def object_id(kind, payload):
    return hashlib.sha1(kind+b' '+str(len(payload)).encode()+b'\0'+payload).hexdigest()


def reference(name):
    require(name.startswith('refs/') and not any(x in name for x in ('..','@{','//','\\'))
            and not any(ord(x) <= 32 or x in '~^:?*[' for x in name)
            and not name.endswith(('/', '.', '.lock'))
            and all(x and not x.startswith('.') and not x.endswith('.lock') for x in name.split('/')),
            'HISTORICAL_REFERENCE_INVALID')
    return name


def resolve_head(witness):
    raw = witness.read('HEAD')
    require(raw.endswith(b'\n') and raw.count(b'\n') == 1, 'HISTORICAL_REFERENCE_INVALID')
    text = raw[:-1].decode('ascii')
    if c.hex_value(text,40): return text
    require(text.startswith('ref: '), 'HISTORICAL_REFERENCE_INVALID')
    name = reference(text[5:])
    if witness.has(name):
        value = witness.read(name)
        require(len(value) == 41 and value[-1:] == b'\n', 'HISTORICAL_REFERENCE_INVALID')
        result = value[:-1].decode('ascii')
    else:
        require(witness.has('packed-refs'), 'HISTORICAL_READ_UNAVAILABLE')
        found = {}
        for line in witness.read('packed-refs').splitlines():
            if line.startswith(b'#'): continue
            if line.startswith(b'^'):
                require(len(line) == 41 and c.hex_value(line[1:].decode('ascii'),40),
                        'HISTORICAL_REFERENCE_INVALID')
                continue
            oid, sep, ref = line.partition(b' ')
            key = reference(ref.decode('ascii'))
            require(sep and c.hex_value(oid.decode('ascii'),40) and key not in found,
                    'HISTORICAL_REFERENCE_INVALID')
            found[key] = oid.decode('ascii')
        require(name in found, 'HISTORICAL_READ_UNAVAILABLE')
        result = found[name]
    require(c.hex_value(result,40), 'HISTORICAL_REFERENCE_INVALID')
    witness.check()
    return result


def config_safe(witness):
    # Values never become commands. Strict ordinary grammar avoids interpreting
    # config includes/conditional includes, extensions, helpers or indirection.
    section = None
    seen = {}
    for raw in witness.read('config').decode('utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith(('#',';')): continue
        if line.startswith('['):
            require(re.fullmatch(r'\[(core|remote "[^"\x00-\x1f]+"|branch "[^"\x00-\x1f]+")\]',line),
                    'HISTORICAL_UNSAFE_CONFIG')
            section = line[1:-1]
            continue
        require(section is not None and '=' in line and '\x00' not in line and not line.endswith('\\'),
                'HISTORICAL_UNSAFE_CONFIG')
        key, value = (x.strip() for x in line.split('=',1))
        key = key.lower()
        ordinary = section == 'core' and key in {
            'repositoryformatversion','filemode','bare','logallrefupdates','ignorecase','precomposeunicode'}
        inert = (section.startswith('remote "') and key in {'url','fetch'}) or \
                (section.startswith('branch "') and key in {'remote','merge'})
        require((ordinary or inert) and (section,key) not in seen, 'HISTORICAL_UNSAFE_CONFIG')
        seen[section,key] = value.lower() if ordinary else value
    require(seen.get(('core','repositoryformatversion')) == '0' and
            seen.get(('core','bare')) == 'false', 'HISTORICAL_UNSAFE_CONFIG')
    witness.check()


def inflate(data, start, end, bound, check):
    decoder = zlib.decompressobj()
    output = bytearray()
    pos = start
    try:
        while pos < end and not decoder.eof:
            check()
            part = data[pos:min(pos+65536,end)]
            pos += len(part)
            output.extend(decoder.decompress(part,bound+1-len(output)))
            require(len(output) <= bound and not decoder.unconsumed_tail, 'HISTORICAL_OBJECT_BOUND')
        require(decoder.eof, 'HISTORICAL_OBJECT_INVALID')
    except zlib.error:
        raise c.ContractError('S8_EXECUTION_HISTORICAL_OBJECT_INVALID') from None
    return bytes(output), pos-len(decoder.unused_data)


def variable(raw, pos):
    value = 0
    for shift in range(0,35,7):
        require(pos < len(raw))
        byte = raw[pos]; pos += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            require(value <= OBJECT_BOUND, 'HISTORICAL_OBJECT_BOUND')
            return value,pos
    require(False, 'HISTORICAL_OBJECT_BOUND')


def delta(base, raw, check):
    length,pos = variable(raw,0)
    result,pos = variable(raw,pos)
    require(length == len(base))
    output = bytearray()
    while pos < len(raw):
        check()
        op = raw[pos]; pos += 1
        if op & 128:
            offset,size = 0,0
            for bit in range(7):
                if op & (1 << bit):
                    require(pos < len(raw))
                    if bit < 4: offset |= raw[pos] << (8*bit)
                    else: size |= raw[pos] << (8*(bit-4))
                    pos += 1
            size = size or 65536
            require(offset+size <= len(base) and len(output)+size <= result)
            output.extend(base[offset:offset+size])
        else:
            require(op and pos+op <= len(raw) and len(output)+op <= result)
            output.extend(raw[pos:pos+op]); pos += op
    require(len(output) == result)
    return bytes(output)


class ObjectStore:
    def __init__(self, witness):
        self.witness = witness
        self.mappings = []
        self.closed = False
        self.packs = []
        self.active = set()
        try:
            names = sorted(str(path.relative_to(witness.root)) for path,_ in witness.rows
                           if path.parent == witness.root/'objects/pack' and path.suffix == '.idx')
            require(len(names) <= 64, 'HISTORICAL_OBJECT_BOUND')
            for name in names:
                require(re.fullmatch(r'objects/pack/pack-[0-9a-f]{40}\.idx',name))
                self.packs.append(self._pack(name))
        except BaseException as error:
            c.close_preserving(error,self)
            raise

    def check(self):
        require(not self.closed and not getattr(self.witness,'failed',False), 'HISTORICAL_OBJECT_WITNESS_LOST')
        self.witness.leases.remaining()

    def _map(self, name, bound):
        fd,size = self.witness.input_descriptor(name)
        require(0 < size <= bound, 'HISTORICAL_OBJECT_BOUND')
        value = mmap.mmap(fd,0,access=mmap.ACCESS_READ)
        self.mappings.append(value)
        return value

    def _hash(self, data, end):
        value = hashlib.sha1()
        for pos in range(0,end,1024*1024):
            self.check(); value.update(data[pos:min(pos+1024*1024,end)])
        return value.digest()

    def _pack(self, name):
        index = self._map(name,INDEX_BOUND)
        pack = self._map(name[:-4]+'.pack',PACK_BOUND)
        require(len(index) >= 1072 and index[:8] == b'\xfftOc\0\0\0\2')
        require(self._hash(index,len(index)-20) == index[-20:])
        fan = struct.unpack('>256I',index[8:1032]); count = fan[-1]
        require(0 < count <= COUNT_BOUND and all(a <= b for a,b in zip(fan,fan[1:]))
                and len(index) >= 1032+28*count+40, 'HISTORICAL_OBJECT_BOUND')
        require(len(pack) >= 32 and pack[:4] == b'PACK' and
                struct.unpack('>II',pack[4:12]) in ((2,count),(3,count)))
        require(self._hash(pack,len(pack)-20) == pack[-20:] == index[-40:-20] and
                name[-44:-4] == pack[-20:].hex())
        extra = len(index)-(1032+28*count+40)
        require(extra >= 0 and extra % 8 == 0)
        large = extra//8
        table = {}; counts = [0]*256; used = set(); previous = b''
        for i in range(count):
            if i % 1024 == 0: self.check()
            oid = index[1032+20*i:1052+20*i]
            require(oid > previous); previous = oid; counts[oid[0]] += 1
            offset = struct.unpack_from('>I',index,1032+24*count+4*i)[0]
            if offset & 0x80000000:
                slot = offset & 0x7fffffff
                require(slot < large and slot not in used); used.add(slot)
                offset = struct.unpack_from('>Q',index,1032+28*count+8*slot)[0]
            require(12 <= offset < len(pack)-20 and offset not in table)
            crc = struct.unpack_from('>I',index,1032+20*count+4*i)[0]
            table[offset] = (oid.hex(),crc)
        require(len(used) == large)
        running = 0
        for i,n in enumerate(counts):
            running += n; require(running == fan[i])
        offsets = sorted(table)
        require(offsets[0] == 12)
        ends = dict(zip(offsets,offsets[1:]+[len(pack)-20]))
        return pack,table,ends,{oid:offset for offset,(oid,_) in table.items()}

    def read(self, oid, depth=0):
        self.check()
        require(c.hex_value(oid,40) and depth <= 50, 'HISTORICAL_OBJECT_BOUND')
        require(oid not in self.active)
        self.active.add(oid)
        try:
            name = 'objects/'+oid[:2]+'/'+oid[2:]
            if self.witness.has(name):
                fd,size = self.witness.input_descriptor(name)
                require(0 < size <= OBJECT_BOUND+65536, 'HISTORICAL_OBJECT_BOUND')
                raw = os.pread(fd,size,0)
                require(len(raw) == size, 'HISTORICAL_READ_UNAVAILABLE')
                decoded,end = inflate(raw,0,size,OBJECT_BOUND+128,self.check)
                header,sep,payload = decoded.partition(b'\0')
                kind,space,length = header.partition(b' ')
                require(end == size and sep and space and kind in KINDS.values()
                        and length.isdigit() and length == str(len(payload)).encode()
                        and len(payload) <= OBJECT_BOUND)
            else:
                hits = [(item,item[3][oid]) for item in self.packs if oid in item[3]]
                require(bool(hits), 'HISTORICAL_READ_UNAVAILABLE')
                kind,payload = self._entry(*hits[0],depth)
            require(object_id(kind,payload) == oid, 'HISTORICAL_CONTENT_RED')
            self.check()
            return kind,payload
        finally: self.active.remove(oid)

    def _entry(self, item, offset, depth):
        pack,table,ends,_ = item
        end = ends[offset]; pos = offset
        byte = pack[pos]; pos += 1
        kind = (byte >> 4) & 7; size = byte & 15; shift = 4
        while byte & 128:
            require(pos < end and shift <= 32, 'HISTORICAL_OBJECT_BOUND')
            byte = pack[pos]; pos += 1; size |= (byte & 127) << shift; shift += 7
        require(size <= OBJECT_BOUND and kind in (*KINDS,6,7), 'HISTORICAL_OBJECT_BOUND')
        base = None
        if kind == 6:
            require(pos < end); byte = pack[pos]; pos += 1; distance = byte & 127
            while byte & 128:
                require(pos < end and distance < PACK_BOUND)
                byte = pack[pos]; pos += 1; distance = ((distance+1) << 7)+(byte & 127)
            require(distance > 0 and offset-distance in table)
            base = table[offset-distance][0]
        elif kind == 7:
            require(pos+20 <= end); base = pack[pos:pos+20].hex(); pos += 20
            require(base in item[3])  # on-disk packs must be self-contained
        raw,actual_end = inflate(pack,pos,end,size,self.check)
        require(actual_end == end and len(raw) == size and
                zlib.crc32(pack[offset:end]) & 0xffffffff == table[offset][1])
        if base is not None:
            resolved,payload = self.read(base,depth+1)
            return resolved,delta(payload,raw,self.check)
        return KINDS[kind],raw

    def close(self):
        self.closed = True
        mappings,self.mappings = self.mappings,[]
        failure = c.ContractError('S8_EXECUTION_RESOURCE_CLEANUP_RED')
        c.close_preserving(failure,*reversed(mappings))
        if failure._s8_cleanup_errors: raise failure
    def __enter__(self): return self
    def __exit__(self,kind,value,trace):
        if value is not None: c.close_preserving(value,self)
        else: self.close()
        return False


def object_read(store, oid):
    return store.read(oid)
