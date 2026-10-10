"""Synthetic decoder tests, not a substitute for the native capture proof."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_historical_objects as g


class DecoderInputs:
    def __init__(self, root):
        self.root = root
        self.rows = [(path,None) for path in root.rglob('*') if path.is_file()]
        self.leases = self
        self.fds = []
    def remaining(self): return 1
    def check(self): pass
    def has(self,name): return (self.root/name).is_file()
    def read(self,name): return (self.root/name).read_bytes()
    def input_descriptor(self,name):
        if not self.has(name): raise c.ContractError('S8_EXECUTION_HISTORICAL_READ_UNAVAILABLE')
        fd = os.open(self.root/name,os.O_RDONLY); self.fds.append(fd)
        return fd,os.fstat(fd).st_size
    def close(self):
        for fd in self.fds: os.close(fd)


def header(kind,size):
    first = (kind << 4) | (size & 15); size >>= 4
    raw = bytearray([first | (128 if size else 0)])
    while size:
        byte = size & 127; size >>= 7; raw.append(byte | (128 if size else 0))
    return bytes(raw)


def packed_fixture(root, representation):
    base = b'synthetic base'
    target = b'synthetic base changed'
    base_id = g.object_id(b'blob',base); target_id = g.object_id(b'blob',target)
    prefix = b'PACK'+struct.pack('>II',2,2)
    first = header(3,len(base))+zlib.compress(base)
    offset = len(prefix)+len(first)
    change = bytes([len(base),len(target),0x90,len(base),8])+b' changed'
    link = bytes([len(first)]) if representation == 6 else bytes.fromhex(base_id)
    second = header(representation,len(change))+link+zlib.compress(change)
    data = prefix+first+second
    checksum = hashlib.sha1(data).digest(); data += checksum
    names = sorted([(base_id,12,first),(target_id,offset,second)])
    fan = [sum(bytes.fromhex(oid)[0] <= i for oid,_,_ in names) for i in range(256)]
    index = b'\xfftOc'+struct.pack('>I256I',2,*fan)
    index += b''.join(bytes.fromhex(oid) for oid,_,_ in names)
    index += b''.join(struct.pack('>I',zlib.crc32(raw) & 0xffffffff) for _,_,raw in names)
    index += b''.join(struct.pack('>I',at) for _,at,_ in names)+checksum
    index += hashlib.sha1(index).digest()
    folder = root/'objects/pack'; folder.mkdir(parents=True)
    stem = folder/('pack-'+checksum.hex())
    stem.with_suffix('.pack').write_bytes(data); stem.with_suffix('.idx').write_bytes(index)
    return stem,base_id,target_id,base,target


class ObjectDecoderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='s8-synthetic-decoder-')
        self.root = Path(self.temp.name)
        self.inputs = DecoderInputs(self.root)
    def tearDown(self):
        self.inputs.close(); self.temp.cleanup()  # only newly created synthetic files
    def reload(self):
        self.inputs.close(); self.inputs = DecoderInputs(self.root)

    def test_loose_hash_header_and_stream_boundaries(self):
        value = b'synthetic payload'; oid = g.object_id(b'tree',value)
        path = self.root/'objects'/oid[:2]/oid[2:]; path.parent.mkdir(parents=True)
        raw = zlib.compress(b'tree '+str(len(value)).encode()+b'\0'+value)
        path.write_bytes(raw); self.reload()
        with g.ObjectStore(self.inputs) as store: self.assertEqual(store.read(oid),(b'tree',value))
        for bad in (raw+b'trailing',raw[:-1],zlib.compress(b'tree 999\0'+value),
                    zlib.compress(b'tree 17\0changed payload!!!')):
            path.write_bytes(bad)
            with self.subTest(), g.ObjectStore(self.inputs) as store, self.assertRaises(c.ContractError):
                store.read(oid)

    def test_pack_ofs_and_ref_delta_match_exact_object_identity(self):
        for representation in (6,7):
            with self.subTest(representation=representation):
                folder = self.root/str(representation); folder.mkdir()
                _,base_id,target_id,base,target = packed_fixture(folder,representation)
                inputs = DecoderInputs(folder)
                try:
                    with g.ObjectStore(inputs) as store:
                        self.assertEqual(store.read(base_id),(b'blob',base))
                        self.assertEqual(store.read(target_id),(b'blob',target))
                finally: inputs.close()

    def test_pack_and_index_corruption_or_missing_data_deny(self):
        stem,_,target,_,_ = packed_fixture(self.root,7); self.reload()
        pack = stem.with_suffix('.pack'); index = stem.with_suffix('.idx')
        saved_pack,saved_index = pack.read_bytes(),index.read_bytes()
        for bad in (b'bad',saved_index[:-1],saved_index[:-20]+b'x'*20):
            index.write_bytes(bad)
            with self.subTest(), self.assertRaises(c.ContractError): g.ObjectStore(self.inputs)
        index.write_bytes(saved_index)
        for bad in (b'bad',saved_pack[:-1],saved_pack[:-20]+b'x'*20):
            pack.write_bytes(bad)
            with self.subTest(), self.assertRaises(c.ContractError): g.ObjectStore(self.inputs)
        pack.write_bytes(saved_pack); pack.unlink()
        with self.assertRaisesRegex(c.ContractError,'READ_UNAVAILABLE'): g.ObjectStore(self.inputs)

    def test_idx_structure_and_crc_checked_not_only_checksum(self):
        stem,_,target,_,_ = packed_fixture(self.root,6); self.reload()
        path = stem.with_suffix('.idx'); saved = path.read_bytes()
        for position in (8,1032,1072,1080):
            raw = bytearray(saved); raw[position] ^= 1
            raw[-20:] = hashlib.sha1(raw[:-20]).digest(); path.write_bytes(raw)
            with self.subTest(position=position), self.assertRaises(c.ContractError):
                with g.ObjectStore(self.inputs) as store: store.read(target)
        path.write_bytes(saved)

    def test_delta_invalid_copy_insert_size_cycle_and_depth_deny(self):
        for raw in (b'\x03\x04\x00',b'\x03\x03\x90\x04',b'\x03\x03\x03ab',
                    b'\x04\x03\x03abc',b'\xff'*6):
            with self.subTest(raw=raw), self.assertRaises(c.ContractError):
                g.delta(b'abc',raw,lambda:None)
        with g.ObjectStore(self.inputs) as store:
            with self.assertRaises(c.ContractError): store.read('a'*40,51)
            store.active.add('b'*40)
            with self.assertRaises(c.ContractError): store.read('b'*40)

    def test_decompression_size_bomb_is_bounded(self):
        with self.assertRaisesRegex(c.ContractError,'OBJECT_BOUND'):
            raw = zlib.compress(b'x'*100000)
            g.inflate(raw,0,len(raw),10,lambda:None)

    def test_symbolic_detached_and_packed_head_no_ref_escape(self):
        oid = 'a'*40; head = self.root/'HEAD'
        for raw in ((oid+'\n').encode(),b'ref: refs/heads/main\n'):
            head.write_bytes(raw)
            (self.root/'packed-refs').write_bytes(('# pack-refs\n'+oid+' refs/heads/main\n').encode())
            self.assertEqual(g.resolve_head(self.inputs),oid)
        for value in ('../escape','refs/heads/../main','refs/heads/a.lock','refs/heads/a@{0}'):
            head.write_bytes(('ref: '+value+'\n').encode())
            with self.subTest(value=value), self.assertRaises(c.ContractError): g.resolve_head(self.inputs)
        head.write_bytes(b'ref: refs/heads/main\n')
        (self.root/'refs/heads').mkdir(parents=True)
        (self.root/'refs/heads/main').write_bytes(('b'*40+'\n').encode())
        self.assertEqual(g.resolve_head(self.inputs),'b'*40)  # normal loose-ref precedence

    def test_config_only_known_inert_fields_and_required_format(self):
        good = b'[core]\nrepositoryformatversion = 0\nbare = false\n[remote "origin"]\nurl = https://fixture.invalid/repo\n'
        path = self.root/'config'; path.write_bytes(good); g.config_safe(self.inputs)
        for raw in (good+b'[include]\npath = private\n',good+b'[core]\nbare = false\n',
                    good.replace(b'= 0',b'= 1'),b'[core]\nbare = false\n'):
            path.write_bytes(raw)
            with self.subTest(), self.assertRaises(c.ContractError): g.config_safe(self.inputs)


if __name__ == '__main__': unittest.main()
