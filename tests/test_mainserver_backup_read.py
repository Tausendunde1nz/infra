"""Finite backup boundary tests. Native cases use only an owned fixture root."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('backup',Path(__file__).resolve().parents[1]/'scripts/tu1nz_mainserver_backup_read.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def plan_fixture(objects=None):
    if objects is None:
        row=dict(metadata={k:0 for k in m.FIELDS if k!='attrs'},sha256=None)
        row['metadata'].update(type=stat.S_IFDIR,attrs={})
        objects={'.':copy.deepcopy(row),**{f'file-{n}.txt':copy.deepcopy(row) for n in range(87)}}
    plan=dict(host=m.MACHINE,root=m.LIGHTING,objects=88,changed_objects=84,existing_root_objects_unchanged=4,
              capture=dict(objects=objects,second_pass=copy.deepcopy(objects)))
    raw=m.canonical(plan)
    paths={m.LIGHTING if n=='.' else m.LIGHTING+'/'+n for n in objects}
    scope=dict(schema='TU1NZ_REV4_FILE_BACKUP_SCOPE_V1',transaction=m.TX,host_id=109772243,machine_sha256=m.MACHINE,
               contract_sha256=m.DECISION,approval_sha256=m.APPROVAL,owner_plan_base64=base64.b64encode(raw).decode(),
               files=sorted(paths|set(m.UNIT_FILES)|set(m.CONFIGS)|set(m.DYNAMIC)),
               max_file_bytes=m.MAX_FILE,max_total_bytes=m.MAX_TOTAL,capture_seconds=300)
    return scope,m.sha(raw)


class Selection(unittest.TestCase):
    def test_exact_compiled_host_contract_and_complete_88_object_plan(self):
        scope,pin=plan_fixture()
        with patch.object(m,'PLAN',pin):self.assertEqual(len(m.bound_selection(scope)),88)
        for key,value in (('host_id',173954685),('transaction','new-slot'),('contract_sha256','0'*64),
                          ('approval_sha256','0'*64),('capture_seconds',600),('max_total_bytes',m.MAX_TOTAL+1)):
            with patch.object(m,'PLAN',pin),self.subTest(key=key),self.assertRaises(m.Denied):
                m.bound_selection({**scope,key:value})
    def test_cannot_extend_omit_or_duplicate_read_set(self):
        scope,pin=plan_fixture()
        for paths in (scope['files'][:-1],scope['files']+['/etc/shadow'],scope['files']+scope['files'][:1]):
            with patch.object(m,'PLAN',pin),self.assertRaises(m.Denied):m.bound_selection({**scope,'files':paths})
    def test_owner_plan_bytes_cannot_be_rebound_by_scope(self):
        scope,_=plan_fixture()
        with self.assertRaises(m.Denied):m.bound_selection(scope)
    def test_plan_path_escape_is_not_an_authorized_file(self):
        scope,_=plan_fixture();plan=json.loads(base64.b64decode(scope['owner_plan_base64']))
        plan['capture']['objects']['../escape']=plan['capture']['objects'].pop('file-0.txt')
        plan['capture']['second_pass']=copy.deepcopy(plan['capture']['objects'])
        raw=m.canonical(plan);scope['owner_plan_base64']=base64.b64encode(raw).decode()
        with patch.object(m,'PLAN',m.sha(raw)),self.assertRaises(m.Denied):m.bound_selection(scope)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'native Linux FD/ioctl/read-only fixture')
class NativeCapture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.capture=None;self.patches=[]
        self.rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        def write(path,raw,uid=0,gid=0,mode=0o644):
            p=self.root/path.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            p.write_bytes(raw);os.chown(p,uid,gid);os.chmod(p,mode);return p
        units={}
        for path in m.UNIT_FILES:units[path]=m.sha(b'[Unit]\nDescription=synthetic\n');write(path,b'[Unit]\nDescription=synthetic\n')
        for path in m.CONFIGS:write(path,b'SYNTHETIC',mode=0o600)
        for path in m.DYNAMIC:write(path,b'{}',1001,1001,0o600)
        for n in range(87):write(m.LIGHTING+f'/file-{n}.txt',b'SYNTHETIC LIGHTING\n')
        objects={}
        for rel in ('.',*(f'file-{n}.txt' for n in range(87))):
            p=self.root/m.LIGHTING.lstrip('/')/rel;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME)
            try:row=m.metadata(fd)
            finally:os.close(fd)
            objects[rel]={'metadata':{k:row[k] for k in m.FIELDS},
                          'sha256':None if p.is_dir() else m.sha(p.read_bytes())}
        scope,pin=plan_fixture(objects)
        for name,value in (('PLAN',pin),('UNIT_FILES',units)):
            p=patch.object(m,name,value);p.start();self.patches.append(p)
        self.scope=scope;self.capture=m.Capture(self.rootfd,scope,deadline=time.monotonic()+15)
    def tearDown(self):
        if self.capture:self.capture.close()
        os.close(self.rootfd)
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_real_finite_readback_preserves_metadata_and_all_bytes(self):
        first=self.capture.directories()
        for path in self.scope['files']:
            row,raw=self.capture.file(path)
            if raw is not None:self.assertEqual(m.sha(raw),row['sha256'])
        self.capture.check();last=self.capture.directories()
        self.assertEqual({p:v.get('names') for p,v in first.items()},{p:v.get('names') for p,v in last.items()})
        self.assertEqual(len(self.capture.rows),102)
        self.assertLess(self.capture.total,m.MAX_TOTAL)
    def test_unknown_dropin_is_not_read_or_silently_omitted(self):
        p=self.root/'etc/systemd/system'/str(m.UNITS[1]+'.d')/'unbound.conf';p.write_bytes(b'SYNTHETIC')
        with self.assertRaisesRegex(m.Denied,'UNKNOWN_DIRECTORY_MEMBER'):self.capture.directories()
    def test_symlink_cannot_redirect_content_read(self):
        path=m.CONFIGS[0];p=self.root/path.lstrip('/');p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaises(OSError):self.capture.file(path)
    def test_hardlink_and_foreign_metadata_are_not_accepted(self):
        path=m.CONFIGS[0];p=self.root/path.lstrip('/');os.link(p,p.with_name('unbound-copy'))
        with self.assertRaisesRegex(m.Denied,'REGULAR_PROFILE'):self.capture.file(path)
    def test_lighting_drift_and_wrong_unit_bytes_deny(self):
        path=m.LIGHTING+'/file-0.txt';(self.root/path.lstrip('/')).write_bytes(b'CHANGED')
        with self.assertRaisesRegex(m.Denied,'OWNER_PLAN_DRIFT'):self.capture.file(path)
        path=next(iter(m.UNIT_FILES));(self.root/path.lstrip('/')).write_bytes(b'CHANGED')
        with self.assertRaisesRegex(m.Denied,'UNIT_BYTES_CHANGED'):self.capture.file(path)
    def test_unadmitted_read_and_deadline_deny(self):
        with self.assertRaisesRegex(m.Denied,'OUT_OF_SCOPE'):self.capture.file('/etc/shadow')
        self.capture.deadline=time.monotonic()-1
        with self.assertRaisesRegex(m.Denied,'DEADLINE'):self.capture.file(m.CONFIGS[0])


if __name__=='__main__':unittest.main()
