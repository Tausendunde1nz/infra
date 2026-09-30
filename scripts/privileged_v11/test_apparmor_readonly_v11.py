import ast
import pathlib
import unittest
import tempfile
from unittest.mock import patch
import apparmor_readonly_v11 as a

class Tests(unittest.TestCase):
    def test_nonroot_does_not_probe(self):
        with patch.object(a.os,'geteuid',return_value=1001),patch.object(a,'docker_get') as docker:
            with self.assertRaises(a.Refused):a.collect()
            docker.assert_not_called()
    def test_fixed_docker_paths(self):
        for path in ['/info','/containers/json','/containers/other/json','/images/json']:
            with self.subTest(path=path),self.assertRaises(a.Refused):a.docker_get(path)
    def test_no_mutating_api_or_subprocess(self):
        tree=ast.parse(pathlib.Path(a.__file__).read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)]
        for n in calls:
            if isinstance(n.func,ast.Attribute) and n.func.attr=='request':self.assertEqual(n.args[0].value,'GET')
        self.assertNotIn('subprocess',pathlib.Path(a.__file__).read_text())
    def test_include(self):
        self.assertEqual(a.include_names('#include <tunables/global>\n include if exists "local/docker"'),['tunables/global','local/docker'])
    def test_include_escape(self):
        for s in ['#include </etc/shadow>','#include <../shadow>','#include <local/*>','#include <${PATH}>']:
            with self.subTest(s=s),self.assertRaises(a.Refused):a.include_names(s)
    def test_identity(self):
        c={'Id':a.CONTAINER,'Image':a.IMAGE,'State':{'Running':True,'Pid':42,'StartedAt':'fixed'},'AppArmorProfile':'docker-default'}
        self.assertEqual(a.identity(c)[2],42)
        for key,value in [('Id','other'),('Image','other')]:
            bad=dict(c);bad[key]=value
            with self.assertRaises(a.Refused):a.identity(bad)
    def test_invalid_pid(self):
        for pid in [0,1,-1,'42',True]:
            c={'Id':a.CONTAINER,'Image':a.IMAGE,'State':{'Running':True,'Pid':pid,'StartedAt':'fixed'}}
            with self.subTest(pid=pid),self.assertRaises(a.Refused):a.identity(c)
    def test_no_secret_fields_selected(self):
        text=pathlib.Path(a.__file__).read_text()
        self.assertNotIn("['Env']",text)
        self.assertNotIn("['Config']",text)
    def test_digest(self):
        self.assertEqual(len(a.digest(b'test')),64)
    def test_full_collection_only_fake_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp).resolve();profile=root/'policy/profiles/docker-default.119';profile.mkdir(parents=True)
            (root/'features').mkdir();(root/'features/test').write_text('yes')
            for n,b in {'name':b'docker-default','mode':b'enforce','sha256':a.POLICY.encode(),
                        'raw_abi':b'9','raw_sha256':b'a'*64,'raw_data':b'\x00compiled'}.items():(profile/n).write_bytes(b)
            original=a.read
            def reader(path,limit=1000000):
                if str(path)=='/proc/42/attr/current':return b'docker-default (enforce)'
                return original(path,limit)
            c={'Id':a.CONTAINER,'Image':a.IMAGE,'State':{'Running':True,'Pid':42,'StartedAt':'fixed'},
               'AppArmorProfile':'docker-default','HostConfig':{'SecurityOpt':None}}
            def docker(path):return {'Version':'fake'} if path=='/version' else c
            with patch.object(a.os,'geteuid',return_value=0),patch.object(a,'SECURITY',root),patch.object(a,'read',side_effect=reader),patch.object(a,'docker_get',side_effect=docker),patch.object(a,'source_records',return_value=[]):
                result=a.collect()
            self.assertEqual(result['docker_version'],{'Version':'fake'})
            self.assertEqual(result['profile'][-1]['sha256'],a.digest(b'\x00compiled'))
            self.assertNotIn('text',result['profile'][-1])
            self.assertFalse(result['further_general_collector_authorized'])

if __name__=='__main__':unittest.main()
