import copy
import unittest
from scope_gate_v11 import evaluate,binding

class Tests(unittest.TestCase):
    def setUp(self):
        self.x={'id':'a'*64,'image':'sha256:'+'b'*64,'pid':1,'uids':['0']*4,'uid_map':['0','0','4294967295'],'process_path':'python','python_script_args':['/app/main.py'],'mounts':[{'Source':'/opt/app','Destination':'/app','Type':'bind','RW':True}],'paths':[{'path':'/opt/app','type':16384,'chatops_writable':True,'acl_xattrs':{}},{'path':'/opt/app/main.py','type':32768,'sha256':'c'*64,'chatops_writable':True,'acl_xattrs':{}}]}
    def test_observed_boundary_blocks(self):self.assertEqual(evaluate(self.x)['admission'],'BLOCKED')
    def test_readonly_mount_does_not_protect_host_source(self):
        self.x['mounts'][0]['RW']=False;self.assertEqual(evaluate(self.x)['admission'],'BLOCKED')
    def test_parent_replacement_blocks(self):
        self.x['paths'][1]['chatops_writable']=False;self.assertEqual(evaluate(self.x)['admission'],'BLOCKED')
    def test_no_automatic_root_escape_claim(self):self.assertTrue(evaluate(self.x)['container_root_is_not_unrestricted_host_root'])
    def test_missing_fields_fail_closed(self):
        for k in list(self.x):
            x=copy.deepcopy(self.x);del x[k];self.assertEqual(evaluate(x)['admission'],'UNPROVEN')
    def test_symlink_is_unproven(self):
        self.x['paths'][1]['type']=40960;self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_acl_is_unproven(self):
        self.x['paths'][1]['acl_xattrs']={'system.posix_acl_access':'fixture'};self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_traversal_rejected(self):
        self.x['python_script_args']=['/app/../main.py'];self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_multiple_mounts_unproven(self):
        self.x['mounts']*=2;self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_no_mount_unproven(self):
        self.x['mounts']=[];self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_no_script_unproven(self):
        self.x['python_script_args']=[];self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_arbitrary_command_not_admitted(self):
        self.x['process_path']='sh';self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_nonroot_alone_not_activation_permission(self):
        self.x['uids']=['10001']*4;self.assertEqual(evaluate(self.x)['admission'],'UNPROVEN')
    def test_protected_nonroot_is_only_this_gate(self):
        self.x['uids']=['10001']*4
        for p in self.x['paths']:p['chatops_writable']=False
        self.assertFalse(evaluate(self.x)['activation_authorized'])
    def test_input_unchanged(self):
        before=copy.deepcopy(self.x);evaluate(self.x);self.assertEqual(before,self.x)
    def test_binding_covers_mutation(self):
        old=binding(self.x);self.x['paths'][1]['sha256']='d'*64;self.assertNotEqual(old,binding(self.x))

if __name__=='__main__':unittest.main()
