import copy
import unittest
from host_boundary_v11 import classify

def known():
    return dict(inspection_complete=True, chatops_controls_source=True,
                host_uid_zero=True, host_bind_writable=True,
                host_suid_enabled=True, host_exec_enabled=True,
                host_caller_can_gain_privilege=True, file_privilege_operations=True,
                lsm_allows_host_file_chain=True, other_host_privilege_path=False,
                boundary_review_complete=True)

class BoundaryTests(unittest.TestCase):
    def test_confirmed_chain(self):
        self.assertEqual(classify(known())['class'],'HOST_ROOT_PATH_CONFIRMED')
    def test_current_unreadable_profile(self):
        f=known();f['lsm_allows_host_file_chain']=None
        self.assertEqual(classify(f)['reason'],'LOADED_LSM_RULES_UNREADABLE')
    def test_name_and_hash_are_not_permissions(self):
        f=known();f['lsm_allows_host_file_chain']=None
        f.update(profile='docker-default',mode='enforce',sha256='a'*64)
        self.assertEqual(classify(f)['class'],'CONTAINER_BOUNDARY_UNRESOLVED')
    def test_reviewed_nonroot_boundary(self):
        f=known();f['host_uid_zero']=False
        self.assertEqual(classify(f)['class'],'ISOLATED_CONTAINER_ROOT_RISK')
    def test_nonroot_not_sufficient_for_other_paths(self):
        f=known();f.update(host_uid_zero=False,other_host_privilege_path=True)
        self.assertEqual(classify(f)['class'],'HOST_ROOT_PATH_CONFIRMED')
    def test_no_implicit_complete_review(self):
        f=known();f.update(host_uid_zero=False,boundary_review_complete=None)
        self.assertEqual(classify(f)['class'],'CONTAINER_BOUNDARY_UNRESOLVED')
    def test_each_missing_field(self):
        for k in known():
            f=known();del f[k]
            with self.subTest(k=k):self.assertEqual(classify(f)['class'],'CONTAINER_BOUNDARY_UNRESOLVED')
    def test_non_boolean_evidence_rejected(self):
        for k in known():
            f=known();f[k]='true'
            with self.subTest(k=k):self.assertEqual(classify(f)['class'],'CONTAINER_BOUNDARY_UNRESOLVED')
    def test_no_false_approval_from_unknown_chain(self):
        f=known();f.update(host_uid_zero=None,boundary_review_complete=None)
        self.assertEqual(classify(f)['class'],'CONTAINER_BOUNDARY_UNRESOLVED')
    def test_explicit_policy_denial_requires_review(self):
        f=known();f.update(lsm_allows_host_file_chain=False,boundary_review_complete=None)
        self.assertEqual(classify(f)['class'],'CONTAINER_BOUNDARY_UNRESOLVED')
    def test_no_input_mutation(self):
        f=known();before=copy.deepcopy(f);classify(f);self.assertEqual(f,before)
    def test_no_activation_output(self):
        self.assertNotIn('activation_authorized',classify(known()))

if __name__=='__main__':unittest.main()
