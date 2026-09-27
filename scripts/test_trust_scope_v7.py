import copy
import unittest
from tu1nz_trust_scope_v7 import *

class ScopeTests(unittest.TestCase):
    def test_independent_accounts(self):
        for name in ('mychatbuddy','jellyfin','cadvisor'):
            self.assertEqual(authority_scope(chatops_influence=False,privileged_effect=True,independent_contract=True),'REQUIRED_CONTRACT')
    def test_application_integrity_separate(self):
        self.assertEqual(authority_scope(chatops_influence=True,privileged_effect=False),'SEPARATE_INTEGRITY_FINDING')
    def test_proved_authority(self):
        self.assertEqual(authority_scope(chatops_influence=True,privileged_effect=True),'BLOCKER')
    def test_unknown_authority(self):
        self.assertEqual(authority_scope(chatops_influence=None,privileged_effect=True),'REVIEW_REQUIRED')
    def test_gid_scope(self):
        independent=dict(uid=10001,groups=[987],inherited_chatops=False,independent_contract_verified=True)
        self.assertTrue(docker_revocation_complete(False,[],[independent],False))
        for identity in (dict(groups=[987],inherited_chatops=True),dict(groups=[987])):
            self.assertFalse(docker_revocation_complete(False,[],[identity],False))
        self.assertFalse(docker_revocation_complete(True,[],[],False))
        self.assertFalse(docker_revocation_complete(False,[987],[],False))
        self.assertFalse(docker_revocation_complete(False,[],[],True))
    def entries(self):return [dict(id='root',source='root',root_capable=True,query_ok=True)]
    def test_literal_not_execution(self):
        edges=[dict(source='root',target='unused',kind='LITERAL_CANDIDATE')]
        r=reachable_review(self.entries(),edges,{'root':True})
        self.assertEqual(r['edges'][0],'UNREACHABLE_LITERAL');self.assertTrue(r['activation_ready'])
    def test_literal_unknown_without_closure(self):
        r=reachable_review(self.entries(),[dict(source='root',target='x',kind='LITERAL_CANDIDATE')],{})
        self.assertEqual(r['edges'][0],'UNRESOLVED_LITERAL');self.assertFalse(r['activation_ready'])
    def test_reachable_dynamic(self):
        r=reachable_review(self.entries(),[dict(source='root',target='x',kind='DYNAMIC')],{'root':True})
        self.assertFalse(r['activation_ready'])
    def test_unreachable_dynamic(self):
        r=reachable_review(self.entries(),[dict(source='unrelated',target='x',kind='DYNAMIC')],{'root':True})
        self.assertTrue(r['activation_ready'])
    def test_transitive_cycle_blocker(self):
        e=[dict(source='root',target='script',kind='EXEC',proven=True,classification='SAFE'),
           dict(source='script',target='root',kind='CONFIG',proven=True,classification='BLOCKER')]
        r=reachable_review(self.entries(),e,dict(root=True,script=True))
        self.assertEqual(r['reached'],['root','script']);self.assertFalse(r['activation_ready'])
    def test_query_failure_not_absence(self):
        e=self.entries();e[0]['query_ok']=False
        self.assertFalse(reachable_review(e,[],{})['activation_ready'])
    def test_template_separate(self):
        e=self.entries();e[0]['template_without_instance_verified']=True
        r=reachable_review(e,[],{});self.assertEqual(r['excluded'][0]['reason'],'UNINSTANTIATED_TEMPLATE')
    def test_inactive_still_activatable(self):
        e=self.entries();e[0]['active']=False
        self.assertFalse(reachable_review(e,[],{})['activation_ready'])
    def test_quarantine_requires_proof(self):
        e=self.entries();e[0]['quarantine_verified']=True
        self.assertTrue(reachable_review(e,[],{})['activation_ready'])
    def test_rollback_never_reenables_unsafe_trigger(self):
        before=dict(triggers={'root-doc':dict(enabled=True)},data=dict(exact='bytes'))
        result=rollback_policy(before,['root-doc'])
        self.assertTrue(before['triggers']['root-doc']['enabled'])
        self.assertFalse(result['triggers']['root-doc']['enabled']);self.assertEqual(before['data'],result['data'])

    def test_empty_entry_coverage_refused(self):
        with self.assertRaises(ValueError):reachable_review([],[],{})
    def test_chatops_cannot_masquerade_as_independent(self):
        p=dict(uid=1001,groups=[987],inherited_chatops=False,independent_contract_verified=True)
        self.assertFalse(docker_revocation_complete(False,[],[p],False))
    def test_group_schema_fail_closed(self):
        self.assertFalse(docker_revocation_complete(False,['987'],[],False))
        self.assertFalse(docker_revocation_complete(False,[],[dict(groups=['987'])],False))
