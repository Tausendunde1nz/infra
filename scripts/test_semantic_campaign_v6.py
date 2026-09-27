import unittest
from copy import deepcopy
from tu1nz_semantic_campaign_v6 import *

class SemanticTests(unittest.TestCase):
    def facts(self):
        return dict(container_uid=0, docker_socket=False, host_root_mount=False,
                    privileged=False, host_code_consumer=False, namespaces_reviewed=True,
                    capabilities_reviewed=True, mounts_reviewed=True, devices_reviewed=True)
    def test_root_alone(self):
        self.assertEqual(classify_container(self.facts()), 'REQUIRED_CONTRACT')
    def test_host_edges(self):
        for key in ('docker_socket','host_root_mount','privileged','host_code_consumer'):
            with self.subTest(key=key):
                f=self.facts(); f[key]=True
                self.assertEqual(classify_container(f),'BLOCKER')
    def test_unknown_host_consumer(self):
        f=self.facts();f.pop('host_code_consumer')
        self.assertEqual(classify_container(f),'REVIEW_REQUIRED')
    def test_nonroot_application(self):
        f=self.facts();f['container_uid']=1001
        self.assertEqual(classify_container(f),'SAFE')
    def test_root_compose_recreated_missing_directory(self):
        for exists in (True,False):
            self.assertEqual(compose_gate(dict(root_execution=True,
                user_writable_ancestor=True, exists=exists)), 'BLOCKER')
    def test_compose_env_hash_drift(self):
        f=dict(explicit_config=True,root_owned_chain=True,env_bound=True,image_bound=True,
               endpoint_bound=True,source_hash_matches=True)
        self.assertEqual(compose_gate(f),'SAFE')
        for key in f:
            g=f.copy();g[key]=False
            self.assertEqual(compose_gate(g),'REVIEW_REQUIRED')
    def test_graph_never_closes_unknowns(self):
        for category in ('BLOCKER','REVIEW_REQUIRED','invalid','REQUIRED_CONTRACT'):
            with self.assertRaises(Refused):readiness([dict(id='x',classification=category)],{})
        with self.assertRaises(Refused):readiness([],{})
    def test_restart_contracts(self):
        for service in ('tu1nz_agentmode.service','mychatbuddy-private-alpha.service'):
            with self.assertRaises(Refused):restart_gate(service,dict(identity_bound=True))
    def model(self):
        return CampaignModel(dict(endpoints=[dict(ip='172.25.0.3',aliases=[],extra=True)],
            image='sha256:pinned', acl='exact', groups=[987], running=True),
            [dict(id='fake-proven-edge',classification='SAFE')],{})
    def test_every_phase_failure_and_resume(self):
        for phase in range(6):
            for boundary in ('before','after'):
                with self.subTest(phase=phase,boundary=boundary):
                    c=self.model();c.start()
                    for p in range(phase):c.step(p,c.state,dict(c.state,phase=p),lambda s:True)
                    before=deepcopy(c.state)
                    with self.assertRaises(Refused):c.step(phase,before,dict(before,phase=phase),lambda s:True,boundary)
                    self.assertEqual(c.state,before)
                    with self.assertRaises(Refused):c.step(phase,before,before,lambda s:True)
                    c.acknowledge_verified_rollback(before)
                    c.step(phase,before,dict(before,phase=phase),lambda s:True)
                    self.assertEqual(c.total_rollback(),c.initial)
    def test_endpoint_mismatch_rolls_back(self):
        c=self.model();c.start();before=deepcopy(c.state);bad=dict(before,endpoints=[])
        with self.assertRaises(Refused):c.step(0,before,bad,lambda s:s['endpoints']==before['endpoints'])
        self.assertEqual(c.state,before)
    def test_parallel_start(self):
        c=self.model();c.start()
        with self.assertRaises(Refused):c.start()
    def test_drift(self):
        c=self.model();c.start()
        with self.assertRaises(Refused):c.step(0,{},c.state,lambda s:True)
    def test_disconnect_and_residual_gid(self):
        c=self.model();c.start();self.assertEqual(c.ssh_disconnect(),0)
        for p in range(6):c.step(p,c.state,dict(c.state,phase=p),lambda s:True)
        with self.assertRaises(Refused):c.complete([dict(uid=10001,gid=987)])
        self.assertTrue(c.complete([]))

if __name__=='__main__':unittest.main()
