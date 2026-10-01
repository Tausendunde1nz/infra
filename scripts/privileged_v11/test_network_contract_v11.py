import copy
import unittest
from network_contract_v11 import *


def sample():
    e={'NetworkID':'net-id','Aliases':['mommy','mommy'],'IPAMConfig':None,
       'DriverOpts':None,'GwPriority':0,'IPAddress':'172.25.0.2','MacAddress':'aa:bb:cc:dd:ee:ff',
       'EndpointID':'old','Gateway':'172.25.0.1'}
    return {'Name':'/mommy','Image':'sha256:fixed','Config':{'User':'','Env':['SECRET=fixture']},
      'HostConfig':{'Privileged':False,'CapAdd':None,'Devices':[],'CapDrop':None,
       'SecurityOpt':None,'ReadonlyRootfs':False,'Binds':['/opt/telegram_chatbot:/app:rw'],
       'PortBindings':{'8080/tcp':[{'HostIp':'','HostPort':'8081'}]}},
      'Mounts':[{'Type':'bind','Source':'/opt/telegram_chatbot','Destination':'/app',
                 'Propagation':'rprivate','RW':True,'Mode':'rw'}],
      'NetworkSettings':{'Networks':{'shared':e},'SandboxID':'old'}}

class NetworkTests(unittest.TestCase):
    def test_ephemeral_values(self):
        a=sample();b=copy.deepcopy(a);e=b['NetworkSettings']['Networks']['shared']
        e.update(IPAddress='172.25.0.3',MacAddress='new',EndpointID='new')
        b['NetworkSettings']['SandboxID']='new'
        self.assertEqual(contract(a,'shared'),contract(b,'shared'))
    def test_static_consumer_rejects_new_ip(self):
        a=sample();b=copy.deepcopy(a);b['NetworkSettings']['Networks']['shared']['IPAddress']='172.25.0.3'
        self.assertNotEqual(contract(a,'shared',{'shared':{'static_ip':True}}),contract(b,'shared',{'shared':{'static_ip':True}}))
    def test_mac_pin_only_when_proven(self):
        a=sample();b=copy.deepcopy(a);b['NetworkSettings']['Networks']['shared']['MacAddress']='new'
        self.assertNotEqual(contract(a,'shared',{'shared':{'static_mac':True}}),contract(b,'shared',{'shared':{'static_mac':True}}))
    def test_added_alias_is_drift(self):
        a=sample();b=copy.deepcopy(a);b['NetworkSettings']['Networks']['shared']['Aliases'].append('other')
        self.assertNotEqual(contract(a,'shared'),contract(b,'shared'))
    def test_alias_duplication_is_not_drift(self):
        a=sample();b=copy.deepcopy(a);b['NetworkSettings']['Networks']['shared']['Aliases']=['mommy']
        self.assertEqual(contract(a,'shared'),contract(b,'shared'))
    def test_dynamic_ipam_preserved(self):
        a=sample();b=copy.deepcopy(a);b['NetworkSettings']['Networks']['shared']['IPAMConfig']={'IPv4Address':'172.25.0.2'}
        self.assertNotEqual(contract(a,'shared'),contract(b,'shared'))
    def test_missing_network(self):
        with self.assertRaises(ContractError):contract(sample(),'absent')
    def test_security_delta_only(self):
        a=sample();b=hardened_snapshot(a)
        self.assertEqual(b['Config']['User'],'20001:20001');self.assertEqual(a,sample())
        self.assertEqual(a['NetworkSettings'],b['NetworkSettings'])
        self.assertEqual(a['HostConfig']['PortBindings'],b['HostConfig']['PortBindings'])
    def test_unknown_mount_rejected(self):
        a=sample();a['HostConfig']['Binds'].append('/run/docker.sock:/sock:ro')
        with self.assertRaises(ContractError):hardened_snapshot(a)
    def test_unexpected_security_rejected(self):
        for key,value in [('Privileged',True),('CapAdd',['SYS_ADMIN']),('SecurityOpt',['apparmor=unconfined']),('ReadonlyRootfs',True)]:
            with self.subTest(key=key):
                a=sample();a['HostConfig'][key]=value
                with self.assertRaises(ContractError):hardened_snapshot(a)
    def test_runtime_checks_required(self):
        with self.assertRaises(ContractError):assert_contract({}, {}, {})
    def test_all_checks_success(self):
        keys={'uid_gid','capabilities','nnp','rootfs','code_readonly','dns','hostport','internal_port','proxy','monitoring','listeners','mychatbuddy','running'}
        checks=dict.fromkeys(keys,True);assert_contract({}, {}, checks)
        for k in keys:
            bad=checks.copy();bad[k]=False
            with self.assertRaises(ContractError):assert_contract({}, {}, bad)
    def test_review_incomplete(self):
        with self.assertRaises(ContractError):reference_decision([],False)
    def test_dnat_unknown(self):
        with self.assertRaises(ContractError):reference_decision([{'kind':'docker_dnat'}],True)
    def test_hostport_dynamic(self):
        self.assertEqual(reference_decision([{'kind':'hostport','value':'8081'},{'kind':'docker_dnat','docker_owned_verified':True}],True),{'static_ips':[],'static_macs':[]})
    def test_hardcoded_dependency_detected(self):
        self.assertEqual(reference_decision([{'kind':'static_ip','value':'172.25.0.2'}],True)['static_ips'],['172.25.0.2'])
    def test_secrets_not_manifested(self):
        self.assertNotIn('SECRET',json.dumps(contract(sample(),'shared')))

if __name__=='__main__':unittest.main()
