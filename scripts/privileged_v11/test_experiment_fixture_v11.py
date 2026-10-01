import unittest
from network_semantic_experiment_v11 import test_hostname_body, APIError
class FixtureTests(unittest.TestCase):
 def test_consumer_hostname_must_not_shadow_service_dns(self):
  source={'Hostname':'service','Cmd':['fixture']}
  consumer=test_hostname_body('consumer',source)
  self.assertEqual(consumer['Hostname'],'consumer')
  self.assertEqual(source['Hostname'],'service')
  self.assertEqual(consumer['Cmd'],source['Cmd'])
 def test_recreated_service_retains_its_name(self):
  self.assertEqual(test_hostname_body('service',{'Hostname':'old'})['Hostname'],'service')
 def test_long_fixture_name_has_valid_distinct_hostname(self):
  a=test_hostname_body('x'*70,{})['Hostname'];b=test_hostname_body('x'*69+'y',{})['Hostname']
  self.assertLessEqual(len(a),63);self.assertNotEqual(a,b)
 def test_collision_uses_message_not_generic_failure(self):
  self.assertTrue(APIError(403,b'{"message":"failed to set up container networking: Address already in use"}').address_collision)
  self.assertFalse(APIError(500,b'{"message":"sethostname: invalid argument"}').address_collision)
if __name__=='__main__':unittest.main()
