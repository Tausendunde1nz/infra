import copy
import unittest
from graph_v9 import verify_graph
from policy_v9 import Refused
class Tests(unittest.TestCase):
 def setUp(self):
  self.g={'scope':'chatops-root-authority-v9','roots':['user'],'nodes':{'user':{'disposition':'TRUSTED_FIXED','proof':'u'},'docker':{'disposition':'REVOKED','proof':'d'}},'edges':[{'source':'user','target':'docker','kind':'DOCKER_API','resolution':'FIXED'}]}
  self.e={'u':{'verified':True},'d':{'verified':True}}
 def test_closed(self):self.assertTrue(verify_graph(self.g,self.e)['verified'])
 def test_no_boolean_waiver(self):
  self.g['closed']=True
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_missing_proof(self):
  del self.e['d']
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_false_proof(self):
  self.e['d']['verified']=False
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_unknown_edge(self):
  self.g['edges'][0]['resolution']='DYNAMIC'
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_literal_not_execution(self):
  self.g['edges'][0]['kind']='LITERAL'
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_unreachable_requires_explicit_removal_from_scope(self):
  self.g['nodes']['other']={'disposition':'TRUSTED_FIXED','proof':'u'}
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_unknown_node(self):
  self.g['nodes']['docker']['disposition']='UNKNOWN'
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
 def test_bad_target(self):
  self.g['edges'][0]['target']='missing'
  with self.assertRaises(Refused):verify_graph(self.g,self.e)
if __name__=='__main__':unittest.main()
