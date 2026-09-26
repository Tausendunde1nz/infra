import importlib.util,pathlib,copy,unittest
p=pathlib.Path(__file__).parents[1]/'scripts'/'tu1nz_ipv6_network_compare.py'
s=importlib.util.spec_from_file_location('cmp',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 def setUp(self):
  self.b={'addr4':[{'ifname':'eth0','addr_info':[{'local':'192.0.2.1','preferred_life_time':100,'valid_life_time':100}]}],'addr6':[],'route6':[{'dst':'default','dev':'eth0'}],'rule6':[{'priority':0}],'links':[{'ifname':'tailscale0','flags':['UP']}],'flags':{'all':'1','default':'1','tailscale0':'1','eth0':'0'}}
 def check(self,mutate,want,elapsed=1.2):
  a=copy.deepcopy(self.b);mutate(a);orig=copy.deepcopy(a);self.assertEqual(m.compare_network(self.b,a,elapsed)[0],want);self.assertEqual(a,orig)
 def test_unchanged(self):self.check(lambda a:None,True)
 def test_countdown(self):self.check(lambda a:a['addr4'][0]['addr_info'][0].update(preferred_life_time=99,valid_life_time=99),True)
 def test_excessive(self):self.check(lambda a:a['addr4'][0]['addr_info'][0].update(valid_life_time=90),False)
 def test_increase(self):self.check(lambda a:a['addr4'][0]['addr_info'][0].update(valid_life_time=101),False)
 def test_address(self):self.check(lambda a:a['addr4'][0]['addr_info'][0].update(local='192.0.2.2'),False)
 def test_interface(self):self.check(lambda a:a['addr4'][0].update(ifname='lo'),False)
 def test_route(self):self.check(lambda a:a['route6'][0].update(dev='tailscale0'),False)
 def test_rule(self):self.check(lambda a:a['rule6'][0].update(priority=1),False)
 def test_flags(self):
  for k in self.b['flags']:
   with self.subTest(k=k):self.check(lambda a:a['flags'].update({k:'9'}),False)
 def test_link(self):self.check(lambda a:a['links'][0].update(flags=[]),False)
 def test_removed(self):self.check(lambda a:a['addr4'].clear(),False)
 def test_new_field(self):self.check(lambda a:a.update(unexpected=1),False)
 def test_forever(self):self.check(lambda a:a['addr4'][0]['addr_info'][0].update(valid_life_time='forever'),False)
 def test_bad_interval(self):
  for t in [-1,61,float('nan'),float('inf')]:
   with self.assertRaises(ValueError):m.compare_network(self.b,self.b,t)
if __name__=='__main__':unittest.main()
