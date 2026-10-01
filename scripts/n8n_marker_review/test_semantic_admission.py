import copy,hashlib,json,unittest
from semantic_admission import admit,Refused

class AdmissionTests(unittest.TestCase):
 def setUp(self):
  pairs=[(2,'parameters.command'),(3,'parameters.functionCode'),(4,'parameters.bodyParameters.parameters[1].value'),(4,'parameters.bodyParameters.parameters[2].value'),(5,'parameters.functionCode'),(6,'parameters.command'),(7,'parameters.command')]
  self.r={'workflow_id':'fixture','version_id':'v1','active':True,'workflow_nodes_sha256':'a'*64,'connections_sha256':'b'*64,'markers':[{'node_index':i,'field':p,'classification':'NON_NETWORK_EXPRESSION','network_endpoint_affected':False} for i,p in pairs],'http_endpoint':{'dynamic_host':False,'host':'api.telegram.org','scheme':'https','port':443,'url_sha256':'c'*64}}
  self.o={k:self.r[k] for k in ['workflow_id','version_id','active','workflow_nodes_sha256','connections_sha256']};self.o['http_url_sha256']='c'*64
 def call(self):
  b=json.dumps(self.r).encode();return admit(b,hashlib.sha256(b).hexdigest(),self.o)
 def test_reviewed_bound_version(self):self.assertFalse(self.call()['activation_authorized']);self.assertFalse(self.call()['n8n_identity_blocker'])
 def test_bad_binding(self):
  with self.assertRaises(Refused):admit(json.dumps(self.r).encode(),'0'*64,self.o)
 def test_all_drift_fields(self):
  for key in self.o:
   with self.subTest(key=key):
    old=self.o[key];self.o[key]='other'
    with self.assertRaises(Refused):self.call()
    self.o[key]=old
 def test_no_generic_expression_exemption(self):
  for kind in ['UNRESOLVED','DIRECT_CONTAINER_IP','RUNTIME_CONTROLLED_ENDPOINT','HOST_PORT_8081','EXTERNAL_ENDPOINT']:
   self.r['markers'][0]['classification']=kind
   with self.assertRaises(Refused):self.call()
 def test_missing_marker(self):
  self.r['markers'].pop()
  with self.assertRaises(Refused):self.call()
 def test_duplicate_marker(self):
  self.r['markers'][0]=self.r['markers'][1]
  with self.assertRaises(Refused):self.call()
 def test_endpoint_affected(self):
  self.r['markers'][0]['network_endpoint_affected']=True
  with self.assertRaises(Refused):self.call()
 def test_dynamic_host(self):
  self.r['http_endpoint']['dynamic_host']=True
  with self.assertRaises(Refused):self.call()
 def test_internal_host(self):
  self.r['http_endpoint']['host']='172.25.0.2'
  with self.assertRaises(Refused):self.call()
 def test_version_review_is_not_global(self):
  self.r['version_id']='v2'
  with self.assertRaises(Refused):self.call()
if __name__=='__main__':unittest.main()
