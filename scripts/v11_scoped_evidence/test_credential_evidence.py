import json,unittest
import credential_evidence as c
class CredentialEvidenceTests(unittest.TestCase):
 def call(self,obj,prop='LoadCredential',rendered=None):return c.evaluate(prop,rendered or prop+'=[unprintable]',json.dumps(obj).encode())
 def test_empty_typed_array(self):self.assertTrue(self.call({'type':'a(ss)','data':[]})['empty_proven'])
 def test_nonempty_never_exported_or_accepted(self):
  result=self.call({'type':'a(ss)','data':[['private-name','private-secret-value']]})
  self.assertEqual(result['status'],'UNRESOLVED_NONEMPTY');self.assertNotIn('private-secret',json.dumps(result))
 def test_unprintable_alone_is_not_proof(self):
  with self.assertRaises(c.Refused):c.evaluate('LoadCredential','LoadCredential=[unprintable]',b'')
 def test_other_rendering_refused(self):
  with self.assertRaises(c.Refused):self.call({'type':'a(ss)','data':[]},rendered='LoadCredential=unknown')
 def test_signature_refused(self):
  with self.assertRaises(c.Refused):self.call({'type':'as','data':[]})
 def test_nonarray_refused(self):
  with self.assertRaises(c.Refused):self.call({'type':'a(ss)','data':None})
 def test_malformed_tuple_refused(self):
  for data in [[['only-one']],[[1,2]],['private']]:
   with self.subTest(data=data):
    with self.assertRaises(c.Refused):self.call({'type':'a(ss)','data':data})
 def test_extra_response_field_refused(self):
  with self.assertRaises(c.Refused):self.call({'type':'a(ss)','data':[],'extra':'private'})
 def test_wrong_property_refused(self):
  with self.assertRaises(c.Refused):self.call({'type':'a(ss)','data':[]},prop='Environment')
 def test_both_arrays_required(self):
  p=self.call({'type':'a(ss)','data':[]})
  with self.assertRaises(c.Refused):c.resolve_unit('trendwatch-fetch.service',[p])
 def test_current_supplement_not_historical_rewrite(self):
  p=[self.call({'type':'a(ss)','data':[]},prop=n) for n in c.PROPERTIES]
  self.assertTrue(c.resolve_unit('trendwatch-fetch.service',p)['original_manifest_unchanged'])
 def test_nonempty_pair_refused(self):
  p=[self.call({'type':'a(ss)','data':[['name','private']]},prop=n) for n in c.PROPERTIES]
  with self.assertRaises(c.Refused):c.resolve_unit('trendwatch-fetch.service',p)
if __name__=='__main__':unittest.main()
