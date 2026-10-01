"""Pure offline admission for the explicitly reviewed seven n8n markers.

No blanket expression exemption, no evaluation, no workflow or host mutation.
Review bytes are separately pinned by the future root-owned transaction bundle.
"""
import hashlib
import json

class Refused(ValueError): pass

def admit(review_bytes, expected_sha256, observed):
    if hashlib.sha256(review_bytes).hexdigest()!=expected_sha256:
        raise Refused('REVIEW_BINDING')
    review=json.loads(review_bytes)
    for key in ('workflow_id','version_id','workflow_nodes_sha256','connections_sha256'):
        if not observed.get(key) or observed[key]!=review[key]:raise Refused('WORKFLOW_DRIFT')
    if review.get('active') is not True or observed.get('active') is not True:raise Refused('ACTIVE_DRIFT')
    expected={(2,'parameters.command'),(3,'parameters.functionCode'),
              (4,'parameters.bodyParameters.parameters[1].value'),
              (4,'parameters.bodyParameters.parameters[2].value'),
              (5,'parameters.functionCode'),(6,'parameters.command'),(7,'parameters.command')}
    markers=review.get('markers',[])
    if len(markers)!=7 or {(m['node_index'],m['field']) for m in markers}!=expected:
        raise Refused('MARKER_SET')
    for m in markers:
        if m.get('classification')!='NON_NETWORK_EXPRESSION' or m.get('network_endpoint_affected') is not False:
            raise Refused('MARKER_SEMANTICS')
    endpoint=review['http_endpoint']
    if endpoint.get('dynamic_host') is not False or endpoint.get('host')!='api.telegram.org' or endpoint.get('scheme')!='https' or endpoint.get('port')!=443:
        raise Refused('ENDPOINT_DRIFT')
    if observed.get('http_url_sha256')!=endpoint['url_sha256']:raise Refused('ENDPOINT_DRIFT')
    return {'consumer_review':'COMPLETE_FOR_BOUND_WORKFLOW_VERSION',
            'n8n_identity_blocker':False,'case':'A','static_ips':[],
            'static_macs':[],'workflow_change_required':False,
            'activation_authorized':False}
