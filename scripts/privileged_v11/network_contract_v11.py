"""Fail-closed functional network contract. No Docker access or mutation here.

Endpoint/MAC/sandbox IDs and dynamic addresses are not identities. The admission
record must prove consumers before selecting dynamic IPAM; unknown is not safe.
"""
import copy
import hashlib
import json

class ContractError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def reference_decision(records, complete):
    if not complete or not records:
        raise ContractError('CONSUMER_REVIEW_INCOMPLETE')
    if any(r['kind'] not in {'hostport','dns','docker_dnat','static_ip','static_mac','unrelated'} for r in records):
        raise ContractError('UNKNOWN_CONSUMER')
    if any(r['kind']=='docker_dnat' and not r.get('docker_owned_verified') for r in records):
        raise ContractError('DNAT_OWNERSHIP_UNPROVEN')
    return {'static_ips':sorted({r['value'] for r in records if r['kind']=='static_ip'}),
            'static_macs':sorted({r['value'] for r in records if r['kind']=='static_mac'})}


def normalize_endpoint(e, pins):
    # Alias duplication is not DNS semantics, but additional aliases are drift.
    required={'NetworkID','Aliases','IPAMConfig','DriverOpts','GwPriority','IPAddress','MacAddress'}
    if not required <= e.keys(): raise ContractError('INCOMPLETE_ENDPOINT')
    ipam=e['IPAMConfig'] or {}
    if set(ipam)-{'IPv4Address','IPv6Address','LinkLocalIPs'}:raise ContractError('UNKNOWN_IPAM')
    if any(ipam.get(k) for k in ('IPv6Address','LinkLocalIPs')):raise ContractError('UNEXPECTED_ADDRESS_FAMILY')
    return {'network_id':e['NetworkID'],'aliases':sorted(set(e['Aliases'] or [])),
            'driver_opts':e['DriverOpts'] or {},'gateway_priority':e['GwPriority'],
            'ipam':ipam,
            'static_ip':e['IPAddress'] if pins.get('static_ip') else None,
            'static_mac':e['MacAddress'] if pins.get('static_mac') else None}


def contract(inspect, default_network, pins=None):
    pins=pins or {}; nets=inspect['NetworkSettings']['Networks']
    if default_network not in nets:raise ContractError('DEFAULT_NETWORK_MISSING')
    if set(pins)-set(nets):raise ContractError('UNKNOWN_PIN_NETWORK')
    return {'name':inspect['Name'],'image':inspect['Image'],
            'config_sha256':digest(inspect['Config']),
            'hostconfig_sha256':digest(inspect['HostConfig']),
            'mounts':sorted(inspect['Mounts'],key=lambda m:m['Destination']),
            'networks':{n:normalize_endpoint(e,pins.get(n,{})) for n,e in sorted(nets.items())},
            'default_network':default_network}


def assert_contract(expected, actual, checks):
    if expected!=actual:raise ContractError('FUNCTIONAL_CONTRACT_DRIFT')
    required={'uid_gid','capabilities','nnp','rootfs','code_readonly','dns','hostport',
              'internal_port','proxy','monitoring','listeners','mychatbuddy','running'}
    if set(checks)!=required or any(checks[k] is not True for k in required):
        raise ContractError('RUNTIME_CHECKS_INCOMPLETE_OR_FAILED')


def hardened_snapshot(original):
    c=copy.deepcopy(original)
    if c['Config']['User'] not in ('','0','0:0'):raise ContractError('UNEXPECTED_BASE_USER')
    h=c['HostConfig']
    if h['Privileged'] or h.get('CapAdd') or h.get('Devices') or h.get('DeviceRequests'):
        raise ContractError('UNEXPECTED_PRIVILEGE')
    if h.get('SecurityOpt') or h.get('CapDrop') or h['ReadonlyRootfs']:
        raise ContractError('UNEXPECTED_BASE_SECURITY')
    if h['Binds']!=['/opt/telegram_chatbot:/app:rw']:
        raise ContractError('UNEXPECTED_BINDS')
    mounts=c['Mounts']
    if len(mounts)!=1 or mounts[0]['Type']!='bind' or mounts[0]['Source']!='/opt/telegram_chatbot' or mounts[0]['Destination']!='/app' or mounts[0]['Propagation']!='rprivate':
        raise ContractError('UNEXPECTED_MOUNTS')
    c['Config']['User']='20001:20001';h['CapDrop']=['ALL']
    h['SecurityOpt']=['no-new-privileges:true'];h['ReadonlyRootfs']=True
    h['Binds']=['/opt/telegram_chatbot:/app:ro'];mounts[0]['RW']=False;mounts[0]['Mode']='ro'
    return c
