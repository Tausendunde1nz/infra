"""Isolated Docker endpoint/recovery experiment; no production resource access."""
import hashlib
import http.client
import json
import socket
import subprocess
import uuid

IMAGE='sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db'

class Unix(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(20);self.sock.connect('/var/run/docker.sock')

def api(method,path,body=None):
    c=Unix('localhost',timeout=20)
    try:
        c.request(method,'/v1.47'+path,body=None if body is None else json.dumps(body),
                  headers={'Content-Type':'application/json'})
        r=c.getresponse();raw=r.read(2_000_001)
        if r.status>=300:raise RuntimeError('API_'+str(r.status)+'_'+hashlib.sha256(raw).hexdigest())
        return json.loads(raw) if raw else None
    finally:c.close()

def endpoints(c):
    return c['NetworkSettings']['Networks']

def stable(e):
    return {k:e[k] for k in ('Aliases','MacAddress','DriverOpts','GwPriority',
                            'IPAddress','IPPrefixLen','Gateway','IPAMConfig')}

def main():
    prefix='tu1nz-v11-net-'+uuid.uuid4().hex
    nets=[];containers=[];report=[]
    try:
        for suffix in ('a-shared','b-compose'):
            n=prefix+'-'+suffix
            r=api('POST','/networks/create',{'Name':n,'Driver':'bridge','Internal':True,
                                          'Labels':{'tu1nz.offline':prefix}})
            nets.append((n,r['Id']))
            ipam=api('GET','/networks/'+r['Id'])['IPAM']
            api('DELETE','/networks/'+r['Id']);nets.pop()
            r=api('POST','/networks/create',{'Name':n,'Driver':'bridge','Internal':True,
                 'IPAM':ipam,'Labels':{'tu1nz.offline':prefix}})
            nets.append((n,r['Id']))
        name=prefix+'-original'
        body={'Image':IMAGE,'User':'20001:20001',
              'Entrypoint':['python'],'Cmd':['-I','-B','-c','import time;time.sleep(240)'],
              'HostConfig':{'NetworkMode':nets[1][0],'Memory':134217728,'NanoCpus':500000000,
                            'PidsLimit':64,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
                            'ReadonlyRootfs':True,'RestartPolicy':{'Name':'no'}},
              'NetworkingConfig':{'EndpointsConfig':{nets[1][0]:{'Aliases':[name,name]}}}}
        cid=api('POST','/containers/create?name='+name,body)['Id'];containers.append(cid)
        api('POST','/networks/'+nets[0][1]+'/connect',{'Container':cid,'EndpointConfig':{'Aliases':[]}})
        api('POST','/containers/'+cid+'/start')
        before=api('GET','/containers/'+cid+'/json')
        assert len(endpoints(before))==2 and not before['Mounts'] and not before['HostConfig']['PortBindings']
        api('POST','/containers/'+cid+'/stop?t=2')
        for n,netid in nets:
            api('POST','/networks/'+netid+'/disconnect',{'Container':cid,'Force':False})
        for n,netid in nets:
            e=endpoints(before)[n]
            # Preserve original dynamic IPAMConfig; top-level IPAddress is
            # deliberately tested rather than assumed to pin the allocation.
            config={k:e.get(k) for k in ('Aliases','MacAddress','DriverOpts','GwPriority','IPAMConfig','IPAddress')}
            api('POST','/networks/'+netid+'/connect',{'Container':cid,'EndpointConfig':config})
        api('POST','/containers/'+cid+'/start')
        after=api('GET','/containers/'+cid+'/json')
        delta={n:{k:{'before':stable(endpoints(before)[n])[k],'after':stable(endpoints(after)[n])[k]}
                  for k in stable(endpoints(before)[n]) if stable(endpoints(before)[n])[k]!=stable(endpoints(after)[n])[k]}
               for n,_ in nets}
        report.append({'case':'disconnect_reconnect_original_dynamic_endpoints','delta':delta,
                       'pass':not any(delta.values())})
        print(json.dumps({'case_result':report[-1]}),flush=True)
        api('POST','/containers/'+cid+'/stop?t=2')
        for n,netid in nets:api('POST','/networks/'+netid+'/disconnect',{'Container':cid,'Force':False})
        # Independent recreation, first retaining dynamic IPAM configuration.
        recreation=json.loads(json.dumps(body))
        recreation['NetworkingConfig']['EndpointsConfig']={
            n:{k:endpoints(before)[n].get(k) for k in ('Aliases','MacAddress','DriverOpts','GwPriority','IPAMConfig','IPAddress')}
            for n,_ in nets}
        other=api('POST','/containers/create?name='+prefix+'-recreated',recreation)['Id'];containers.append(other)
        api('POST','/containers/'+other+'/start')
        recreated=api('GET','/containers/'+other+'/json')
        delta={n:{k:{'before':stable(endpoints(before)[n])[k],'after':stable(endpoints(recreated)[n])[k]}
                  for k in stable(endpoints(before)[n]) if stable(endpoints(before)[n])[k]!=stable(endpoints(recreated)[n])[k]}
               for n,_ in nets}
        report.append({'case':'recreate_all_endpoints_dynamic_ipam','delta':delta,'pass':not any(delta.values())})
        print(json.dumps({'case_result':report[-1]}),flush=True)
        api('DELETE','/containers/'+other+'?force=1');containers.remove(other)
        # A separate harmless sleeper takes the just-freed addresses: models
        # concurrent allocation without touching any production endpoint.
        contender=json.loads(json.dumps(body));contender['NetworkingConfig']['EndpointsConfig']={
            n:{'Aliases':[]} for n,_ in nets}
        occupied=api('POST','/containers/create?name='+prefix+'-contender',contender)['Id'];containers.append(occupied)
        api('POST','/containers/'+occupied+'/start')
        other=api('POST','/containers/create?name='+prefix+'-recreated-race',recreation)['Id'];containers.append(other)
        api('POST','/containers/'+other+'/start')
        raced=api('GET','/containers/'+other+'/json')
        delta={n:{k:{'before':stable(endpoints(before)[n])[k],'after':stable(endpoints(raced)[n])[k]}
                  for k in stable(endpoints(before)[n]) if stable(endpoints(before)[n])[k]!=stable(endpoints(raced)[n])[k]}
               for n,_ in nets}
        report.append({'case':'dynamic_ipam_with_competing_allocation','delta':delta,'pass':not any(delta.values())})
        print(json.dumps({'case_result':report[-1]}),flush=True)
        api('DELETE','/containers/'+other+'?force=1');containers.remove(other)
        api('DELETE','/containers/'+occupied+'?force=1');containers.remove(occupied)
        # Static binding preserves the observed address but changes the
        # original IPAM configuration. Record that difference; never waive it.
        for n,_ in nets:recreation['NetworkingConfig']['EndpointsConfig'][n]['IPAMConfig']={'IPv4Address':endpoints(before)[n]['IPAddress']}
        other=api('POST','/containers/create?name='+prefix+'-static',recreation)['Id'];containers.append(other)
        api('POST','/containers/'+other+'/start')
        pinned=api('GET','/containers/'+other+'/json')
        delta={n:{k:{'before':stable(endpoints(before)[n])[k],'after':stable(endpoints(pinned)[n])[k]}
                  for k in stable(endpoints(before)[n]) if stable(endpoints(before)[n])[k]!=stable(endpoints(pinned)[n])[k]}
               for n,_ in nets}
        report.append({'case':'static_ipam_pinning','delta':delta,'pass':not any(delta.values())})
        print(json.dumps({'case_result':report[-1]}),flush=True)
        print(json.dumps({'experiment':report,'production_networks_used':False,'external_access':False},sort_keys=True))
    finally:
        for cid in reversed(containers):api('DELETE','/containers/'+cid+'?force=1')
        for _,nid in reversed(nets):api('DELETE','/networks/'+nid)

if __name__=='__main__':main()
