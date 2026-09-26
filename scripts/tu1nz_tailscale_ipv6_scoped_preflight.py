#!/usr/bin/python3
"""Protected snapshot + isolated netns tests. NO live activation path."""
import os, sys, json, pathlib, subprocess, socket, hashlib, stat, datetime
P=pathlib.Path
BASE=P('/opt/tu1nz_repos/network-hardening-private-2026-09-22/ipv6-scoped-20260926T065529Z')
TARGET=P('/proc/sys/net/ipv6/conf/tailscale0/disable_ipv6')
def run(args, timeout=30, check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode: raise RuntimeError('command failed: '+repr(args)+' rc='+str(p.returncode))
    return {'args':args,'rc':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def flags():
    return {p.parent.name:p.read_text().strip() for p in P('/proc/sys/net/ipv6/conf').glob('*/disable_ipv6')}
def interface_write(name,value):
    if name != 'tailscale0' or type(value) is not int or value not in (0,1): raise ValueError('scope rejected')
    if not P('/sys/class/net/tailscale0').exists() or not TARGET.is_file(): raise RuntimeError('tailscale0 absent')
    TARGET.write_text(str(value)+'\n')
def netstate():
    return {k:json.loads(run(a)['stdout']) for k,a in {
        'links':['ip','-j','link','show'], 'addr4':['ip','-j','-4','addr','show'],
        'addr6':['ip','-j','-6','addr','show'], 'route4':['ip','-j','-4','route','show','table','all'],
        'route6':['ip','-j','-6','route','show','table','all'], 'rule4':['ip','-j','-4','rule','show'],
        'rule6':['ip','-j','-6','rule','show']}.items()}
def normalized_interface():
    a=json.loads(run(['ip','-j','-6','addr','show','dev','tailscale0'])['stdout'])
    r=json.loads(run(['ip','-j','-6','route','show','table','all','dev','tailscale0'])['stdout'])
    return {'flag':TARGET.read_text().strip(),'addresses':a,'routes':r}
def isolated():
    assert os.readlink('/proc/self/ns/net') != os.environ['TU1NZ_HOST_NS'], 'not isolated'
    start=flags(); assert 'tailscale0' not in start
    # This loopback change exists ONLY inside the disposable network namespace.
    run(['ip','link','set','lo','up'])
    run(['ip','link','add','tailscale0','type','dummy'])
    run(['ip','link','set','tailscale0','up'])
    interface_write('tailscale0',1)
    baseline=normalized_interface(); others={k:v for k,v in flags().items() if k!='tailscale0'}
    rejected=[]
    for bad in ['all','default','eth0','lo','docker0','br-test','*','tailscale*','../all','tailscale0/../all','tailscale0\n']:
        before=flags()
        try: interface_write(bad,0)
        except ValueError: rejected.append(bad)
        else: raise AssertionError('unsafe target accepted')
        assert flags()==before
    for bad in [True,False,'0',2,-1]:
        try: interface_write('tailscale0',bad)
        except ValueError: pass
        else: raise AssertionError('bad value accepted')
    trial=BASE/'offline-files'; trial.mkdir(mode=0o700)
    original=trial/'existing'; original.write_bytes(b'unchanged reference\n'); original.chmod(0o600)
    orig=(original.read_bytes(),stat.S_IMODE(original.stat().st_mode))
    new=trial/'new-hook'; assert not new.exists(); new.write_bytes(b'isolated test artifact\n'); new.chmod(0o600)
    try:
        interface_write('tailscale0',0); interface_write('tailscale0',0)
        assert {k:v for k,v in flags().items() if k!='tailscale0'}==others
        # Explicit test address/route only in isolated netns, NEVER in live path.
        run(['ip','-6','addr','add','fd00:7455:1::1/128','dev','tailscale0','nodad'])
        run(['ip','-6','route','add','fd00:7455:2::/64','dev','tailscale0'])
        route=run(['ip','-j','-6','route','get','fd00:7455:2::1'])
        assert json.loads(route['stdout'])[0]['dev']=='tailscale0'
        with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as srv:
            srv.settimeout(2);srv.bind(('fd00:7455:1::1',0));srv.listen(1)
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as client:
                client.settimeout(2);client.connect(srv.getsockname());client.sendall(b'namespace-check')
                conn,_=srv.accept()
                with conn:
                    conn.settimeout(2);assert conn.recv(64)==b'namespace-check'
        assert {k:v for k,v in flags().items() if k!='tailscale0'}==others
    finally:
        interface_write('tailscale0',1)
        assert new.read_bytes()==b'isolated test artifact\n';new.unlink()
    assert normalized_interface()==baseline,'interface rollback mismatch'
    assert (original.read_bytes(),stat.S_IMODE(original.stat().st_mode))==orig
    assert not new.exists()
    assert {k:v for k,v in flags().items() if k!='tailscale0'}==others
    run(['ip','link','delete','tailscale0'])
    try:interface_write('tailscale0',0)
    except RuntimeError:pass
    else:raise AssertionError('missing interface accepted')
    print(json.dumps({'isolated':True,'idempotent':True,'tcp':True,'route':True,'rollback_exact':True,'other_flags_unchanged':True,'negative_targets_rejected':rejected,'missing_interface_rejected':True,'test_scope':'Kernel mechanics only; does NOT prove tailscaled IPv6 support or live address adoption.'}))
def main():
    assert os.geteuid()==0
    if '--isolated' in sys.argv:return isolated()
    assert len(sys.argv)==1,'no activation mode exists'
    os.umask(0o077)
    uid=int(os.environ.get('SUDO_UID','1001'));gid=int(os.environ.get('SUDO_GID','1001'))
    out=BASE/'evidence';out.mkdir(mode=0o700)
    def save(name,data):
        p=out/name
        with p.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
        p.chmod(0o600);os.chown(p,uid,gid)
    def capture(name,args,timeout=30):
        r=run(args,timeout=timeout);save(name,r);return r
    beforeflags=flags();beforestate=netstate();save('host-flags-before.json',beforeflags);save('host-net-before.json',beforestate)
    commands={
        'tailscale-status.json':['tailscale','status','--json'],
        'tailscale-prefs.json':['tailscale','debug','prefs'],
        'tailscale-version.json':['tailscale','version'],
        'tailscaled-unit.json':['systemctl','cat','tailscaled'],
        'tailscaled-properties.json':['systemctl','show','tailscaled','-p','FragmentPath','-p','DropInPaths','-p','ExecStart','-p','MainPID'],
        'nft.json':['nft','-a','list','ruleset'],
        'iptables.json':['iptables-save'], 'ip6tables.json':['ip6tables-save'],
        'ufw.json':['ufw','status','verbose'],
        'listeners.json':['ss','-H','-lntup'],
        'docker-networks.json':['docker','network','ls','--no-trunc'],
        'docker-ps.json':['docker','ps','--no-trunc','--format','{{json .}}'],
        'fail2ban.json':['fail2ban-client','status','sshd']}
    for name,args in commands.items():capture(name,args)
    ids=run(['docker','network','ls','-q'])['stdout'].split()
    if ids:capture('docker-network-details.json',['docker','network','inspect',*ids])
    ids=run(['docker','ps','-aq'])['stdout'].split()
    if ids:capture('docker-state.json',['docker','inspect','--format','{{json .Id}} {{json .Name}} {{json .State}} {{json .RestartCount}} {{json .NetworkSettings.Networks}} {{json .HostConfig.PortBindings}}',*ids])
    paths={P('/etc/sysctl.conf'),P('/etc/default/ufw')}
    for d,pat in [('/etc/sysctl.d','*.conf'),('/run/sysctl.d','*.conf'),('/usr/lib/sysctl.d','*.conf'),('/lib/sysctl.d','*.conf'),('/etc/ufw','*.rules'),('/etc/systemd/system/tailscaled.service.d','*.conf')]:
        paths.update(P(d).glob(pat))
    fragment=run(['systemctl','show','tailscaled','-p','FragmentPath','--value'])['stdout'].strip()
    if fragment:paths.add(P(fragment))
    store=out/'files';store.mkdir(mode=0o700);metadata=[]
    for p in sorted(paths):
        if not p.exists():continue
        raw=p.read_bytes();s=p.stat();dest=store/(str(p).lstrip('/').replace('/','__'))
        with dest.open('xb') as f:f.write(raw)
        dest.chmod(0o600);os.chown(dest,uid,gid)
        metadata.append({'path':str(p),'resolved':str(p.resolve()),'link':os.readlink(p) if p.is_symlink() else None,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'sha256':hashlib.sha256(raw).hexdigest(),'backup':dest.name})
    save('file-metadata.json',metadata)
    env=dict(os.environ,TU1NZ_HOST_NS=os.readlink('/proc/self/ns/net'))
    p=subprocess.run(['unshare','--net','--',sys.executable,str(P(__file__).resolve()),'--isolated'],capture_output=True,text=True,timeout=30,env=env)
    save('isolated-test.json',{'rc':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    afterflags=flags();afterstate=netstate();save('host-flags-after.json',afterflags);save('host-net-after.json',afterstate)
    unchanged=(beforeflags==afterflags and beforestate==afterstate)
    save('result.json',{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'namespace_pass':p.returncode==0,'host_network_exactly_unchanged':unchanged,'live_activated':False})
    sums={str(f.relative_to(out)):hashlib.sha256(f.read_bytes()).hexdigest() for f in out.rglob('*') if f.is_file()}
    save('manifest.json',sums)
    for d in [store,out]:os.chown(d,uid,gid)
    if p.returncode or not unchanged:raise RuntimeError('PREFLIGHT FAILED; no live activation; inspect protected result')
    print('PREFLIGHT PASS: isolated rollback, TCP, route, negative tests; host network unchanged; NO LIVE ACTIVATION')
if __name__=='__main__':main()
