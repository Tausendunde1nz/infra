#!/usr/bin/python3
"""One sudo entry for fresh pre/post read-only network attestations."""
import pathlib,subprocess,os,json,time,hashlib
B=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-retry-20260923T185834Z')
SCRIPT=B.parent/'phase4-readonly.py'
assert os.geteuid()==0
assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest()=='a8c4208a1604bdadc0721a3cafc7a1a637e8b44905b42f7bb977991d4029ce84'
def valid_input_filters(nft):
 chains=[x['chain'] for x in nft['nftables'] if 'chain' in x and x['chain'].get('hook')=='input' and x['chain'].get('type')=='filter']
 return len(chains)==2 and {(x['family'],x['table'],x['name'],x['policy']) for x in chains}=={('ip','filter','INPUT','drop'),('ip6','filter','INPUT','drop')}
def capture(label):
 output=subprocess.check_output(['python3',str(SCRIPT)],stderr=subprocess.STDOUT,timeout=120).decode().strip()
 assert output.startswith('PHASE4_READONLY_COMPLETE ')
 p=pathlib.Path(output.split(' ',1)[1]);assert p.parent==B.parent
 for name,h in json.loads((p/'manifest.json').read_text()).items():assert hashlib.sha256((p/name).read_bytes()).hexdigest()==h
 nft=json.loads((p/'nft.json').read_text())
 assert valid_input_filters(nft), 'Unexpected INPUT filter chains or policy'
 assert (p/'fail2ban-port.txt').read_text().strip()=='2222'
 ssh=(p/'sshd.txt').read_text();assert 'port 2222\n' in ssh and 'allowusers chatops\n' in ssh and 'permitrootlogin no\n' in ssh
 f=B/(label+'.json')
 with f.open('x') as out:json.dump({'evidence':str(p),'default_drop':True,'fail2ban_2222':True,'sshd_chatops_only':True},out)
 os.chmod(f,0o600);os.chown(f,1001,1001)
 print(label,p,flush=True)
capture('PRE_PRIVILEGED')
print('WAITING_FOR_POST_CHECK — Konsole offen lassen.',flush=True)
end=time.monotonic()+1800
while time.monotonic()<end:
 if (B/'ABORT_PRIVILEGED').exists():raise SystemExit('Read-only checks aborted; no configuration changed')
 if (B/'CHECK_POST').exists():capture('POST_PRIVILEGED');raise SystemExit(0)
 time.sleep(2)
raise SystemExit('Read-only wait expired; no configuration changed')
