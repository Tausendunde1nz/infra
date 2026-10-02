"""Hash-bound semantic regression checks for the reviewed Control governance delta.
Run against an isolated archive of Control 05b1270. This is not a prose-policy
inference engine: a future document revision requires a new semantic review.
"""
import hashlib,json,sys
from pathlib import Path
PINS={
'SUPERSEDED.md':'fa6356627afe1c83bfe568938f173eb0531baf707a674428b04d1445f17050e1',
'chatgpt-project-instructions-v1.1.txt':'74dc46002098263bd2e9cd5d32a85539e6298cd9b051e5f9056a4f9badfff7fa',
'efficiency-standard-v1.1.md':'183b768a6bc8ff83ecd1679af09c878b692c7ee9a0ebf3257eaf6bf22ff07c90',
'operative-policy-v1.1.md':'83506c27c6adc4fce97cf9faa0c4a4d60dbe15380fc473c1d4ae4d746554423c'}
def verify(root):
 texts={}
 for name,pin in PINS.items():
  p=Path(root)/'governance'/name
  if p.is_symlink() or not p.is_file():raise ValueError('GOVERNANCE_TYPE')
  raw=p.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('SEMANTIC_REVIEW_INVALIDATED')
  texts[name]=raw.decode('utf-8')
 e=texts['efficiency-standard-v1.1.md'];o=texts['operative-policy-v1.1.md'];s=texts['SUPERSEDED.md'];c=texts['chatgpt-project-instructions-v1.1.txt']
 checks={
 'sole_operational_authority':'Diese Datei ist die operative SSOT' in e and 'historical evidence only' in o,
 'no_microgates':'Keine wiederholten Freigaben' in e and 'no artificial micro-gates' in o,
 'safety_preserved':all(x in e for x in ['Backup, Rollback, Pfad-/Rechteprüfung, Health/Validierung, SSOT, Versionierung, No-Delete, VPN, Secrets-Schutz und autorisierte Schreibpfade','Effizienz darf niemals zulasten von Sicherheit']),
 'history_preserved':'originals remain unchanged under No-Delete' in s,
 'compression_not_evidence_loss':'Details nur bei Abweichung' in e and 'explicit evidence requirements' in o,
 'no_automatic_pdf':'No automatic PDF/report creation' in o,
 'one_module':'no parallel operations' in o,
 'runtime_and_secrets_protected':'Keine Secrets, keine unautorisierte Runtime-Aktivierung' in c}
 if not all(checks.values()):raise ValueError('GOVERNANCE_SEMANTIC_REGRESSION')
 return checks
if __name__=='__main__':
 checks=verify(sys.argv[1]);print(json.dumps({'governance_checks':len(checks),'passed':all(checks.values())}))
