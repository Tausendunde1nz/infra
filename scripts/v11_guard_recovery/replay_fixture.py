"""Non-root subprocess fixture. Systemd actions are explicitly modeled.
Real Store/Journal serialization and os._exit crashes; never a production adapter.
"""
import json,os,sys
from pathlib import Path
from state import Store,encode,digest,Refused
from preseal import Recovery,STEPS

def main():
 root=Path(sys.argv[1]);boot=sys.argv[2];point=sys.argv[3];bad=sys.argv[4]
 if os.geteuid()==0 or root.parent!=Path('/tmp') or not root.name.startswith('tu1nz-fence-test-'):raise Refused('FIXTURE')
 def write(name,value):
  p=root/name;tmp=root/(name+'.tmp')
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:os.write(fd,encode(value));os.fsync(fd)
  finally:os.close(fd)
  os.replace(tmp,p);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 class Model:
  def preseal_admitted(self):return True
  def close_preseal_fence(self):write('fixture-fence.json',{'closed':bad!='unconfirmed'})
  def preseal_fence_closed(self):return json.loads((root/'fixture-fence.json').read_bytes())['closed']
  def preseal_secured_stop(self):
   if not self.preseal_fence_closed():raise AssertionError('STOP_BEFORE_FENCE')
   write('fixture-stop.json',{'stopped':True})
  def preseal_step(self,step,binding,current_boot):
   if not self.preseal_fence_closed():raise AssertionError('OPEN_FENCE')
   if bad==step:raise RuntimeError('INJECTED_HOST_FAILURE')
   p=root/'fixture-completed.json';rows=json.loads(p.read_bytes()) if p.exists() else []
   if step not in rows:rows.append(step);write(p.name,rows)
   return {'verified':True,'sha256':digest(encode({'steps':rows,'binding':binding}))}
 def inject(event):
  if event==point:os._exit(91)
 store=Store(root,fixture=True,inject=inject)
 try:print(Recovery(store,Model(),inject).run(boot),flush=True)
 finally:store.close()
if __name__=='__main__':main()
