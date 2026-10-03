"""Non-root host fixture; no systemd calls, persistent action records."""
import os,sys,json
from pathlib import Path
from core import *
def main():
 root=Path(sys.argv[1]);point=sys.argv[2];boot=sys.argv[3]
 def inject(x):
  if x==point:os._exit(91)
 class Host:
  def verify_closed(self,s):
   if s.read('gate.json',0o600)!={'state':'CLOSED'}:raise Refused('OPEN')
  def validate_binding(self,b):
   if not binding_valid(b):raise Refused('BINDING')
  def quiesce(self):pass
  def step(self,step,b):
   # Real persistent receipt per action; repeated execution is idempotent.
   p=root/('action-'+step)
   if not p.exists():
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,raw({'step':step,'binding':b}));os.fsync(fd);os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
   if parse(p.read_bytes())!={'step':step,'binding':b}:raise Refused('ACTION_DRIFT')
   return sha(p.read_bytes())
  def verify_terminal(self,b):
   for step in STEPS:
    if parse((root/('action-'+step)).read_bytes())!={'step':step,'binding':b}:raise Refused('ACTION_MISSING')
   return sha(raw(b))
 s=Durable(root,fixture=True,inject=inject)
 try:print(Dispatcher(s,Host(),inject).run(boot));print('PERMIT',permit(s,Host()))
 finally:s.close()
if __name__=='__main__':main()
