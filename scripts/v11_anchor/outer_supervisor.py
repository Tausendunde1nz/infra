"""Independent parent-death/monotonic-timeout cleanup supervisor.

No PID from a journal is signalled. The guardian retains a pidfd obtained
before fork, owns its own session, and restores only the literal test scope.
"""
import os,signal,select,time,json,stat,socket,array
from pathlib import Path
from anchor import Refused,encode,digest,parse

ACTIVE_CHANNEL=None

def register(process):
 if ACTIVE_CHANNEL is None:raise Refused('WORKER_SUPERVISOR_ABSENT')
 fd=os.pidfd_open(process.pid,0)
 previous=ACTIVE_CHANNEL.gettimeout();ACTIVE_CHANNEL.settimeout(10)
 try:
  ACTIVE_CHANNEL.sendmsg([b'R'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
  if ACTIVE_CHANNEL.recv(1)!=b'A':raise Refused('WORKER_REGISTRATION_FAILED')
 finally:ACTIVE_CHANNEL.settimeout(previous);os.close(fd)

def supervise(run,restore,seconds=1200):
 if type(seconds)!=int or not 1<=seconds<=1200:raise Refused('SUPERVISOR_DEADLINE')
 global ACTIVE_CHANNEL
 if ACTIVE_CHANNEL is not None:raise Refused('SUPERVISOR_REENTRY')
 parent_channel,child_channel=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);done_r,done_w=os.pipe();parent=os.getpid();pidfd=os.pidfd_open(parent,0)
 guardian=os.fork()
 if guardian==0:
  parent_channel.close();os.close(done_r);os.setsid();workers=[];groups=[];deadline=time.monotonic_ns()+seconds*1_000_000_000
  reason='PARENT_EXIT';ok=False
  try:
   while True:
    remaining=max(0,(deadline-time.monotonic_ns())/1_000_000_000)
    ready,_,_=select.select([child_channel,pidfd],[],[],min(remaining,1))
    if child_channel in ready:
     command,ancillary,flags,_=child_channel.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
     if flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC):raise Refused('SUPERVISOR_PROTOCOL')
     if command==b'R':
      if len(ancillary)!=1 or ancillary[0][:2]!=(socket.SOL_SOCKET,socket.SCM_RIGHTS):raise Refused('SUPERVISOR_PROTOCOL')
      fds=array.array('i');fds.frombytes(ancillary[0][2])
      if len(fds)!=1 or len(workers)>64:raise Refused('SUPERVISOR_PROTOCOL')
      fd=fds[0]
      info=Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines()
      ids=[x.split(':',1)[1].strip() for x in info if x.startswith('Pid:')]
      if len(ids)!=1 or not ids[0].isdecimal():raise Refused('PIDFD_IDENTITY')
      pid=int(ids[0]);workers.append(fd)
      if os.getpgid(pid)!=pid or os.getsid(pid)!=pid:raise Refused('WORKER_PRIVATE_SESSION')
      groups.append(pid);child_channel.send(b'A');continue
     if ancillary:raise Refused('SUPERVISOR_PROTOCOL')
     if command==b'C':reason='CONTROLLER_COMPLETE';break
     if not command:break
     raise Refused('SUPERVISOR_PROTOCOL')
    if pidfd in ready:break
    if time.monotonic_ns()>=deadline:
     reason='MONOTONIC_TIMEOUT'
     signal.pidfd_send_signal(pidfd,signal.SIGKILL)
     # Wait until no publisher can race the independent cleanup.
     seen,_,_=select.select([pidfd],[],[],10)
     if not seen:raise Refused('PUBLISHER_NOT_EXITED')
     break
   # Registered workers cannot race restoration after publisher death.
   from worker import group_members
   for fd,group in zip(workers,groups):
    if not select.select([fd],[],[],0)[0]:
     os.killpg(group,signal.SIGKILL)
    elif group_members(group):raise Refused('ORPHANED_WORKER_GROUP')
   for fd in workers:
    if not select.select([fd],[],[],10)[0]:raise Refused('WORKER_NOT_EXITED')
   result=restore(reason)
   ok=result is True
   os.write(done_w,b'P' if ok else b'F')
  except BaseException:
   try:os.write(done_w,b'F')
   except OSError:pass
  finally:
   # Even a supervisor protocol/restore failure kills registered live leaders.
   for fd in workers:
    try:
     if not select.select([fd],[],[],0)[0]:signal.pidfd_send_signal(fd,signal.SIGKILL)
    except OSError:pass
   child_channel.close()
   for f in (*workers,done_w,pidfd):os.close(f)
  os._exit(0 if ok else 1)
 child_channel.close();os.close(done_w);os.close(pidfd);ACTIVE_CHANNEL=parent_channel
 failure=None;value=None
 try:value=run()
 except BaseException as e:failure=e
 finally:
  parent_channel.send(b'C');parent_channel.close();ACTIVE_CHANNEL=None
  # Cleanup has an independent bound; retain guardian if it fails to finish.
  ready,_,_=select.select([done_r],[],[],120)
  token=os.read(done_r,1) if ready else b'';os.close(done_r)
  if ready:_,status=os.waitpid(guardian,0)
  else:status=None
 if token!=b'P' or status!=0:raise Refused('INDEPENDENT_CLEANUP_FAILED')
 if failure is not None:raise failure
 return value
