"""macOS Security.framework storage; no secret subprocess arguments or output."""
import ctypes as C, json, sys
SERVICE=b'TU1NZ temporary Tailnet policy rollback'
ACCOUNT=b'phase5-2026-09-26'
class KeychainError(Exception):pass
class Keychain:
 def __init__(self):
  if sys.platform!='darwin':raise KeychainError('macOS required')
  self.s=C.CDLL('/System/Library/Frameworks/Security.framework/Security');self.cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
  self.s.SecKeychainAddGenericPassword.argtypes=[C.c_void_p,C.c_uint32,C.c_char_p,C.c_uint32,C.c_char_p,C.c_uint32,C.c_void_p,C.POINTER(C.c_void_p)];self.s.SecKeychainAddGenericPassword.restype=C.c_int32
  self.s.SecKeychainFindGenericPassword.argtypes=[C.c_void_p,C.c_uint32,C.c_char_p,C.c_uint32,C.c_char_p,C.POINTER(C.c_uint32),C.POINTER(C.c_void_p),C.POINTER(C.c_void_p)];self.s.SecKeychainFindGenericPassword.restype=C.c_int32
  self.s.SecKeychainItemFreeContent.argtypes=[C.c_void_p,C.c_void_p];self.s.SecKeychainItemDelete.argtypes=[C.c_void_p];self.s.SecKeychainItemDelete.restype=C.c_int32
  self.cf.CFRelease.argtypes=[C.c_void_p]
 def put(self,value,account=ACCOUNT):
  raw=json.dumps(value).encode();buf=C.create_string_buffer(raw)
  rc=self.s.SecKeychainAddGenericPassword(None,len(SERVICE),SERVICE,len(account),account,len(raw),buf,None)
  C.memset(buf,0,len(raw))
  if rc:raise KeychainError('keychain add failed code '+str(rc))
 def get(self,account=ACCOUNT):
  n=C.c_uint32();data=C.c_void_p()
  rc=self.s.SecKeychainFindGenericPassword(None,len(SERVICE),SERVICE,len(account),account,C.byref(n),C.byref(data),None)
  if rc:raise KeychainError('keychain read failed code '+str(rc))
  try:return json.loads(C.string_at(data,n.value))
  finally:self.s.SecKeychainItemFreeContent(None,data)
 def delete(self,account=ACCOUNT):
  item=C.c_void_p();rc=self.s.SecKeychainFindGenericPassword(None,len(SERVICE),SERVICE,len(account),account,None,None,C.byref(item))
  if rc==-25300:return
  if rc:raise KeychainError('keychain locate failed code '+str(rc))
  try:
   rc=self.s.SecKeychainItemDelete(item)
   if rc:raise KeychainError('keychain delete failed code '+str(rc))
  finally:self.cf.CFRelease(item)
