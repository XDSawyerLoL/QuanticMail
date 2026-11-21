//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -ladvapi32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdint.h>
#include <wchar.h>

static PTOKEN_USER qv_user(void) {
 HANDLE token = NULL;
 DWORD n = 0;
 PTOKEN_USER u = NULL;
 if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
 GetTokenInformation(token, TokenUser, NULL, 0, &n);
 if (n > 0 && n <= 65536) {
  u = (PTOKEN_USER)LocalAlloc(LPTR, n);
  if (u && !GetTokenInformation(token, TokenUser, u, n, &n)) {
   LocalFree(u); u = NULL;
  }
 }
 CloseHandle(token);
 return u;
}

static int qv_private(HANDLE h) {
 PTOKEN_USER u = qv_user();
 if (!u) return 0;
 PSID owner = NULL, system = NULL;
 PACL dacl = NULL;
 PSECURITY_DESCRIPTOR sd = NULL;
 SECURITY_DESCRIPTOR_CONTROL control = 0;
 DWORD revision = 0;
 ACL_SIZE_INFORMATION ai;
 int seen_user = 0, seen_system = 0, ok = 0;
 if (!ConvertStringSidToSidW(L"S-1-5-18", &system)) goto done;
 if (GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
     &owner, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS) goto done;
 if (!owner || !EqualSid(owner,u->User.Sid) || !dacl ||
     !GetSecurityDescriptorControl(sd,&control,&revision) ||
     !(control & SE_DACL_PROTECTED) ||
     !GetAclInformation(dacl,&ai,sizeof(ai),AclSizeInformation) ||
     ai.AceCount != 2) goto done;
 for (DWORD i=0; i<ai.AceCount; i++) {
  ACCESS_ALLOWED_ACE *ace = NULL;
  if (!GetAce(dacl,i,(LPVOID*)&ace) || ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE ||
      ace->Header.AceFlags != 0 ||
      (ace->Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS) goto done;
  PSID sid=(PSID)&ace->SidStart;
  if (!IsValidSid(sid)) goto done;
  if (EqualSid(sid,u->User.Sid)) seen_user++;
  else if (EqualSid(sid,system)) seen_system++;
  else goto done;
 }
 ok = seen_user==1 && seen_system==1;
done:
 if (sd) LocalFree(sd);
 if (system) LocalFree(system);
 LocalFree(u);
 return ok;
}

static PSECURITY_DESCRIPTOR qv_descriptor(void) {
 PTOKEN_USER u=qv_user();
 if (!u) return NULL;
 LPWSTR sid=NULL;
 PSECURITY_DESCRIPTOR sd=NULL;
 WCHAR buf[512];
 if (ConvertSidToStringSidW(u->User.Sid,&sid)) {
  if (wcslen(sid)<180) {
   wcscpy(buf,L"O:"); wcscat(buf,sid);
   wcscat(buf,L"D:P(A;;FA;;;"); wcscat(buf,sid);
   wcscat(buf,L")(A;;FA;;;SY)");
   ConvertStringSecurityDescriptorToSecurityDescriptorW(buf,SDDL_REVISION_1,&sd,NULL);
  }
  LocalFree(sid);
 }
 LocalFree(u);
 return sd;
}

static int qv_ntfs(const WCHAR *root) {
 WCHAR fs[32];
 return GetDriveTypeW(root)==DRIVE_FIXED &&
  GetVolumeInformationW(root,NULL,0,NULL,NULL,NULL,fs,32) &&
  lstrcmpiW(fs,L"NTFS")==0;
}
static int qv_type(HANDLE h,int directory) {
 BY_HANDLE_FILE_INFORMATION i;
 if (GetFileType(h)!=FILE_TYPE_DISK || !GetFileInformationByHandle(h,&i)) return 0;
 if (i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return 0;
 if (!!(i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != !!directory) return 0;
 return directory || i.nNumberOfLinks==1;
}
static uintptr_t qv_dir(const WCHAR *path,int private) {
 HANDLE h=CreateFileW(path,FILE_READ_ATTRIBUTES | (private?READ_CONTROL:0),
  FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,
  FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
 if (h==INVALID_HANDLE_VALUE) return 0;
 if (!qv_type(h,1) || (private && !qv_private(h))) {CloseHandle(h);return 0;}
 return (uintptr_t)h;
}
static int qv_mkdir(const WCHAR *path) {
 PSECURITY_DESCRIPTOR sd=qv_descriptor();
 if (!sd) return 0;
 SECURITY_ATTRIBUTES sa={sizeof(sa),sd,FALSE};
 int ok=CreateDirectoryW(path,&sa);
 LocalFree(sd);return ok;
}
static uintptr_t qv_file(const WCHAR *path,int mode) {
 int create=mode==1, write=mode!=0;
 PSECURITY_DESCRIPTOR sd=create?qv_descriptor():NULL;
 if (create && !sd) return 0;
 SECURITY_ATTRIBUTES sa={sizeof(sa),sd,FALSE};
 HANDLE h=CreateFileW(path,READ_CONTROL|FILE_READ_ATTRIBUTES|(write?(GENERIC_READ|GENERIC_WRITE):GENERIC_READ),
  0,create?&sa:NULL,create?CREATE_NEW:OPEN_EXISTING,
  FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|(write?FILE_FLAG_WRITE_THROUGH:0),NULL);
 if(sd) LocalFree(sd);
 if(h==INVALID_HANDLE_VALUE) return 0;
 if(!qv_type(h,0)||!qv_private(h)){CloseHandle(h);return 0;}
 return (uintptr_t)h;
}
*/
import "C"

import (
 "errors"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "syscall"
 "unsafe"
)

var windowsPathComponent = regexp.MustCompile("^[A-Za-z0-9_ .-]+$")
var windowsReserved = regexp.MustCompile("^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$")
var windowsStorageRefusal = errors.New("Windows private NTFS storage refused")

// Restrict the lab to canonical local DOS paths; no UNC, device paths, ADS,
// short-name/reparse escape, ambiguous suffix or reserved DOS name.
func winPathParts(path string)(string,[]string,error){
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path||len(path)>240||len(path)<4||path[1:3]!=":\\"||!strings.Contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",path[:1]){
  return "",nil,windowsStorageRefusal
 }
 parts:=strings.Split(path[3:],"\\")
 for _,p:=range parts{
  if !windowsPathComponent.MatchString(p)||strings.HasSuffix(p,".")||strings.HasSuffix(p," ")||p=="."||p==".."||windowsReserved.MatchString(strings.ToUpper(strings.TrimSpace(strings.SplitN(p,".",2)[0]))){
   return "",nil,windowsStorageRefusal
  }
 }
 return path[:3],parts,nil
}
func winWide(s string)*C.WCHAR{
 p,e:=syscall.UTF16PtrFromString(s)
 if e!=nil{return nil}
 return (*C.WCHAR)(unsafe.Pointer(p))
}
func winClose(hs []syscall.Handle){for i:=len(hs)-1;i>=0;i--{syscall.CloseHandle(hs[i])}}

// Keep all traversed directories open without delete sharing for the duration
// of a file operation. Reparse points on any path segment are refused.
func winLockDirectory(path string,private bool)([]syscall.Handle,error){
 root,parts,e:=winPathParts(path)
 if e!=nil||C.qv_ntfs(winWide(root))==0{return nil,windowsStorageRefusal}
 var hs []syscall.Handle
 ok:=false
 defer func(){if !ok{winClose(hs)}}()
 h:=C.qv_dir(winWide(root),0)
 if h==0{return nil,windowsStorageRefusal};hs=append(hs,syscall.Handle(h))
 cur:=root
 for i,p:=range parts{
  cur=filepath.Join(cur,p);flag:=C.int(0)
  if private&&i==len(parts)-1{flag=1}
  h=C.qv_dir(winWide(cur),flag)
  if h==0{return nil,windowsStorageRefusal}
  hs=append(hs,syscall.Handle(h))
 }
 ok=true;return hs,nil
}
func winCreatePrivateDirectory(path string)error{
 if _,_,e:=winPathParts(path);e!=nil{return e}
 hs,e:=winLockDirectory(filepath.Dir(path),false);if e!=nil{return e};defer winClose(hs)
 if C.qv_mkdir(winWide(path))==0{return windowsStorageRefusal}
 inner,e:=winLockDirectory(path,true);if e!=nil{return e};winClose(inner)
 return nil
}
func winOpenPrivate(path string,write bool)(*os.File,[]syscall.Handle,error){
 mode:=0;if write{mode=1};return winOpenPrivateMode(path,mode)
}
func winOpenPrivateMode(path string,mode int)(*os.File,[]syscall.Handle,error){
 if mode<0||mode>2{return nil,nil,windowsStorageRefusal}
 if _,_,e:=winPathParts(path);e!=nil{return nil,nil,e}
 hs,e:=winLockDirectory(filepath.Dir(path),true);if e!=nil{return nil,nil,e}
 h:=C.qv_file(winWide(path),C.int(mode));if h==0{winClose(hs);return nil,nil,windowsStorageRefusal}
 f:=os.NewFile(uintptr(h),path)
 if f==nil{syscall.CloseHandle(syscall.Handle(h));winClose(hs);return nil,nil,windowsStorageRefusal}
 return f,hs,nil
}
func winWritePrivate(path string,b []byte)error{
 if len(b)==0||len(b)>131072{return windowsStorageRefusal}
 f,hs,e:=winOpenPrivate(path,true);if e!=nil{return e};defer winClose(hs)
 n,e:=f.Write(b);if e==nil&&n!=len(b){e=io.ErrShortWrite}
 if e==nil{e=f.Sync()};ce:=f.Close();if e==nil{e=ce};return e
}
func winReadPrivate(path string,max int)([]byte,error){
 if max<1||max>131072{return nil,windowsStorageRefusal}
 f,hs,e:=winOpenPrivate(path,false);if e!=nil{return nil,e};defer winClose(hs);defer f.Close()
 s,e:=f.Stat();if e!=nil||!s.Mode().IsRegular()||s.Size()<1||s.Size()>int64(max){return nil,windowsStorageRefusal}
 b,e:=io.ReadAll(io.LimitReader(f,int64(max+1)));if e!=nil||len(b)>max||int64(len(b))!=s.Size(){clear(b);return nil,windowsStorageRefusal}
 return b,nil
}

// Use exactly the existing Linux encrypted classical and PQ sidecar formats.
// These are storage primitives only: no broker, journal, UI or production cutover.
func winWriteClassical(path,magic string,pw []byte,k portableKeys)error{
 b,e:=encryptPortableMode(k,pw,magic);if e!=nil{return e};defer clear(b);return winWritePrivate(path,b)
}
func winReadClassical(path,magic string,pw []byte,signPin,encPin string)(portableKeys,error){
 b,e:=winReadPrivate(path,len(magic)+16+12+64+16);if e!=nil{return portableKeys{},e};defer clear(b)
 k,e:=decryptPortableMode(b,pw,magic);if e!=nil{return portableKeys{},e};s,a:=portablePins(k)
 if s!=signPin||a!=encPin{return portableKeys{},portableRefusal};return k,nil
}
func winWritePQ(path,magic string,pw []byte,p *pqKeys)error{
 b,e:=encodePQStorage(magic,pw,p);if e!=nil{return e};defer clear(b);return winWritePrivate(path,b)
}
func winReadPQ(path,magic string,pw []byte,addr,device,kemPin,dsaPin string)(*pqKeys,error){
 b,e:=winReadPrivate(path,50000);if e!=nil{return nil,e};defer clear(b);return decodePQStorage(b,magic,pw,addr,device,kemPin,dsaPin)
}
