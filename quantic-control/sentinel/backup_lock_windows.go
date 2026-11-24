//go:build windows

package sentinel

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "syscall"
 "unsafe"
)

// BackupLock is an opt-in, temporary Windows share-deny-write/delete handle
// on one existing local backup file. It never modifies bytes or permissions.
// It is NOT a driver, a permanent lock, or a defense against an administrator.
// Closing the handle (including process exit) releases the restriction.
type BackupLock struct {
 mu sync.Mutex
 handle syscall.Handle
 path string
 identity BackupIdentity
}
type BackupIdentity struct{
 Path string
 Volume uint32
 IndexHigh uint32
 IndexLow uint32
}
func (b *BackupLock) Path()string{return b.path}
func (b *BackupLock) Identity()BackupIdentity{return b.identity}
const MaxBackupLocks=16

// LockBackupSet acquires only previously selected exact file identities.
// On any failure all newly acquired handles are closed.
func LockBackupSet(items []BackupIdentity)([]*BackupLock,error){
 if len(items)>MaxBackupLocks{return nil,errors.New("maximum 16 copies")}
 locks:=make([]*BackupLock,0,len(items))
 seen:=map[BackupIdentity]bool{}
 for _,id:=range items{
  l,err:=LockBackup(id.Path)
  if err==nil&&(l.Identity()!=id||seen[id]){
   _=l.Close()
   err=errors.New("identité de sauvegarde différente ou doublon")
  }
  if err!=nil{
   for _,held:=range locks{_ =held.Close()}
   return nil,err
  }
  seen[id]=true
  locks=append(locks,l)
 }
 return locks,nil
}
func (b *BackupLock) Close()error{
 b.mu.Lock();defer b.mu.Unlock()
 if b.handle==0{return nil}
 if err:=syscall.CloseHandle(b.handle);err!=nil{return err}
 b.handle=0
 return nil
}

// LockBackup opens an existing explicitly selected backup read-only and
// permits compatible readers only. Existing writers cause acquisition to
// fail; no process is killed, no security descriptor is changed.
func LockBackup(path string)(*BackupLock,error){
 if !filepath.IsAbs(path)||len(path)>32760||strings.ContainsRune(path,0){
  return nil,errors.New("chemin local absolu requis")
 }
 path=filepath.Clean(path)
 vol:=filepath.VolumeName(path)
 if len(vol)!=2||vol[1]!=':'||strings.Contains(path[2:],":")||strings.HasPrefix(path,"\\\\"){
  return nil,errors.New("seuls les fichiers locaux ordinaires sont acceptés")
 }
 // Restrict the feature to inactive backup/archive copies. Never use it
 // to lock programs, OS files, or a live Vault/database/journal.
 switch strings.ToLower(filepath.Ext(path)){
 case ".bak",".backup",".zip",".7z",".qvb":
 default:return nil,errors.New("sélectionnez une copie de sauvegarde (.bak, .backup, .zip, .7z, .qvb)")
 }
 root,err:=syscall.UTF16PtrFromString(vol+"\\")
 if err!=nil{return nil,err}
 k:=syscall.NewLazyDLL("kernel32.dll")
 drive,_,_:=k.NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(root)))
 if drive!=3{return nil,errors.New("disque local fixe requis")}
 // Windows may supply 8.3 names (for example in TEMP). Expand those
 // before comparing with the normalized handle path. Reject reparse
 // components before and after expansion; do not treat aliases as trust.
 if err:=checkBackupComponents(path);err!=nil{return nil,err}
 original,err:=syscall.UTF16PtrFromString(path)
 if err!=nil{return nil,err}
 long:=make([]uint16,32768)
 count,_,callErr:=k.NewProc("GetLongPathNameW").Call(uintptr(unsafe.Pointer(original)),uintptr(unsafe.Pointer(&long[0])),uintptr(len(long)))
 if count==0||count>=uintptr(len(long)){return nil,fmt.Errorf("chemin Windows non résolu : %v",callErr)}
 path=syscall.UTF16ToString(long[:count])
 if err:=checkBackupComponents(path);err!=nil{return nil,err}
 before,err:=os.Lstat(path)
 if err!=nil||!before.Mode().IsRegular()||before.Mode()&os.ModeSymlink!=0{
  return nil,errors.New("copie de sauvegarde ordinaire requise")
 }
 ptr,err:=syscall.UTF16PtrFromString(path)
 if err!=nil{return nil,err}
 // FILE_FLAG_OPEN_REPARSE_POINT prevents following a final reparse point.
 // Absence of FILE_SHARE_WRITE and FILE_SHARE_DELETE is the actual enforced
 // Windows protection; GENERIC_READ alone is not sufficient.
 h,err:=syscall.CreateFile(ptr,syscall.GENERIC_READ,syscall.FILE_SHARE_READ,nil,
  syscall.OPEN_EXISTING,0x00200000,0)
 if err!=nil{return nil,fmt.Errorf("verrou refusé (fichier peut-être en cours de modification) : %w",err)}
 accepted:=false
 defer func(){if !accepted{_ =syscall.CloseHandle(h)}}()
 var info syscall.ByHandleFileInformation
 if err=syscall.GetFileInformationByHandle(h,&info);err!=nil{return nil,err}
 if info.FileAttributes&(0x10|0x400)!=0{return nil,errors.New("dossier ou point de réanalyse refusé")}
 // Restrict to disk file handles and verify the resolved path is exactly the
 // expanded chosen path (reject parent junctions and unexpected targets).
 kind,_,_:=k.NewProc("GetFileType").Call(uintptr(h))
 if kind!=1{return nil,errors.New("fichier disque requis")}
 resolved:=make([]uint16,32768)
 n,_,e:=k.NewProc("GetFinalPathNameByHandleW").Call(uintptr(h),uintptr(unsafe.Pointer(&resolved[0])),uintptr(len(resolved)),0)
 if n==0||n>=uintptr(len(resolved)){return nil,fmt.Errorf("chemin du fichier non vérifié : %v",e)}
 actual:=strings.TrimPrefix(syscall.UTF16ToString(resolved[:n]),"\\\\?\\")
 if !strings.EqualFold(actual,path){return nil,fmt.Errorf("chemin résolu différent : verrou refusé (%q != %q)",actual,path)}
 accepted=true
 return &BackupLock{handle:h,path:path,identity:BackupIdentity{Path:path,Volume:info.VolumeSerialNumber,IndexHigh:info.FileIndexHigh,IndexLow:info.FileIndexLow}},nil
}


// Reject any reparse component on the selected path. This is a defensive
// preflight, not atomic ancestor custody against a hostile local administrator.
func checkBackupComponents(path string)error{
 for current:=path;;current=filepath.Dir(current){
  ptr,err:=syscall.UTF16PtrFromString(current)
  if err!=nil{return err}
  attrs,err:=syscall.GetFileAttributes(ptr)
  if err!=nil{return err}
  if attrs&0x400!=0{return errors.New("point de réanalyse refusé")}
  if filepath.Dir(current)==current{break}
 }
 return nil
}
