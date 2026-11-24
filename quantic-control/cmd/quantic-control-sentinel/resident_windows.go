//go:build windows

package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "time"
 "unsafe"

 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

const (
 residentVersion=1
 registryRunKey="Software\\Microsoft\\Windows\\CurrentVersion\\Run"
 registryValueName="QuanticSentinelUserAgent"
 residentFileName="quantic-sentinel.exe"
 residentStopEvent="Local\\QuanticSentinelStopV1"
 residentMutexName="Local\\QuanticSentinelUserAgentV1"
 errorAlreadyExists syscall.Errno=183
 eventModifyState=0x0002
 synchronize=0x00100000
)
var(
 advapi32=syscall.NewLazyDLL("advapi32.dll")
 regCreateKeyEx=advapi32.NewProc("RegCreateKeyExW")
 regSetValueEx=advapi32.NewProc("RegSetValueExW")
 regDeleteValue=advapi32.NewProc("RegDeleteValueW")
 residentKernel=syscall.NewLazyDLL("kernel32.dll")
 createMutex=residentKernel.NewProc("CreateMutexW")
 createNamedEvent=residentKernel.NewProc("CreateEventW")
 openNamedEvent=residentKernel.NewProc("OpenEventW")
 setNamedEvent=residentKernel.NewProc("SetEvent")
 closeWinHandle=residentKernel.NewProc("CloseHandle")
 waitWinObject=residentKernel.NewProc("WaitForSingleObject")
)

type installManifest struct{
 Version int `json:"version"`
 ExeHash string `json:"exe_sha256"`
 Root string `json:"monitored_root"`
}
func userInstallFolder()(string,error){
 cache,err:=os.UserCacheDir()
 if err!=nil{return "",err}
 if !filepath.IsAbs(cache){return "",errors.New("local application folder is not absolute")}
 return filepath.Join(cache,"QuanticSillage","Sentinel"),nil
}
func installExePath()(string,error){
 dir,err:=userInstallFolder();if err!=nil{return "",err}
 return filepath.Join(dir,residentFileName),nil
}
func installManifestPath()(string,error){
 dir,err:=userInstallFolder();if err!=nil{return "",err}
 return filepath.Join(dir,"installed.json"),nil
}
func auditPath()(string,error){
 dir,err:=userInstallFolder();if err!=nil{return "",err}
 return filepath.Join(dir,"events.jsonl"),nil
}
func quotedRunCommand(exe string)(string,error){
 if !filepath.IsAbs(exe)||strings.ContainsAny(exe,"\r\n\"") {return "",errors.New("unsafe executable path")}
 return "\""+exe+"\" --resident",nil
}
func validateSelectedRoot(root string)error{
 if !filepath.IsAbs(root){return errors.New("select an absolute folder")}
 info,err:=os.Lstat(root)
 if err!=nil{return err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("a real folder must be selected")}
 return nil
}
func fileHash(path string)(string,error){
 info,err:=os.Lstat(path)
 if err!=nil{return "",err}
 if !info.Mode().IsRegular()||info.Size()>32<<20{return "",errors.New("unexpected program file")}
 f,err:=os.Open(path);if err!=nil{return "",err}
 defer f.Close()
 h:=sha256.New()
 n,err:=io.Copy(h,io.LimitReader(f,32<<20+1))
 if err!=nil||n>32<<20{return "",errors.New("cannot verify program")}
 return hex.EncodeToString(h.Sum(nil)),nil
}
func readManifest()(installManifest,error){
 path,err:=installManifestPath()
 if err!=nil{return installManifest{},err}
 info,err:=os.Lstat(path)
 if err!=nil{return installManifest{},err}
 if !info.Mode().IsRegular()||info.Size()>4096{return installManifest{},errors.New("invalid installation manifest")}
 raw,err:=os.ReadFile(path);if err!=nil{return installManifest{},err}
 var m installManifest
 if err:=json.Unmarshal(raw,&m);err!=nil{return installManifest{},err}
 if m.Version!=residentVersion||len(m.ExeHash)!=64||!filepath.IsAbs(m.Root){return installManifest{},errors.New("invalid installed metadata")}
 return m,nil
}
func writeExclusive(path string,data []byte)error{
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err}
 n,err:=f.Write(data)
 if err==nil&&n!=len(data){err=io.ErrShortWrite}
 if err==nil{err=f.Sync()}
 closeErr:=f.Close()
 if err==nil{err=closeErr}
 return err
}
func regReadStartup()(string,error){
 var key syscall.Handle
 err:=syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER,syscall.StringToUTF16Ptr(registryRunKey),0,syscall.KEY_QUERY_VALUE,&key)
 if err!=nil{return "",err}
 defer syscall.RegCloseKey(key)
 var size uint32=4096
 raw:=make([]byte,size)
 var typ uint32
 err=syscall.RegQueryValueEx(key,syscall.StringToUTF16Ptr(registryValueName),nil,&typ,&raw[0],&size)
 if err!=nil{return "",err}
 if typ!=syscall.REG_SZ||size<2||size>4096||size%2!=0{return "",errors.New("unexpected startup entry")}
 values:=make([]uint16,size/2)
 for i:=range values{values[i]=uint16(raw[2*i])|uint16(raw[2*i+1])<<8}
 return syscall.UTF16ToString(values),nil
}
func regSetStartup(command string)error{
 var key syscall.Handle
 status,_,_:=regCreateKeyEx.Call(uintptr(syscall.HKEY_CURRENT_USER),uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(registryRunKey))),
  0,0,0,uintptr(syscall.KEY_SET_VALUE),0,uintptr(unsafe.Pointer(&key)),0)
 if status!=0{return syscall.Errno(status)}
 defer syscall.RegCloseKey(key)
 raw:=syscall.StringToUTF16(command)
 status,_,_ = regSetValueEx.Call(uintptr(key),uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(registryValueName))),
  0,uintptr(syscall.REG_SZ),uintptr(unsafe.Pointer(&raw[0])),uintptr(len(raw)*2))
 if status!=0{return syscall.Errno(status)}
 return nil
}
func regDeleteStartup()error{
 var key syscall.Handle
 err:=syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER,syscall.StringToUTF16Ptr(registryRunKey),0,syscall.KEY_SET_VALUE,&key)
 if err!=nil{return err}
 defer syscall.RegCloseKey(key)
 status,_,_:=regDeleteValue.Call(uintptr(key),uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(registryValueName))))
 if status!=0{return syscall.Errno(status)}
 return nil
}
func installResident(root string)error{
 source,err:=os.Executable();if err!=nil{return err}
 return installResidentFrom(source,root,true)
}

// installResidentFrom separates the verified install operation from launch,
// so Windows integration tests can exercise real HKCU state and reversible
// cleanup without accidentally launching a Go test binary as an agent.
func installResidentFrom(source,root string,launch bool)error{
 if err:=validateSelectedRoot(root);err!=nil{return err}
 source,err:=filepath.Abs(source);if err!=nil{return err}
 dir,err:=userInstallFolder();if err!=nil{return err}
 dest,err:=installExePath();if err!=nil{return err}
 manifest,err:=installManifestPath();if err!=nil{return err}
 command,err:=quotedRunCommand(dest);if err!=nil{return err}
 if value,err:=regReadStartup();err==nil {
  return fmt.Errorf("startup entry already exists (%d bytes); uninstall previous version first",len(value))
 }else if !errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)&&!errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){return err}
 for _,path:=range []string{dest,manifest}{
  if _,err:=os.Lstat(path);err==nil{return errors.New("existing installation files: manual review required")
  }else if !errors.Is(err,os.ErrNotExist){return err}
 }
 if err:=os.MkdirAll(dir,0700);err!=nil{return err}
 st,err:=os.Lstat(dir);if err!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0{return errors.New("unsafe installation folder")}
 srcHash,err:=fileHash(source);if err!=nil{return err}
 original,err:=os.Open(source);if err!=nil{return err}
 defer original.Close()
 // Copy into a newly-created path (O_EXCL): never overwrite an unknown
 // application or a file created by a concurrent installation.
 installed,err:=os.OpenFile(dest,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err}
 committed:=false
 manifestWritten:=false
 defer func(){
  if !committed{
   if manifestWritten{_ =os.Remove(manifest)}
   _=os.Remove(dest)
  }
 }()
 n,err:=io.Copy(installed,io.LimitReader(original,32<<20+1))
 if err==nil&&n>32<<20{err=errors.New("program too large")}
 if err==nil{err=installed.Sync()}
 ce:=installed.Close();if err==nil{err=ce}
 if err!=nil{return err}
 newHash,err:=fileHash(dest)
 if err!=nil||newHash!=srcHash{return errors.New("installed executable verification failed")}
 data,err:=json.Marshal(installManifest{Version:residentVersion,ExeHash:srcHash,Root:root})
 if err!=nil{return err}
 if err:=writeExclusive(manifest,data);err!=nil{return err}
 manifestWritten=true
 if err:=regSetStartup(command);err!=nil{return err}
 committed=true
 // Startup is installed even if immediate launch fails; UI reports that error
 // so the user can disable it. No shell, PowerShell or UAC is launched.
 if !launch{return nil}
 child:=exec.Command(dest,"--resident")
 if err:=child.Start();err!=nil{return fmt.Errorf("startup registered but agent launch failed: %w",err)}
 return child.Process.Release()
}
func requestAgentStop(){
 ptr:=syscall.StringToUTF16Ptr(residentStopEvent)
 h,_,_:=openNamedEvent.Call(eventModifyState,0,uintptr(unsafe.Pointer(ptr)))
 if h!=0{setNamedEvent.Call(h);closeWinHandle.Call(h)}
}
func uninstallResident()error{
 m,err:=readManifest();if err!=nil{return err}
 path,err:=installExePath();if err!=nil{return err}
 command,err:=quotedRunCommand(path);if err!=nil{return err}
 actual,err:=regReadStartup()
 startupPresent:=err==nil
 if startupPresent&&actual!=command{return errors.New("startup command modified: refusing unsafe uninstall")}
 if err!=nil&&!errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)&&!errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){return err}
 digest,err:=fileHash(path)
 if err!=nil||digest!=m.ExeHash{return errors.New("program modified: refusing to remove unverified executable")}
 // Removing an existing, verified entry is the first step. A second attempt
 // is allowed after partial uninstall, when the entry is already absent.
 if startupPresent {if err:=regDeleteStartup();err!=nil{return err}}
 requestAgentStop()
 // Keep only files belonging to this lab installation in the deletion list.
 // Do not delete the directory, alerts, or unrecognized user files.
 var removeErr error
 for deadline:=time.Now().Add(7*time.Second);time.Now().Before(deadline);time.Sleep(250*time.Millisecond){
  removeErr=os.Remove(path)
  if removeErr==nil||errors.Is(removeErr,os.ErrNotExist){break}
 }
 if removeErr!=nil&&!errors.Is(removeErr,os.ErrNotExist){
  return fmt.Errorf("automatic startup disabled; agent program remains in use, close it then retry: %w",removeErr)
 }
 mp,err:=installManifestPath();if err!=nil{return err}
 return os.Remove(mp)
}
func residentAgent()error{
 path,err:=os.Executable();if err!=nil{return err}
 required,err:=installExePath();if err!=nil{return err}
 if !strings.EqualFold(filepath.Clean(path),filepath.Clean(required)){
  return errors.New("resident agent may only start from its verified installation folder")
 }
 m,err:=readManifest();if err!=nil{return err}
 digest,err:=fileHash(path);if err!=nil||digest!=m.ExeHash{return errors.New("resident binary not verified")}
 if err:=validateSelectedRoot(m.Root);err!=nil{return err}
 name:=syscall.StringToUTF16Ptr(residentMutexName)
 mutex,_,mutexErr:=createMutex.Call(0,0,uintptr(unsafe.Pointer(name)))
 if mutex==0{return fmt.Errorf("cannot lock agent: %v",mutexErr)}
 defer closeWinHandle.Call(mutex)
 if mutexErr==errorAlreadyExists{return nil}
 stopName:=syscall.StringToUTF16Ptr(residentStopEvent)
 stop,_,stopErr:=createNamedEvent.Call(0,1,0,uintptr(unsafe.Pointer(stopName)))
 if stop==0{return fmt.Errorf("cannot register stop event: %v",stopErr)}
 defer closeWinHandle.Call(stop)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 done:=make(chan struct{})
 go func(){
  defer close(done)
  for{
   select{case <-ctx.Done():return;default:}
   result,_,_:=waitWinObject.Call(stop,500)
   if result==0{cancel();return}
   if result!=258{cancel();return} // unexpected wait result: fail closed
  }
 }()
 log,err:=auditPath();if err!=nil{return err}
 err=sentinel.RunResident(ctx,m.Root,log)
 cancel()
 <-done
 return err
}
