//go:build windows

// Local, native bootstrap for the Windows Alpha. It does not load Web UI.
// The launcher checks independently supplied package and vault pins before
// invoking any installed PowerShell. Only the verified installed scripts may
// use a per-process execution policy; domain GPO policy still has priority.
package main

import (
 "bufio"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "syscall"
 "unsafe"
)

const (createNewConsole=0x00000010; createNoWindow=0x08000000)
var hexPin=regexp.MustCompile("^[a-f0-9]{64}$")

func fileSHA256(path string)(string,error){
 f,e:=os.Open(path);if e!=nil{return "",e};defer f.Close()
 info,e:=f.Stat();if e!=nil{return "",e};if !info.Mode().IsRegular(){return "",errors.New("not a regular file")}
 h:=sha256.New();if _,e=io.Copy(h,io.LimitReader(f,256<<20));e!=nil{return "",e}
 return hex.EncodeToString(h.Sum(nil)),nil
}
func pinnedFile(root,name,manifest string)error{
 var want string
 count:=0
 sc:=bufio.NewScanner(strings.NewReader(manifest))
 for sc.Scan(){
  line:=sc.Text()
  if !strings.HasSuffix(line," *./"+name){continue}
  if len(line)!=68+len(name)||!hexPin.MatchString(line[:64]){return errors.New("invalid manifest entry")}
  want=line[:64];count++
 }
 if sc.Err()!=nil||count!=1{return errors.New("missing/duplicate pinned file")}
 path:=filepath.Join(root,filepath.FromSlash(name))
 stat,e:=os.Lstat(path);if e!=nil{return e}
 if !stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0{return errors.New("not a regular pinned file")}
 got,e:=fileSHA256(path);if e!=nil{return e}
 if got!=want{return errors.New("pinned application file changed")}
 return nil
}
func verify(root,manifestPin,vaultPin string)error{
 if !hexPin.MatchString(manifestPin)||!hexPin.MatchString(vaultPin){return errors.New("invalid independent fingerprint")}
 manifestFile:=filepath.Join(root,"SHA256SUMS.txt")
 stat,e:=os.Lstat(manifestFile);if e!=nil{return e}
 if !stat.Mode().IsRegular()||stat.Size()<1||stat.Size()>262144{return errors.New("manifest type/size invalid")}
 actual,e:=fileSHA256(manifestFile);if e!=nil{return e}
 if actual!=manifestPin{return errors.New("package fingerprint mismatch")}
 raw,e:=os.ReadFile(manifestFile);if e!=nil{return e}
 manifest:=string(raw)
 for _,name:=range []string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1"}{
  if e=pinnedFile(root,name,manifest);e!=nil{return fmt.Errorf("trusted script rejected: %w",e)}
 }
 got,e:=fileSHA256(filepath.Join(root,"bin","Vault-PQ-lab.exe"));if e!=nil{return e}
 if got!=vaultPin{return errors.New("native cryptography provider mismatch")}
 return nil
}
func localPowerShell(root,manifestPin,vaultPin string,smoke bool)(uint32,error){
 winDir:=os.Getenv("SystemRoot")
 if winDir==""{return 1,errors.New("Windows root unavailable")}
 shell:=filepath.Join(winDir,"System32","WindowsPowerShell","v1.0","powershell.exe")
 info,e:=os.Stat(shell)
 if e!=nil||!info.Mode().IsRegular(){return 1,errors.New("system PowerShell missing")}
 argv:=[]string{shell,"-NoLogo","-NoProfile","-STA","-ExecutionPolicy","Bypass","-File",filepath.Join(root,"Start-Windows-PQ-Lab.ps1"),"-Operation","Dashboard","-ExpectedManifestSha256",manifestPin,"-TrustedBinarySha256",vaultPin}
 if smoke{argv[9]="DashboardCheck"}
 list:=make([]string,len(argv))
 for i,a:=range argv{list[i]=syscall.EscapeArg(a)}
 program,e:=syscall.UTF16PtrFromString(shell);if e!=nil{return 1,e}
 command,e:=syscall.UTF16PtrFromString(strings.Join(list," "));if e!=nil{return 1,e}
 cwd,e:=syscall.UTF16PtrFromString(root);if e!=nil{return 1,e}
 var si syscall.StartupInfo;si.Cb=uint32(unsafe.Sizeof(si))
 var pi syscall.ProcessInformation
 flags:=uint32(createNewConsole);if smoke{flags=createNoWindow}
 if e=syscall.CreateProcess(program,command,nil,nil,false,flags,nil,cwd,&si,&pi);e!=nil{return 1,fmt.Errorf("start native dashboard: %w",e)}
 defer syscall.CloseHandle(pi.Process);defer syscall.CloseHandle(pi.Thread)
 status,e:=syscall.WaitForSingleObject(pi.Process,0xFFFFFFFF)
 if e!=nil||status!=syscall.WAIT_OBJECT_0{return 1,errors.New("process wait failed")}
 var code uint32
 if e=syscall.GetExitCodeProcess(pi.Process,&code);e!=nil{return 1,e}
 return code,nil
}
func messageBox(message string){
 title,_:=syscall.UTF16PtrFromString("Quantic Sillage Alpha - Diagnostic")
 body,_:=syscall.UTF16PtrFromString(message)
 api:=syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
 api.Call(0,uintptr(unsafe.Pointer(body)),uintptr(unsafe.Pointer(title)),0x10|0x1000)
}
func main(){
 argc:=len(os.Args)-1
 test:=argc==3&&(os.Args[3]=="--self-test"||os.Args[3]=="--smoke-ui")
 if argc<2||argc>3||argc==3&&!test{
  if !test{messageBox("Parametres de demarrage non fiables. Aucun compte ou cle n'a ete modifie.")}
  os.Exit(2)
 }
 rootExe,e:=os.Executable()
 if e!=nil{if !test{messageBox("Chemin d'installation non disponible.")};os.Exit(2)}
 root:=filepath.Dir(filepath.Dir(rootExe))
 if e=verify(root,os.Args[1],os.Args[2]);e!=nil{
  if test{fmt.Fprintln(os.Stderr,e)}else{messageBox("Demarrage refuse : les fichiers ne correspondent pas aux empreintes de l'installateur.\nAucune cle n'a ete touchee.\n\nDetail : "+e.Error())}
  os.Exit(2)
 }
 if argc==3&&os.Args[3]=="--self-test"{return}
 code,e:=localPowerShell(root,os.Args[1],os.Args[2],argc==3)
 if e!=nil{
  if test{fmt.Fprintln(os.Stderr,e)}else{messageBox("Impossible de demarrer l'interface locale.\n"+e.Error()+"\nAucune interface Web de secours.")}
  os.Exit(1)
 }
 if code!=0{
  if test{fmt.Fprintln(os.Stderr,"GUI self-test rejected",code)}else{messageBox(fmt.Sprintf("L'interface locale s'est arretee avec le code %d.\nWindows peut bloquer PowerShell ou un controle de securite.\nAucun repli vers un client Web.",code))}
  os.Exit(1)
 }
}
