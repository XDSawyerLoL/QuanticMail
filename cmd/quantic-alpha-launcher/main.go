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
 "os/exec"
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

var hexPin=regexp.MustCompile("^[a-f0-9]{64}$")

func fileSHA256(path string)(string,error){
 f,e:=os.Open(path);if e!=nil{return "",e};defer f.Close()
 info,e:=f.Stat();if e!=nil{return "",e};if !info.Mode().IsRegular()||info.Size()>256<<20{return "",errors.New("not a regular file or file too large")}
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
 for _,name:=range []string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1","Quantic-Sillage-Compose.ps1","Quantic-Sillage-Advanced.ps1"}{
  if e=pinnedFile(root,name,manifest);e!=nil{return fmt.Errorf("trusted script rejected: %w",e)}
 }
 got,e:=fileSHA256(filepath.Join(root,"bin","Vault-PQ-lab.exe"));if e!=nil{return e}
 if got!=vaultPin{return errors.New("native cryptography provider mismatch")}
 return nil
}
// Resolve the Windows root from the OS, not the caller's environment.
func trustedWindowsRoot()(string,error){
 var buffer [32768]uint16
 proc:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemWindowsDirectoryW")
 n,_,_:=proc.Call(uintptr(unsafe.Pointer(&buffer[0])),uintptr(len(buffer)))
 if n==0||n>=uintptr(len(buffer)){return "",errors.New("Windows root unavailable")}
 root:=syscall.UTF16ToString(buffer[:int(n)])
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||len(root)<3||root[1:3]!=":\\"{return "",errors.New("Windows root invalid")}
 return root,nil
}

// Fresh allowlist: do not inherit debugger, runtime preload, TLS keylog,
// proxy, cloud tokens, arbitrary module paths or other parent variables.
// User profile/temp locations are retained for normal Windows operation;
// these remain inside the trusted same-user OS boundary.
func dashboardEnvironment(winDir,modules string,parent []string)[]string{
 allowed:=map[string]bool{"USERPROFILE":true,"LOCALAPPDATA":true,"APPDATA":true,"HOMEDRIVE":true,"HOMEPATH":true,"TEMP":true,"TMP":true,"USERNAME":true,"USERDOMAIN":true,"COMPUTERNAME":true,"PROGRAMDATA":true,"ALLUSERSPROFILE":true,"PROCESSOR_ARCHITECTURE":true,"PROCESSOR_IDENTIFIER":true,"NUMBER_OF_PROCESSORS":true,"PROCESSOR_LEVEL":true,"PROCESSOR_REVISION":true}
 values:=map[string]string{}
 for _,entry:=range parent{
  key,value,ok:=strings.Cut(entry,"=")
  key=strings.ToUpper(key)
  if ok&&allowed[key]&&value!=""{values[key]=value}
 }
 env:=[]string{"SystemRoot="+winDir,"WINDIR="+winDir,"ComSpec="+filepath.Join(winDir,"System32","cmd.exe"),"OS=Windows_NT","PATHEXT=.COM;.EXE;.BAT;.CMD","PATH="+filepath.Join(winDir,"System32")+";"+filepath.Join(winDir,"System32","WindowsPowerShell","v1.0"),"PSModulePath="+modules}
 for key,value:=range values{env=append(env,key+"="+value)}
 return env
}

// Default Windows UI is graphical: do not allocate a background PowerShell console.
// Only a deliberate Advanced operation may launch a visible separate terminal.
func localPowerShell(root,manifestPin,vaultPin string,smoke bool)(uint32,error){
 winDir,e:=trustedWindowsRoot()
 if e!=nil{return 1,e}
 shell:=filepath.Join(winDir,"System32","WindowsPowerShell","v1.0","powershell.exe")
 info,e:=os.Stat(shell);if e!=nil||!info.Mode().IsRegular(){return 1,errors.New("system PowerShell missing")}
 action:="Dashboard"
 if smoke{action="DashboardCheck"}
 argv:=[]string{"-NoLogo","-NoProfile","-STA","-ExecutionPolicy","Bypass","-File",filepath.Join(root,"Start-Windows-PQ-Lab.ps1"),"-Operation",action,"-ExpectedManifestSha256",manifestPin,"-TrustedBinarySha256",vaultPin}
 // Go standard library handles Windows command line quoting and handle
 // inheritance, unlike the earlier hand-built CreateProcess calls.
 cmd:=exec.Command(shell,argv...)
 cmd.Dir=root
 // Powershell 7 parent processes can pass a PSModulePath that masks the
 // Windows PowerShell 5.1 inbox modules. Get-FileHash and other built-in
 // verification cmdlets then appear "not recognized" in the spawned GUI.
 // Pin module loading to Windows's own inbox directory, never to arbitrary
 // user-controlled module roots. Never modify machine environment globally.
 systemModules:=filepath.Join(winDir,"System32","WindowsPowerShell","v1.0","Modules")
 stat,e:=os.Stat(systemModules)
 if e!=nil||!stat.IsDir(){return 1,errors.New("trusted Windows PowerShell system modules unavailable")}
 cmd.Env=dashboardEnvironment(winDir,systemModules,os.Environ())
 cmd.SysProcAttr=&syscall.SysProcAttr{CreationFlags:0x08000000} // CREATE_NO_WINDOW
 // The smoke test uses only synthetic identities; collect process stderr
 // into a private temporary diagnostic file for the CI test exclusively.
 if smoke&&os.Getenv("GITHUB_ACTIONS")=="true"{
  log,e:=os.OpenFile(filepath.Join(os.TempDir(),"quantic-alpha-ui-ci.log"),os.O_CREATE|os.O_WRONLY|os.O_TRUNC,0600)
  if e==nil{
   defer log.Close()
   cmd.Stdout=log;cmd.Stderr=log
   defer func(){log.Sync()}()
  }
 }
 err:=cmd.Run()
 if err!=nil{
  var ex *exec.ExitError
  if errors.As(err,&ex){return uint32(ex.ExitCode()),nil}
  return 1,fmt.Errorf("native dashboard spawn: %w",err)
 }
 return 0,nil
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
