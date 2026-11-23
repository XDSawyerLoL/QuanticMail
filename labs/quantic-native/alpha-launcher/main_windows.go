//go:build windows

package main

import (
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "unsafe"
)

const createNewConsole=0x00000010

func alert(){
 // No secrets, local paths or certificate material are printed to the user.
 title,_:=syscall.UTF16PtrFromString("Quantic Sillage Alpha")
 message,_:=syscall.UTF16PtrFromString(
  "Demarrage refuse. L'installation n'est pas verifiee ou une operation a echoue. "+
  "Verifier le paquet officiel et son empreinte SHA256. Aucun compte reel n'a ete modifie.")
 proc:=syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
 proc.Call(0,uintptr(unsafe.Pointer(message)),uintptr(unsafe.Pointer(title)),0x10)
}

func start()error{
 if len(os.Args)>2||(len(os.Args)==2&&os.Args[1]!="--self-test"){
  return errors.New("unsupported GUI arguments")
 }
 if err:=validateEmbeddedPins();err!=nil{return err}
 executable,err:=os.Executable()
 if err!=nil{return err}
 root:=filepath.Clean(filepath.Dir(executable))
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){return errors.New("local application directory required")}
 if err:=validateInstallation(root,expectedManifestSHA256,expectedVaultSHA256);err!=nil{return err}
 system:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(system)||strings.HasPrefix(system,`\\`){return errors.New("trusted system root required")}
 powershell:=filepath.Join(system,"System32","WindowsPowerShell","v1.0","powershell.exe")
 operation:="Dashboard"
 if len(os.Args)==2{operation="DashboardCheck"}
 cmd:=exec.Command(powershell,"-NoLogo","-NoProfile","-STA","-File",
  filepath.Join(root,"app","Start-Windows-PQ-Lab.ps1"),"-Operation",operation,
  "-ExpectedManifestSha256",expectedManifestSHA256,
  "-TrustedBinarySha256",expectedVaultSHA256)
 cmd.Dir=filepath.Join(root,"app")
 // The Alpha desktop sends all crypto consent and passphrases through the
 // existing local console: never attempt to swallow these into GUI stdout.
 cmd.SysProcAttr=&syscall.SysProcAttr{CreationFlags:createNewConsole}
 if err:=cmd.Run();err!=nil{return err}
 return nil
}

func main(){
 if err:=start();err!=nil{
  if len(os.Args)!=2||os.Args[1]!="--self-test"{alert()}
  os.Exit(1)
 }
}
