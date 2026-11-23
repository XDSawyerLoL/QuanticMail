//go:build windows

package main

import (
 "errors"
 "bytes"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "unsafe"
)

// Bounded, non-sensitive failure stage for CI self-test. No local paths,
// private identities, secrets or hashes are ever emitted in this mode.
var startupStage=1

// Force the stock Windows PowerShell module location (Get-FileHash belongs to
// Microsoft.PowerShell.Utility). Neither user PSModulePath nor the GitHub
// pwsh 7 environment may replace these standard modules. This is local-only.
func childPowerShellEnv(in []string,systemRoot string) []string{
 out:=make([]string,0,len(in)+1)
 for _,v:=range in{
  i:=strings.IndexByte(v,'=')
  if i<=0 {continue}
  key:=v[:i]
  if strings.EqualFold(key,"PSModulePath")||
   strings.EqualFold(key,"PSModuleAnalysisCachePath") {continue}
  out=append(out,v)
 }
 out=append(out,"PSModulePath="+filepath.Join(systemRoot,
  "System32","WindowsPowerShell","v1.0","Modules"))
 return out
}

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
 startupStage=2
 if err:=validateEmbeddedPins();err!=nil{return err}
 startupStage=3
 executable,err:=os.Executable()
 if err!=nil{return err}
 root:=filepath.Clean(filepath.Dir(executable))
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){return errors.New("local application directory required")}
 startupStage=4
 if err:=validateInstallation(root,expectedManifestSHA256,expectedVaultSHA256);err!=nil{return err}
 startupStage=5
 system:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(system)||strings.HasPrefix(system,`\\`){return errors.New("trusted system root required")}
 powershell:=filepath.Join(system,"System32","WindowsPowerShell","v1.0","powershell.exe")
 operation:="Dashboard"
 if len(os.Args)==2{operation="DashboardCheck"}
 psArgs:=[]string{"-NoLogo","-NoProfile","-STA"}
 if len(os.Args)==2 {psArgs=append(psArgs,"-NonInteractive")}
 psArgs=append(psArgs,"-File",filepath.Join(root,"app","Start-Windows-PQ-Lab.ps1"),
  "-Operation",operation,"-ExpectedManifestSha256",expectedManifestSHA256,
  "-TrustedBinarySha256",expectedVaultSHA256)
 cmd:=exec.Command(powershell,psArgs...)
 cmd.Dir=filepath.Join(root,"app")
 cmd.Env=childPowerShellEnv(os.Environ(),system)
 var diagnostic bytes.Buffer
 if len(os.Args)==2{
  // Synthetic self-test only: never capture actual human consents,
  // passwords, mailbox contents or production stdout.
  cmd.Stdout=&diagnostic
  cmd.Stderr=&diagnostic
 }
 // The Alpha desktop sends all crypto consent and passphrases through the
 // existing local console: never attempt to swallow these into GUI stdout.
 // Windows creates the necessary console automatically when a console
 // child is started by a GUI-subsystem parent. Forcing CREATE_NEW_CONSOLE
 // while os/exec supplies its standard handles breaks the CI startup.
 // Do not detach: passphrases and explicit local approvals need a console.
 startupStage=6
 if err:=cmd.Start();err!=nil{return err}
 startupStage=7
 if err:=cmd.Wait();err!=nil{
  if len(os.Args)==2{
   output:=diagnostic.String()
   if len(output)>4096{output=output[len(output)-4096:]}
   return fmt.Errorf("Windows Alpha dashboard self-test exited: %w; captured public diagnostics: %s",err,output)
  }
  return err
 }
 return nil
}

func main(){
 if err:=start();err!=nil{
  if len(os.Args)==2&&os.Args[1]=="--self-test" {
   // CI-only report in an exclusive new file under GitHub's own temp;
   // never write a secret, overwrite a file, or enable on normal GUI use.
   if temp:=os.Getenv("RUNNER_TEMP");temp!=""{
    if f,e:=os.OpenFile(filepath.Join(temp,"quantic-alpha-launcher-diagnostic.txt"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);e==nil{
     msg:=err.Error();if len(msg)>4096{msg=msg[len(msg)-4096:]}
     fmt.Fprintf(f,"startupStage=%d; %s\\n",startupStage,msg)
     f.Close()
    }
   }
   os.Exit(10+startupStage)
  }
  alert()
  os.Exit(1)
 }
}
