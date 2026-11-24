//go:build windows

package main

import(
 "errors"
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "time"
 "fmt"
 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

// This test actually creates and removes the current user's HKCU Run entry
// on the disposable GitHub Windows runner. It never launches the test binary
// as a permanent agent and never elevates its privileges. All files are
// isolated by LOCALAPPDATA pointing to t.TempDir().
func TestPerUserInstallerAndUninstallerEndToEnd(t *testing.T){
 if _,err:=regReadStartup();err==nil{
  t.Skip("existing HKCU Sentinel entry: refuse to modify user installation")
 }else if !errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)&&!errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){
  t.Fatalf("cannot read HKCU safely: %v",err)
 }
 local:=t.TempDir()
 t.Setenv("LOCALAPPDATA",local)
 watched:=t.TempDir()
 source,err:=os.Executable();if err!=nil{t.Fatal(err)}
 installed:=false
 t.Cleanup(func(){
  if installed{_ =uninstallResident()}
  // Never delete a registry value we did not create.
 })
 if err:=installResidentFrom(source,watched,false);err!=nil{t.Fatal(err)}
 installed=true
 installedExe,err:=installExePath();if err!=nil{t.Fatal(err)}
 manifest,err:=readManifest();if err!=nil{t.Fatal(err)}
 if manifest.Root!=watched||len(manifest.ExeHash)!=64{t.Fatalf("bad manifest %+v",manifest)}
 hash,err:=fileHash(installedExe);if err!=nil||hash!=manifest.ExeHash{t.Fatalf("installed exe hash mismatch: %v",err)}
 actual,err:=regReadStartup();if err!=nil{t.Fatal(err)}
 expected,err:=quotedRunCommand(installedExe);if err!=nil{t.Fatal(err)}
 if actual!=expected{t.Fatalf("startup command not bound to installed program: %q != %q",actual,expected)}
 folder,err:=userInstallFolder();if err!=nil{t.Fatal(err)}
 if !strings.HasPrefix(strings.ToLower(folder),strings.ToLower(local)){t.Fatalf("installation escaped isolated profile: %s",folder)}
 // Neither an audit log nor unrelated user files are allowed to disappear.
 preserved:=[]string{filepath.Join(folder,"events.jsonl"),filepath.Join(folder,"my-notes.txt")}
 for _,name:=range preserved{if err:=os.WriteFile(name,[]byte("KEEP"),0600);err!=nil{t.Fatal(err)}}
 if err:=uninstallResident();err!=nil{t.Fatal(err)}
 installed=false
 for _,name:=range preserved{
  raw,err:=os.ReadFile(name);if err!=nil||string(raw)!="KEEP"{t.Fatalf("uninstall modified user data: %s %v",name,err)}
 }
 for _,name:=range []string{installedExe,filepath.Join(folder,"installed.json")}{
  if _,err:=os.Lstat(name);!errors.Is(err,os.ErrNotExist){t.Fatalf("known installed file remains: %s %v",name,err)}
 }
 if _,err:=regReadStartup();!errors.Is(err,syscall.ERROR_FILE_NOT_FOUND){t.Fatalf("HKCU startup still present: %v",err)}
}

func TestInstallerNeverOverwritesUnknownProgram(t *testing.T){
 if _,err:=regReadStartup();err==nil{t.Skip("existing HKCU agent")}
 t.Setenv("LOCALAPPDATA",t.TempDir())
 folder,err:=userInstallFolder();if err!=nil{t.Fatal(err)}
 if err:=os.MkdirAll(folder,0700);err!=nil{t.Fatal(err)}
 path,err:=installExePath();if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,[]byte("unknown file must remain"),0600);err!=nil{t.Fatal(err)}
 source,err:=os.Executable();if err!=nil{t.Fatal(err)}
 if err:=installResidentFrom(source,t.TempDir(),false);err==nil{t.Fatal("installer overwrote unknown file")}
 b,err:=os.ReadFile(path);if err!=nil||string(b)!="unknown file must remain"{t.Fatal("unknown file replaced or deleted")}
}


// This opt-in CI test exercises the ACTUAL compiled Win32 GUI executable
// in its resident mode, under a temporary LocalAppData folder on an ephemeral
// runner. It does not rely on manual clicks, reboot, or administrator rights.
// It verifies real startup, a real file burst and targeted uninstall.
func TestActualResidentBinaryInstallationE2E(t *testing.T){
 binary:=os.Getenv("QUANTIC_SENTINEL_TEST_BINARY")
 if binary==""{t.Skip("requires compiled GUI binary via isolated Windows CI")}
 binary,err:=filepath.Abs(binary);if err!=nil{t.Fatal(err)}
 if _,err:=regReadStartup();err==nil{t.Skip("user already has Quantic Sentinel startup entry")}
 t.Setenv("LOCALAPPDATA",t.TempDir())
 watched:=t.TempDir()
 installed:=false
 t.Cleanup(func(){if installed{_ =uninstallResident()}})
 if err:=installResidentFrom(binary,watched,true);err!=nil{t.Fatal(err)}
 installed=true
 log,err:=auditPath();if err!=nil{t.Fatal(err)}
 // Wait for the installed binary to start from the actual installation path.
 started:=false
 for deadline:=time.Now().Add(8*time.Second);time.Now().Before(deadline);time.Sleep(100*time.Millisecond){
  records,err:=sentinel.RecentRecords(log,30)
  if err==nil{
   for _,r:=range records{if r.Type=="started"{started=true;break}}
  }
  if started{break}
 }
 if !started{t.Fatal("real installed GUI binary did not start resident monitoring")}
 for i:=0;i<25;i++{
  filename:=filepath.Join(watched,fmt.Sprintf("case-%03d.txt",i))
  if err:=os.WriteFile(filename,[]byte("harmless CI file"),0600);err!=nil{t.Fatal(err)}
 }
 alerted:=false
 for deadline:=time.Now().Add(10*time.Second);time.Now().Before(deadline);time.Sleep(150*time.Millisecond){
  records,err:=sentinel.RecentRecords(log,70)
  if err==nil{for _,r:=range records{if r.Type=="alert"{alerted=true;break}}}
  if alerted{break}
 }
 if !alerted{t.Fatal("real resident did not detect harmless file burst")}
 if err:=uninstallResident();err!=nil{t.Fatalf("real agent uninstall failed: %v",err)}
 installed=false
 if _,err:=regReadStartup();!errors.Is(err,syscall.ERROR_FILE_NOT_FOUND){t.Fatalf("startup entry still present: %v",err)}
 if _,err:=os.Stat(log);err!=nil{t.Fatalf("uninstall deleted incident history: %v",err)}
 installedExe,err:=installExePath();if err!=nil{t.Fatal(err)}
 if _,err:=os.Lstat(installedExe);!errors.Is(err,os.ErrNotExist){t.Fatalf("uninstall left running program: %v",err)}
}
