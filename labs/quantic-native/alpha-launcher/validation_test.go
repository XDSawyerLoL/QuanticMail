package main

import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func sum(b []byte)string{x:=sha256.Sum256(b);return hex.EncodeToString(x[:])}
func fixture(t *testing.T)(string,string,string){
 t.Helper()
 root:=t.TempDir()
 app:=filepath.Join(root,"app")
 if err:=os.MkdirAll(filepath.Join(app,"bin"),0700);err!=nil{t.Fatal(err)}
 manifest:=[]byte(sum([]byte("trusted script"))+" *./Start-Windows-PQ-Lab.ps1\n"+
  sum([]byte("trusted verifier"))+" *./Test-Windows-PQ-Package.ps1\n"+
  sum([]byte("trusted dashboard"))+" *./Quantic-Sillage-Alpha.ps1\n")
 vault:=[]byte("synthetic vault binary\n")
 for path,contents:=range map[string][]byte{
  filepath.Join(app,"SHA256SUMS.txt"):manifest,
  filepath.Join(app,"bin","Vault-PQ-lab.exe"):vault,
  filepath.Join(app,"Start-Windows-PQ-Lab.ps1"):[]byte("trusted script"),
  filepath.Join(app,"Test-Windows-PQ-Package.ps1"):[]byte("trusted verifier"),
  filepath.Join(app,"Quantic-Sillage-Alpha.ps1"):[]byte("trusted dashboard"),
 }{
  if err:=os.WriteFile(path,contents,0600);err!=nil{t.Fatal(err)}
 }
 return root,sum(manifest),sum(vault)
}
func TestValidateInstalledPackage(t *testing.T){
 root,manifest,vault:=fixture(t)
 if err:=validateInstallation(root,manifest,vault);err!=nil{t.Fatal(err)}
 if err:=validateInstallation(root,strings.Repeat("0",64),vault);err==nil{t.Fatal("untrusted manifest accepted")}
 if err:=validateInstallation(root,manifest,strings.Repeat("0",64));err==nil{t.Fatal("untrusted vault accepted")}
 if err:=os.WriteFile(filepath.Join(root,"app","SHA256SUMS.txt"),[]byte("modified"),0600);err!=nil{t.Fatal(err)}
 if err:=validateInstallation(root,manifest,vault);err==nil{t.Fatal("tampered manifest accepted")}
}
func TestFailClosedMissingScriptAndInvalidPin(t *testing.T){
 root,manifest,vault:=fixture(t)
 if err:=os.Remove(filepath.Join(root,"app","Start-Windows-PQ-Lab.ps1"));err!=nil{t.Fatal(err)}
 if err:=validateInstallation(root,manifest,vault);err==nil{t.Fatal("missing script accepted")}
 if validPin(strings.Repeat("F",64))||validPin("abc")||validPin(strings.Repeat("0",63)+"z"){t.Fatal("invalid pin accepted")}
 if !validPin(strings.Repeat("a",64)){t.Fatal("valid pin rejected")}
}

func TestRejectModifiedStartupScriptsBeforeExecution(t *testing.T){
 for _,name:=range []string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1"}{
  root,manifest,vault:=fixture(t)
  if err:=os.WriteFile(filepath.Join(root,"app",name),[]byte("changed script"),0600);err!=nil{t.Fatal(err)}
  if err:=validateInstallation(root,manifest,vault);err==nil{t.Fatalf("modified %s accepted",name)}
 }
}
func TestRejectDuplicateStartupScriptEntry(t *testing.T){
 root,_,vault:=fixture(t)
 path:=filepath.Join(root,"app","SHA256SUMS.txt")
 raw,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 raw=append(raw,[]byte(sum([]byte("trusted script"))+" *./Start-Windows-PQ-Lab.ps1\n")...)
 if e=os.WriteFile(path,raw,0600);e!=nil{t.Fatal(e)}
 if e=validateInstallation(root,sum(raw),vault);e==nil{t.Fatal("duplicate entry accepted")}
}
