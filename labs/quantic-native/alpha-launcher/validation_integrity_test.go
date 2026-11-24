package main

import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestEntrypointIntegrityRejectsTampering(t *testing.T) {
 dir:=t.TempDir()
 names:=[]string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1"}
 var lines []string
 for _,name:=range names {
  data:=[]byte("Write-Output 'safe'\n")
  if err:=os.WriteFile(filepath.Join(dir,name),data,0600);err!=nil{t.Fatal(err)}
  sum:=sha256.Sum256(data)
  lines=append(lines,hex.EncodeToString(sum[:])+" *./"+name)
 }
 if err:=os.WriteFile(filepath.Join(dir,"SHA256SUMS.txt"),[]byte(strings.Join(lines,"\n")+"\n"),0600);err!=nil{t.Fatal(err)}
 if err:=validateEntrypointHashes(dir);err!=nil{t.Fatalf("valid package refused: %v",err)}
 if err:=os.WriteFile(filepath.Join(dir,names[0]),[]byte("Write-Output 'tampered'\n"),0600);err!=nil{t.Fatal(err)}
 if err:=validateEntrypointHashes(dir);err==nil{t.Fatal("tampered startup script accepted")}
}
func TestEntrypointIntegrityRejectsMissingInventory(t *testing.T){
 dir:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(dir,"SHA256SUMS.txt"),[]byte(""),0600);err!=nil{t.Fatal(err)}
 if err:=validateEntrypointHashes(dir);err==nil{t.Fatal("missing script inventory accepted")}
}
