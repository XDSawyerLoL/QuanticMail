//go:build windows
package main

import(
 "encoding/json"
 "os"
 "path/filepath"
 "reflect"
 "strings"
 "testing"
)
func TestResidentCommandCannotInjectArguments(t *testing.T){
 root:=t.TempDir()
 good:=filepath.Join(root,"quantic-sentinel.exe")
 command,err:=quotedRunCommand(good)
 if err!=nil||command!="\""+good+"\" --resident"{t.Fatalf("bad startup command: %q %v",command,err)}
 for _,bad:=range []string{"relative.exe",good+"\" --other",good+"\n--other"}{
  if _,err:=quotedRunCommand(bad);err==nil{t.Fatalf("unsafe startup command accepted %q",bad)}
 }
}
func TestResidentRequiresRealLocalFolder(t *testing.T){
 root:=t.TempDir()
 if err:=validateSelectedRoot(root);err!=nil{t.Fatal(err)}
 file:=filepath.Join(root,"file")
 if err:=os.WriteFile(file,[]byte("test"),0600);err!=nil{t.Fatal(err)}
 if err:=validateSelectedRoot(file);err==nil{t.Fatal("regular file allowed as watch root")}
 if err:=validateSelectedRoot("relative");err==nil{t.Fatal("relative directory allowed")}
 if err:=validateSelectedRoot(filepath.Join(root,"missing"));err==nil{t.Fatal("nonexistent directory allowed")}
}
func TestManifestFormatAndNoImplicitAgentInstallation(t *testing.T){
 m:=installManifest{Version:residentVersion,Root:t.TempDir(),ExeHash:strings.Repeat("f",64)}
 raw,err:=json.Marshal(m)
 if err!=nil{t.Fatal(err)}
 var back installManifest
 if err:=json.Unmarshal(raw,&back);err!=nil||!reflect.DeepEqual(back,m){t.Fatalf("manifest mismatch %+v %v",back,err)}
 // A test executable not explicitly installed at the canonical path must
 // never be able to start the resident agent, even with --resident.
 if err:=residentAgent();err==nil{t.Fatal("uninstalled test process became a resident agent")}
}
