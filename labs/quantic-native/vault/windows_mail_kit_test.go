//go:build windows && cgo && pqopenssl

package main
import (
 "encoding/json"
 "encoding/base64"
 "path/filepath"
 "strings"
 "testing"
)
func TestWindowsMailKitRefusesWrongScope(t *testing.T){
 identity:=map[string]string{"address":"alice~"+strings.Repeat("a",32)+"@quantic","deviceId":"d-"+strings.Repeat("b",32)}
 kit:=windowsMailKit{Format:"quantic-windows-mail-kit-lab/v1",Address:identity["address"],DeviceID:identity["deviceId"],Files:map[string]string{}}
 for _,n:=range []string{"desktop.json","quorum.json","contacts.json","peer-ca.pem","peer-cert.pem","peer-key.pem"}{kit.Files[n]=base64.RawURLEncoding.EncodeToString([]byte("{}"))}
 raw,_:=json.Marshal(kit)
 files,e:=decodeMailKit(raw,identity);if e!=nil{t.Fatal(e)};defer clearMailKit(files)
 if e=checkMailKitConfig("C:\\vault","C:\\bin\\vault.exe",strings.Repeat("a",64),identity,files);e==nil{t.Fatal("unbound configuration accepted")}
 kit.DeviceID="d-"+strings.Repeat("c",32);raw,_=json.Marshal(kit)
 if _,e=decodeMailKit(raw,identity);e==nil{t.Fatal("other device accepted")}
 kit.DeviceID=identity["deviceId"];kit.Files["controller.pem"]=kit.Files["peer-key.pem"];raw,_=json.Marshal(kit)
 if _,e=decodeMailKit(raw,identity);e==nil{t.Fatal("controller key import accepted")}
 delete(kit.Files,"controller.pem");kit.Files["..\\escape.json"]=kit.Files["peer-key.pem"];raw,_=json.Marshal(kit)
 if _,e=decodeMailKit(raw,identity);e==nil{t.Fatal("traversal accepted")}
}
func TestWindowsMailKitResumeNoOverwrite(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"mail-kit-vault")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 if e:=winWritePrivate(filepath.Join(dir,"lab-provisioned"),[]byte(strings.Repeat("a",64)));e!=nil{t.Fatal(e)}
 files:=map[string][]byte{"contacts.json":[]byte("[]"),"desktop.json":[]byte("{}")}
 if e:=writeMailKit(dir,files);e!=nil{t.Fatal(e)}
 if e:=writeMailKit(dir,files);e!=nil{t.Fatal("identical resume failed",e)}
 files["desktop.json"]=[]byte("{\"changed\":true}");files["quorum.json"]=[]byte("[]")
 if e:=writeMailKit(dir,files);e==nil{t.Fatal("overwrite accepted")}
 if b,e:=winReadPrivate(filepath.Join(dir,"desktop.json"),32);e!=nil||string(b)!="{}"{t.Fatal("existing bytes changed")}
 if _,e:=winReadPrivate(filepath.Join(dir,"quorum.json"),32);e==nil{t.Fatal("partial new write before conflict preflight")}
}
