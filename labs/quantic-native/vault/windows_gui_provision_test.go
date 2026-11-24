//go:build windows && cgo && pqopenssl

package main
import (
 "testing"
 "strings"
 "path/filepath"
 "encoding/json"
)
func TestWindowsGUISecretBounds(t *testing.T){
 var good [257]uint16
 for i:=0;i<20;i++{good[i]='a'}
 p,e:=winGUISecretBytes(good[:]);if e!=nil||len(p)!=20{t.Fatal("valid phrase refused")};clear(p)
 for _,bad:=range []uint16{1,127,233}{
  modified:=good;modified[4]=bad
  if p,e:=winGUISecretBytes(modified[:]);e==nil{clear(p);t.Fatal("non printable ASCII accepted")}
 }
 if p,e:=winGUISecretBytes([]uint16{'a',0});e==nil{clear(p);t.Fatal("short secret accepted")}
 full:=make([]uint16,257);for i:=range full{full[i]='a'}
 if p,e:=winGUISecretBytes(full);e==nil{clear(p);t.Fatal("unterminated secret accepted")}
}

func TestWindowsGUIProvisionReadback(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"gui-test-vault")
 quorum:=strings.Repeat("1",64)
 addr:="synthetic~"+strings.Repeat("a",32)+"@quantic"
 pw:=[]byte("synthetic classical test password");defer clear(pw)
 pq:=[]byte("synthetic postquantum test password");defer clear(pq)
 record,e:=winGUIProvisionAndVerify(dir,quorum,addr,pw,pq)
 if e!=nil{t.Fatal(e)}
 if record["localReadback"]!="verified"||record["address"]!=addr{t.Fatal("unverified result")}
 raw,e:=winReadPrivate(filepath.Join(dir,"identity-public.json"),16384);if e!=nil{t.Fatal(e)}
 var persisted map[string]string
 if e=json.Unmarshal(raw,&persisted);e!=nil{t.Fatal(e)}
 if persisted["deviceId"]!=record["deviceId"]{t.Fatal("public identity mismatch")}
 if e=winGUIVerifyStored(dir,quorum,persisted,pw,pq);e!=nil{t.Fatal(e)}
 if e=winGUIVerifyStored(dir,quorum,persisted,[]byte("synthetic invalid password"),pq);e==nil{t.Fatal("wrong password accepted")}
 if _,e=winGUIProvisionAndVerify(dir,quorum,addr,pw,pq);e==nil{t.Fatal("existing identity overwritten")}
}
