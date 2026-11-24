//go:build windows && cgo && pqopenssl

package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsMailLabInventory(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"private-outbox")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 empty,e:=winMailLabInventory(dir)
 if e!=nil||empty.DeliveryVerified||len(empty.Items)!=0{t.Fatal("invalid empty inventory",e)}
 id:=strings.Repeat("a",32)
 draft:=filepath.Join(dir,"draft-"+id+".json")
 wire:=filepath.Join(dir,"wire-"+id+".json")
 if e=winWriteEncryptedDraft(draft,[]byte("{\"context\":{},\"payload\":{}}"));e!=nil{t.Fatal(e)}
 s,e:=winMailLabInventory(dir)
 if e!=nil||len(s.Items)!=1||!s.Items[0].Draft||s.Items[0].Wire||s.DeliveryVerified{t.Fatal("draft status invalid",e)}
 data:=[]byte("{\"format\":\"quantic-native-mail\",\"version\":1}")
 if e=winWritePrivate(wire,data);e!=nil{t.Fatal(e)}
 s,e=winMailLabInventory(dir)
 if e!=nil||len(s.Items)!=1||!s.Items[0].Draft||!s.Items[0].Wire||s.DeliveryVerified{t.Fatal("wire presence misrepresented",e)}
 // A file called a wire must not prove a signature or delivery.
 other:=filepath.Join(dir,"wire-"+strings.Repeat("b",32)+".json")
 if e=winWritePrivate(other,[]byte("{\"format\":\"fake\",\"version\":1}"));e!=nil{t.Fatal(e)}
 if _,e=winMailLabInventory(dir);e==nil{t.Fatal("fake wire accepted")}
 if e=os.Remove(other);e!=nil{t.Fatal(e)}
 raw,e:=winReadPrivate(draft,16384);if e!=nil{t.Fatal(e)}
 raw[0]^=1
 if e=os.WriteFile(draft,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=winMailLabInventory(dir);e==nil{t.Fatal("clear or tampered draft accepted")}
}
