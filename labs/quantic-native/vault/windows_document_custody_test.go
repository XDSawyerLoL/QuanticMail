//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsDocumentCustody(t *testing.T){
 key:=bytes.Repeat([]byte{7},32)
 address:="alice~"+strings.Repeat("a",32)+"@quantic"
 device:="d-"+strings.Repeat("b",32)
 id:=strings.Repeat("c",32)
 p:=documentPayload{"private-test.txt",bytes.Repeat([]byte("synthetic document "),3000)}
 record,e:=sealDocument(key,address,device,id,p);if e!=nil{t.Fatal(e)}
 if bytes.Contains(record,[]byte(p.Name))||bytes.Contains(record,p.Data){t.Fatal("plaintext in record")}
 got,e:=openDocument(key,address,device,id,record)
 if e!=nil||got.Name!=p.Name||!bytes.Equal(got.Data,p.Data){t.Fatal("roundtrip",e)}
 if _,e=openDocument(key,address,device,strings.Repeat("d",32),record);e==nil{t.Fatal("document substitution accepted")}
 if _,e=openDocument(key,address+"x",device,id,record);e==nil{t.Fatal("identity substitution accepted")}
 if _,e=openDocument(bytes.Repeat([]byte{8},32),address,device,id,record);e==nil{t.Fatal("wrong key accepted")}
 bad:=append([]byte(nil),record...);bad[len(bad)-1]^=1
 if _,e=openDocument(key,address,device,id,bad);e==nil{t.Fatal("tampered document accepted")}
 for _,name:=range []string{"..","../escape","CON.txt","test.txt:stream","trailing."}{
  if _,e=sealDocument(key,address,device,id,documentPayload{name,[]byte("x")});e==nil{t.Fatal("unsafe name accepted",name)}
 }
 if _,e=sealDocument(key,address,device,id,documentPayload{"big.txt",make([]byte,documentMax+1)});e==nil{t.Fatal("oversize accepted")}
}
func TestWindowsDocumentPrivateImportExport(t *testing.T){
 parent:=t.TempDir()
 source:=filepath.Join(parent,"synthetic.txt")
 data:=bytes.Repeat([]byte("fixture only"),100)
 if e:=os.WriteFile(source,data,0600);e!=nil{t.Fatal(e)}
 p,e:=readDocumentSource(source);if e!=nil||!bytes.Equal(p.Data,data){t.Fatal("source",e)}
 link:=filepath.Join(parent,"hardlink.txt")
 if e=os.Link(source,link);e!=nil{t.Fatal(e)}
 if _,e=readDocumentSource(source);e==nil{t.Fatal("hardlink accepted")}
 if e=os.Remove(link);e!=nil{t.Fatal(e)}
 dir,e:=exportDocument(parent,strings.Repeat("1",32),p);if e!=nil{t.Fatal(e)}
 got,e:=winReadPrivate(filepath.Join(dir,p.Name),documentMax)
 if e!=nil||!bytes.Equal(got,data){t.Fatal("private export",e)}
 if _,e=exportDocument(parent,strings.Repeat("1",32),p);e==nil{t.Fatal("export overwrote existing folder")}
 original,e:=os.ReadFile(source);if e!=nil||!bytes.Equal(original,data){t.Fatal("original changed",e)}
}
