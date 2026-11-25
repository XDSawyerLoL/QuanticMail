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
 got,e:=readDocumentBytes(filepath.Join(dir,p.Name),documentMax)
 if e!=nil||!bytes.Equal(got,data){t.Fatal("private export",e)}
 if _,e=exportDocument(parent,strings.Repeat("1",32),p);e==nil{t.Fatal("export overwrote existing folder")}
 original,e:=os.ReadFile(source);if e!=nil||!bytes.Equal(original,data){t.Fatal("original changed",e)}
}


func TestWindowsDocumentEnrollmentRoundTrip(t *testing.T){
 parent:=t.TempDir()
 pw:=[]byte("synthetic device classical password")
 pq:=[]byte("synthetic device postquantum password")
 owner:=[]byte("synthetic independent owner password")
 _,dir,e:=prepareWindowsEnrollmentVault(parent,"testdocs",strings.Repeat("c",64),pw,pq,owner)
 if e!=nil{t.Fatal(e)}
 r,e:=readPendingEnrollment(dir);if e!=nil{t.Fatal(e)}
 draft,e:=readLocalCustody(dir,"draft",r,pw,pq);if e!=nil{t.Fatal(e)};defer clear(draft)
 key,e:=documentKey(draft,r);if e!=nil{t.Fatal(e)};defer clear(key)
 if bytes.Equal(key,draft){t.Fatal("domain separation failed")}
 data:=bytes.Repeat([]byte("synthetic file 0123456789"),350000)
 data=data[:documentMax]
 source:=filepath.Join(parent,"large-test.pdf")
 if e=os.WriteFile(source,data,0600);e!=nil{t.Fatal(e)}
 p,e:=readDocumentSource(source);if e!=nil{t.Fatal(e)};defer clear(p.Data)
 entry,e:=addDocument(dir,key,r,p);if e!=nil{t.Fatal(e)}
 clear(key);clear(draft)
 // Close and re-open the existing encrypted enrollment custody.
 r,e=readPendingEnrollment(dir);if e!=nil{t.Fatal(e)}
 next,e:=readLocalCustody(dir,"draft",r,pw,pq);if e!=nil{t.Fatal(e)};defer clear(next)
 reopened,e:=documentKey(next,r);if e!=nil{t.Fatal(e)};defer clear(reopened)
 ids,e:=documentIDs(dir);if e!=nil||len(ids)!=1||ids[0]!=entry.ID{t.Fatal("inventory",e)}
 actual,e:=readDocument(dir,entry.ID,reopened,r);if e!=nil{t.Fatal(e)};defer clear(actual.Data)
 if actual.Name!=p.Name||!bytes.Equal(actual.Data,data){t.Fatal("reopened document differs")}
 if _,e=readDocument(dir,entry.ID,next,r);e==nil{t.Fatal("raw draft key accepted")}
 out,e:=exportDocument(parent,entry.ID,actual);if e!=nil{t.Fatal(e)}
 exported,e:=readDocumentBytes(filepath.Join(out,p.Name),documentMax);if e!=nil||!bytes.Equal(exported,data){t.Fatal("export changed",e)}
 original,e:=os.ReadFile(source);if e!=nil||!bytes.Equal(original,data){t.Fatal("original changed",e)}
 if _,e=winReadPrivate(documentFile(dir,entry.ID),documentRecordMax);e==nil{t.Fatal("general storage limit weakened")}
}
