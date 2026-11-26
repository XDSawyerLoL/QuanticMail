//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "encoding/json"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsDesktopReceiptHistory(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 var r enrollmentRequest
 r.Claim.Address="alice~"+strings.Repeat("a",32)+"@quantic"
 r.Claim.DeviceID="d-"+strings.Repeat("b",32)
 key:=bytes.Repeat([]byte{9},32)
 op,closeOp,e:=nativeReceiptTransport(r.Claim.Address,r.Claim.DeviceID,key)
 if e!=nil{t.Fatal(e)};defer closeOp()
 request:=map[string]any{"id":"01234567-89ab-4cde-8fab-0123456789ab","digest":strings.Repeat("c",64),"payload":nativeReceiptPayload{Subject:"Synthetic subject",Body:"Secret body"}}
 input,_:=json.Marshal(request);sealed,e:=op("receipt-seal",input);if e!=nil{t.Fatal(e)}
 id:=strings.Repeat("1",32)
 path:=filepath.Join(dir,"receipt-"+id+".json")
 if e=winWritePrivate(path,sealed);e!=nil{t.Fatal(e)}
 bad:=append([]byte(nil),sealed...);bad[len(bad)/2]^=1
 if e=winWritePrivate(filepath.Join(dir,"receipt-"+strings.Repeat("2",32)+".json"),bad);e!=nil{t.Fatal(e)}
 if e=winWritePrivate(filepath.Join(dir,"receipt-"+strings.Repeat("3",32)+".json"),sealed);e!=nil{t.Fatal(e)}
 var out bytes.Buffer
 if e=executeDesktopReceipt("mail-list",dir,r,key,documentRequest{},&out);e!=nil{t.Fatal(e)}
 if !strings.Contains(out.String(),"Synthetic subject")||strings.Contains(out.String(),"Secret body")||!strings.Contains(out.String(),"\"unverified\":2"){t.Fatal("unexpected list",out.String())}
 out.Reset()
 if e=executeDesktopReceipt("mail-open",dir,r,key,documentRequest{ID:id},&out);e!=nil||!strings.Contains(out.String(),"Secret body"){t.Fatal("receipt failed",e)}
 if e=executeDesktopReceipt("mail-open",dir,r,bytes.Repeat([]byte{1},32),documentRequest{ID:id},&out);e==nil{t.Fatal("wrong key accepted")}
 if e=executeDesktopReceipt("mail-open",dir,r,key,documentRequest{ID:"../escape"},&out);e==nil{t.Fatal("traversal accepted")}
 after,e:=winReadPrivate(path,24000);if e!=nil||!bytes.Equal(after,sealed){t.Fatal("receipt changed",e)}
}
