package main

import (
 "bytes"
 "crypto/rand"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)
func TestNativeMailboxTransportNoExport(t *testing.T){
 token:=make([]byte,32);if _,e:=rand.Read(token);e!=nil{t.Fatal(e)}
 address:="alice~"+strings.Repeat("a",32)+"@quantic"
 device:="d-"+strings.Repeat("b",32)
 hits:=0
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  hits++
  if r.Header.Get("Authorization")!="Bearer "+b64.EncodeToString(token){t.Error("wrong native credential");w.WriteHeader(403);return}
  if r.URL.Path=="/api/quantic/native/v1/pull"{w.Write([]byte(`{"item":null}`));return}
  w.Header().Set("Location","https://example.invalid/");w.WriteHeader(302)
 }))
 defer server.Close()
 call,close,e:=newMailboxTransport(server.URL+"/",address,device,token);if e!=nil{t.Fatal(e)};defer close()
 raw,_:=json.Marshal(map[string]string{"address":address,"deviceId":device})
 out,e:=call("pull",raw);if e!=nil||!bytes.Equal(out,[]byte(`{"item":null}`))||bytes.Contains(out,token){t.Fatal("pull refused or secret exported",e)}
 if _,e=call("register",raw);e==nil{t.Fatal("non-mail operation accepted")}
 bad,_:=json.Marshal(map[string]string{"address":"other","deviceId":device})
 if _,e=call("pull",bad);e==nil{t.Fatal("scope bypass")}
 ack,_:=json.Marshal(map[string]string{"address":address,"deviceId":device,"id":"test","digest":"test"})
 if _,e=call("ack",ack);e==nil{t.Fatal("redirect accepted")}
 if hits!=2{t.Fatal("unexpected network operations",hits)}
 close();if _,e=call("pull",raw);e==nil{t.Fatal("closed session reused")}
 if _,_,e=newMailboxTransport("https://example.invalid/",address,device,token);e==nil{t.Fatal("remote endpoint accepted")}
}
