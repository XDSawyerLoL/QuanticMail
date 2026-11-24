package main

// A strictly loopback mailbox transport. The bearer stays in the native
// process. No generic HTTP, remote URL, proxy, redirect or credential export.
import (
 "bytes"
 "encoding/json"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "time"
)
type mailboxTransport func(string,json.RawMessage)(json.RawMessage,error)
func newMailboxTransport(endpoint,address,device string,token []byte)(mailboxTransport,func(),error){
 u,e:=url.Parse(endpoint)
 if e!=nil||u.Scheme!="http"||u.Hostname()!="127.0.0.1"||u.User!=nil||u.Path!="/"||u.RawPath!=""||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.Opaque!=""||len(token)!=32||!strongAddr.MatchString(address)||!strongDevice.MatchString(device){return nil,nil,portableRefusal}
 port,e:=strconv.Atoi(u.Port());if e!=nil||port<1||port>65535||u.Host!="127.0.0.1:"+strconv.Itoa(port){return nil,nil,portableRefusal}
 tr:=&http.Transport{Proxy:nil,DisableKeepAlives:true,DisableCompression:true,DialContext:(&net.Dialer{Timeout:3*time.Second}).DialContext,ResponseHeaderTimeout:12*time.Second}
 client:=&http.Client{Transport:tr,Timeout:20*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 secret:=append([]byte(nil),token...)
 closed:=false
 close:=func(){closed=true;clear(secret);tr.CloseIdleConnections()}
 return func(op string,body json.RawMessage)(json.RawMessage,error){
  if closed||len(body)<2||len(body)>23000{return nil,portableRefusal}
  var obj map[string]json.RawMessage
  if json.Unmarshal(body,&obj)!=nil||obj==nil{return nil,portableRefusal}
  var a,d string
  switch op{
  case "send":
   if len(obj)!=5{return nil,portableRefusal}
   var c pqContext
   if json.Unmarshal(obj["context"],&c)!=nil||c.From!=address||c.FromDeviceID!=device{return nil,portableRefusal}
  case "pull","ack","recover":
   if json.Unmarshal(obj["address"],&a)!=nil||json.Unmarshal(obj["deviceId"],&d)!=nil||a!=address||d!=device{return nil,portableRefusal}
   if op=="pull"&&len(obj)!=2||op!="pull"&&len(obj)!=4{return nil,portableRefusal}
  default:return nil,portableRefusal
  }
  req,e:=http.NewRequest("POST","http://"+u.Host+"/api/quantic/native/v1/"+op,bytes.NewReader(body));if e!=nil{return nil,portableRefusal}
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("Authorization","Bearer "+b64.EncodeToString(secret))
  req.Close=true
  res,e:=client.Do(req);if e!=nil{return nil,portableRefusal};defer res.Body.Close()
  expected:=200;if op=="send"{expected=202}
  if res.StatusCode!=expected{return nil,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(res.Body,23001))
  if e!=nil||len(raw)>23000||len(raw)<2||!json.Valid(raw){return nil,portableRefusal}
  var response map[string]json.RawMessage
  if json.Unmarshal(raw,&response)!=nil||response==nil{return nil,portableRefusal}
  // Only mailbox results, never arbitrary response fields (including headers).
  if op=="pull"||op=="recover"{if len(response)!=1||response["item"]==nil{return nil,portableRefusal}
  }else{if len(response)!=4||response["id"]==nil||response["digest"]==nil||response["status"]==nil||response["duplicate"]==nil{return nil,portableRefusal}}
  return raw,nil
 },close,nil
}
