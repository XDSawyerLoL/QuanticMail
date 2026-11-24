package main

import (
 "bytes"
 stdcontext "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "net"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestDirectWitnessUDPEndToEnd(t *testing.T){
 dir:=t.TempDir()
 sign,enc,app,id:=strings.Repeat("a",64),strings.Repeat("b",64),strings.Repeat("c",64),strings.Repeat("d",64)
 path:=filepath.Join(dir,"vault")
 if e:=initReplay(path,sign,enc,app);e!=nil{t.Fatal(e)}
 initial,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 ctx,cancel:=stdcontext.WithCancel(stdcontext.Background());defer cancel()
 var members [4]directWitnessMember
 var secret0 []byte
 var addr0 *net.UDPAddr
 for i:=range members{
  pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  secret:=make([]byte,32);if _,e=rand.Read(secret);e!=nil{t.Fatal(e)}
  s:=directTestStore{filepath.Join(dir,string(rune('0'+i))),sign,enc,app,id}
  if e=initReplay(s.path,sign,enc,app);e!=nil{t.Fatal(e)}
  sock,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if e!=nil{t.Fatal(e)}
  defer sock.Close()
  done:=make(chan error,1)
  go func(){done<-serveDirectUDPWitness(ctx,sock,secret,id,s,key)}()
  defer func(){cancel();<-done}()
  addr:=sock.LocalAddr().(*net.UDPAddr)
  exchange,e:=newDirectUDPExchange(addr,secret,id,pub);if e!=nil{t.Fatal(e)}
  members[i]=directWitnessMember{pub,exchange}
  if i==0{secret0=secret;addr0=addr}
 }
 pin,e:=directWitnessRosterPin(members);if e!=nil{t.Fatal(e)}
 j,e:=openReplay(path,sign,enc,app);if e!=nil{t.Fatal(e)}
 if e=attachDirectPeerQuorum(j,id,members,pin);e!=nil{j.close();t.Fatal(e)}
 record:=[32]byte{1,2,3}
 if e=j.consume(record);e!=nil{j.close();t.Fatal(e)}
 count,tail:=len(j.seen),j.tail;j.close()
 q,e:=newDirectPeerQuorum(members,pin);if e!=nil{t.Fatal(e)}
 if e=q.check(id,count,tail);e!=nil{t.Fatal("UDP checkpoint not persisted",e)}
 request:=directWitnessRequest{Op:"check",ID:id,Count:count,Tail:tail,Nonce:[32]byte{9}}
 keys,e:=makeDirectUDPKeys(secret0,id,members[0].Public);if e!=nil{t.Fatal(e)}
 raw,e:=json.Marshal(directUDPPayload{time.Now().UnixMilli(),request});if e!=nil{t.Fatal(e)}
 packet,e:=directUDPSeal(keys.request,raw);if e!=nil{t.Fatal(e)}
 if bytes.Contains(packet,[]byte(id)){t.Fatal("identity exposed in payload")}
 if _,e=directUDPOpen(keys.response,packet);e==nil{t.Fatal("direction confusion")}
 packet[len(packet)-1]^=1
 if _,e=directUDPOpen(keys.request,packet);e==nil{t.Fatal("modified datagram accepted")}
 old,e:=json.Marshal(directUDPPayload{time.Now().UnixMilli()-directUDPWindow-100,request});if e!=nil{t.Fatal(e)}
 if _,e=directUDPParse(old,time.Now().UnixMilli());e==nil{t.Fatal("stale datagram accepted")}
 wrong:=bytes.Clone(secret0);wrong[0]^=1
 ex,e:=newDirectUDPExchange(addr0,wrong,id,members[0].Public);if e!=nil{t.Fatal(e)}
 short,stop:=stdcontext.WithTimeout(ctx,150*time.Millisecond);defer stop()
 if _,e=ex(short,request);e==nil{t.Fatal("unauthorized request accepted")}
 ex,e=newDirectUDPExchange(addr0,secret0,id,members[0].Public);if e!=nil{t.Fatal(e)}
 request.ID=strings.Repeat("e",64)
 if _,e=ex(ctx,request);e==nil{t.Fatal("wrong journal identity accepted")}
 if _,e=newDirectUDPExchange(&net.UDPAddr{IP:net.IPv4(8,8,8,8),Port:1234},secret0,id,members[0].Public);e==nil{t.Fatal("public address accepted")}
 // Roll back local file while the four independent witness stores stay current.
 if e=os.WriteFile(path,initial,0600);e!=nil{t.Fatal(e)}
 j,e=openReplay(path,sign,enc,app);if e!=nil{t.Fatal(e)};defer j.close()
 if e=attachDirectPeerQuorum(j,id,members,pin);e==nil{t.Fatal("UDP quorum accepted rollback")}
}
