//go:build (linux || windows) && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "strings"
 "testing"
 "time"
)

func TestDirectRenewalHybrid(t *testing.T){
 sk,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 ek,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 sign,e:=x509.MarshalPKIXPublicKey(&sk.PublicKey);if e!=nil{t.Fatal(e)}
 enc,e:=x509.MarshalPKIXPublicKey(&ek.PublicKey);if e!=nil{t.Fatal(e)}
 point:=elliptic.Marshal(elliptic.P256(),ek.X,ek.Y)
 device:="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(point[1:33])+":"+b64.EncodeToString(point[33:])))[:32]
 address:="bob~"+strings.Repeat("a",32)+"@quantic"
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)}
 defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)}
 defer dsa.close()
 p,e:=pqMake(kem,dsa,address,device);if e!=nil{t.Fatal(e)}
 now:=time.Now().UnixMilli()
 old:=senderContact{Address:address,Device:device,ClassicalRoot:sign,PQRoot:p.dsaPub,Encryption:enc,KEM:p.kemPub,Expires:now-1000}
 recipient:="alice~"+strings.Repeat("b",32)+"@quantic"
 receiver:="d-"+strings.Repeat("c",32)
 pending,e:=newDirectRenewPending(old,recipient,receiver,now);if e!=nil{t.Fatal(e)}
 expires:=now+23*3600000
 proof,e:=signDirectRenew(pending.req,expires,now,softwareSigner{sk},p);if e!=nil{t.Fatal(e)}
 if _,e=signDirectRenew(pending.req,now+directLeaseMax+1,now,softwareSigner{sk},p);e==nil{t.Fatal("unbounded lease")}
 bad:=proof;bad.Expires++
 if _,e=pending.accept(old,bad,now);e==nil{t.Fatal("changed lease accepted")}
 bad=proof;bad.Request.RecipientDevice="d-"+strings.Repeat("d",32)
 if _,e=pending.accept(old,bad,now);e==nil{t.Fatal("wrong recipient accepted")}
 bad=proof;bad.Auth.PQ=b64.EncodeToString(make([]byte,3309))
 if _,e=pending.accept(old,bad,now);e==nil{t.Fatal("invalid PQ signature accepted")}
 bad=proof;bad.Auth.Classical=b64.EncodeToString(make([]byte,64))
 if _,e=pending.accept(old,bad,now);e==nil{t.Fatal("invalid classical signature accepted")}
 changed:=old;changed.Expires--
 if _,e=pending.accept(changed,proof,now);e==nil{t.Fatal("changed old contact accepted")}
 if _,e=pending.accept(old,proof,now+directRenewWindow+1);e==nil{t.Fatal("expired challenge accepted")}
 other,e:=newDirectRenewPending(old,recipient,receiver,now);if e!=nil{t.Fatal(e)}
 if _,e=other.accept(old,proof,now);e==nil{t.Fatal("proof replayed against different challenge")}
 renewed,e:=pending.accept(old,proof,now);if e!=nil{t.Fatal(e)}
 if renewed.Expires!=expires||renewed.Address!=old.Address||renewed.Device!=old.Device||
 !bytes.Equal(renewed.ClassicalRoot,old.ClassicalRoot)||!bytes.Equal(renewed.PQRoot,old.PQRoot)||
 !bytes.Equal(renewed.Encryption,old.Encryption)||!bytes.Equal(renewed.KEM,old.KEM){t.Fatal("identity changed")}
 if _,e=pending.accept(old,proof,now);e==nil{t.Fatal("proof reused")}
}
