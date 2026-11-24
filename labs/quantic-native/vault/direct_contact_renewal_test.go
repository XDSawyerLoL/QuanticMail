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
 "io"
 "os"
 "path/filepath"
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
 testDirectLeasePersistence(t,old,recipient,receiver,now,softwareSigner{sk},p)
}

func testDirectLeasePersistence(t *testing.T,old senderContact,recipient,receiver string,now int64,signer signer,p *pqKeys){
 t.Helper()
 path,sp,ep,app:=testJournal(t)
 initial,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 j,e:=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)}
 pin:=strings.Repeat("a",64)
 id,e:=directLeaseJournalID(old,recipient,receiver,pin);if e!=nil{j.close();t.Fatal(e)}
 q:=&quorumAnchor{pin:pin}
 var ws [4]*fakeAnchor
 for i:=range ws{ws[i]=&fakeAnchor{tail:j.tail};q.members[i]=ws[i]}
 dir:=filepath.Dir(path)
 read:=func(path string,max int)([]byte,error){
  raw,e:=os.ReadFile(path);if e!=nil{return nil,e}
  if len(raw)>max{return nil,portableRefusal};return raw,nil
 }
 write:=func(path string,raw []byte)error{
  f,e:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if e!=nil{return e}
  n,e:=f.Write(raw);if e==nil&&n!=len(raw){e=io.ErrShortWrite}
  if e==nil{e=f.Sync()};closeErr:=f.Close();if e==nil{e=closeErr};return e
 }
 makeStore:=func(j *replayLog)(*directLeaseStore,error){return newDirectLeaseStore(j,dir,old,recipient,receiver,pin,read,write)}
 if _,e=makeStore(j);e==nil{j.close();t.Fatal("unanchored store accepted")}
 if e=j.attachAnchor(q,id);e!=nil{j.close();t.Fatal(e)}
 s,e:=makeStore(j);if e!=nil{j.close();t.Fatal(e)}
 if _,e=s.active(now);e==nil{j.close();t.Fatal("expired original lease accepted")}
 pending,e:=s.begin(now);if e!=nil{j.close();t.Fatal(e)}
 expires:=now+23*3600000
 proof,e:=signDirectRenew(pending.req,expires,now,signer,p);if e!=nil{j.close();t.Fatal(e)}
 renewed,e:=s.commit(pending,proof,now);if e!=nil||renewed.Expires!=expires{j.close();t.Fatal("commit",e)}
 if _,e=s.commit(pending,proof,now);e==nil{j.close();t.Fatal("duplicate commit")}
 j.close()
 j,e=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)}
 if e=j.attachAnchor(q,id);e!=nil{j.close();t.Fatal(e)}
 s,e=makeStore(j);if e!=nil{j.close();t.Fatal(e)}
 renewed,e=s.active(now+directRenewWindow+1);if e!=nil||renewed.Expires!=expires{j.close();t.Fatal("restart",e)}
 if _,e=s.active(expires);e==nil{j.close();t.Fatal("expired renewed lease accepted")}
 if _,e=s.active(now-1);e==nil{j.close();t.Fatal("clock before acceptance")}
 entryPath:=s.path(0)
 raw,e:=os.ReadFile(entryPath);if e!=nil{j.close();t.Fatal(e)}
 if e=os.WriteFile(entryPath,append(bytes.Clone(raw),' '),0600);e!=nil{j.close();t.Fatal(e)}
 if _,e=s.active(now);e==nil{j.close();t.Fatal("tampered entry accepted")}
 if e=os.Remove(entryPath);e!=nil{j.close();t.Fatal(e)}
 if _,e=s.active(now);e==nil{j.close();t.Fatal("missing entry accepted")}
 if e=write(entryPath,raw);e!=nil{j.close();t.Fatal(e)}
 // A valid renewal is not activated when fewer than three witnesses can
 // commit it. Local state is intentionally quarantined on uncertain commit.
 later:=expires-3600000
 pending,e=s.begin(later);if e!=nil{j.close();t.Fatal(e)}
 proof,e=signDirectRenew(pending.req,later+23*3600000,later,signer,p);if e!=nil{j.close();t.Fatal(e)}
 // Pre-create an orphan at the next sequence; it must not be overwritten.
 orphan:=s.path(1)
 if e=write(orphan,[]byte("orphan"));e!=nil{j.close();t.Fatal(e)}
 if _,e=s.commit(pending,proof,later);e==nil{j.close();t.Fatal("overwrote orphan")}
 if b,e:=os.ReadFile(orphan);e!=nil||string(b)!="orphan"{j.close();t.Fatal("orphan changed")}
 if e=os.Remove(orphan);e!=nil{j.close();t.Fatal(e)}
 pending,e=s.begin(later);if e!=nil{j.close();t.Fatal(e)}
 proof,e=signDirectRenew(pending.req,later+23*3600000,later,signer,p);if e!=nil{j.close();t.Fatal(e)}
 // Failure is injected only after the pre-commit check, on advance.
 q.members[0]=directAdvanceRefusal{ws[0]}
 q.members[1]=directAdvanceRefusal{ws[1]}
 if _,e=s.commit(pending,proof,later);e==nil||!j.failed{j.close();t.Fatal("failed quorum released renewal")}
 j.close()
 if e=os.WriteFile(path,initial,0600);e!=nil{t.Fatal(e)}
 j,e=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)};defer j.close()
 if e=j.attachAnchor(q,id);e==nil{t.Fatal("old snapshot accepted")}
}
type directAdvanceRefusal struct{*fakeAnchor}
func(d directAdvanceRefusal)advance(string,int,[32]byte,[32]byte)error{return portableRefusal}

