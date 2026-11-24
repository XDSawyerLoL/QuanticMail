package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Test stores are independent files. In deployment these must reside on
// independently controlled machines, not four directories on one disk.
type directTestStore struct{ path, sign, enc, app, id string }
func (s directTestStore) check(id string,n int,h [32]byte)error{
 if id!=s.id{return portableRefusal}
 j,e:=openReplay(s.path,s.sign,s.enc,s.app);if e!=nil{return e};defer j.close()
 if len(j.seen)!=n||j.tail!=h{return portableRefusal};return nil
}
func(s directTestStore)advance(id string,n int,h,k [32]byte)error{
 if id!=s.id{return portableRefusal}
 j,e:=openReplay(s.path,s.sign,s.enc,s.app);if e!=nil{return e};defer j.close()
 if len(j.seen)!=n||j.tail!=h{return portableRefusal};return j.consume(k)
}
func TestDirectWitnessRollbackAndQuorum(t *testing.T){
 dir:=t.TempDir()
 sign,enc,app:=strings.Repeat("a",64),strings.Repeat("b",64),strings.Repeat("c",64)
 id:=strings.Repeat("d",64)
 path:=filepath.Join(dir,"vault")
 if e:=initReplay(path,sign,enc,app);e!=nil{t.Fatal(e)}
 initial,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 var members [4]directWitnessMember
 for i:=range members{
  pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  s:=directTestStore{filepath.Join(dir,string(rune('0'+i))),sign,enc,app,id}
  if e=initReplay(s.path,sign,enc,app);e!=nil{t.Fatal(e)}
  members[i]=directWitnessMember{pub,func(_ context.Context,q directWitnessRequest)([]byte,error){return signDirectWitness(q,id,s,key)}}
 }
 pin,e:=directWitnessRosterPin(members);if e!=nil{t.Fatal(e)}
 if _,e=newDirectPeerQuorum(members,strings.Repeat("f",64));e==nil{t.Fatal("wrong roster accepted")}
 duplicate:=members;duplicate[1]=duplicate[0]
 if _,e=directWitnessRosterPin(duplicate);e==nil{t.Fatal("duplicate witness accepted")}
 j,e:=openReplay(path,sign,enc,app);if e!=nil{t.Fatal(e)}
 if e=attachDirectPeerQuorum(j,id,members,pin);e!=nil{j.close();t.Fatal(e)}
 record:=[32]byte{42}
 if e=j.consume(record);e!=nil{j.close();t.Fatal(e)}
 count,tail:=len(j.seen),j.tail;j.close()
 q,e:=newDirectPeerQuorum(members,pin);if e!=nil{t.Fatal(e)}
 if e=q.check(id,count,tail);e!=nil{t.Fatal("durable witness state lost",e)}
 absent:=func(context.Context,directWitnessRequest)([]byte,error){return nil,errors.New("offline")}
 missing:=members;missing[0].Exchange=absent
 q,e=newDirectPeerQuorum(missing,pin);if e!=nil{t.Fatal(e)}
 if e=q.check(id,count,tail);e!=nil{t.Fatal("three witnesses refused",e)}
 missing[1].Exchange=absent
 q,e=newDirectPeerQuorum(missing,pin);if e!=nil{t.Fatal(e)}
 if e=q.check(id,count,tail);e==nil{t.Fatal("two witnesses accepted")}
 // A previously valid response must not authorize a new nonce.
 var saved []byte
 original:=members[0].Exchange
 members[0].Exchange=func(c context.Context,r directWitnessRequest)([]byte,error){
  if saved!=nil{return saved,nil}
  var err error;saved,err=original(c,r);return saved,err
 }
 peer:=directPeerAnchor{member:members[0]}
 if e=peer.check(id,count,tail);e!=nil{t.Fatal(e)}
 if e=peer.check(id,count,tail);e==nil{t.Fatal("stale response accepted")}
 // Replace the whole local journal with a formerly valid snapshot.
 if e=os.WriteFile(path,initial,0600);e!=nil{t.Fatal(e)}
 j,e=openReplay(path,sign,enc,app);if e!=nil{t.Fatal(e)};defer j.close()
 if e=attachDirectPeerQuorum(j,id,members,pin);e==nil{t.Fatal("rollback accepted")}
}
