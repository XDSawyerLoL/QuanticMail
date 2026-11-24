package main

import (
 "os"
 "strings"
 "testing"
)

func TestDirectRevocationDurable(t *testing.T){
 path,sp,ep,app:=testJournal(t)
 snapshot,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 id,pin:=strings.Repeat("a",64),strings.Repeat("b",64)
 j,e:=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)}
 q:=&quorumAnchor{pin:pin}
 var ws [4]*fakeAnchor
 for i:=range ws{ws[i]=&fakeAnchor{tail:j.tail};q.members[i]=ws[i]}
 if e=commitDirectRevocation(j,id,pin,func()bool{return true});e==nil{j.close();t.Fatal("unanchored revoke accepted")}
 if e=j.attachAnchor(q,id);e!=nil{j.close();t.Fatal(e)}
 if e=commitDirectRevocation(j,id,pin,func()bool{return false});e==nil||len(j.seen)!=0{j.close();t.Fatal("unapproved revoke")}
 if e=commitDirectRevocation(j,id,strings.Repeat("c",64),func()bool{return true});e==nil{j.close();t.Fatal("wrong roster")}
 if e=commitDirectRevocation(j,id,pin,func()bool{return true});e!=nil{j.close();t.Fatal(e)}
 if e=directRevocationCheck(j,id,pin);e!=errDirectRevoked{j.close();t.Fatal("not revoked",e)}
 if e=commitDirectRevocation(j,id,pin,nil);e!=nil||len(j.seen)!=1{j.close();t.Fatal("idempotence",e)}
 j.close()
 j,e=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)}
 if e=j.attachAnchor(q,id);e!=nil{j.close();t.Fatal(e)}
 if e=directRevocationCheck(j,id,pin);e!=errDirectRevoked{j.close();t.Fatal("restart lost revocation",e)}
 ws[0].fail=true;ws[1].fail=true
 if e=directRevocationCheck(j,id,pin);e==nil{j.close();t.Fatal("no quorum allowed")}
 ws[0].fail=false;ws[1].fail=false
 j.close()
 if e=os.WriteFile(path,snapshot,0600);e!=nil{t.Fatal(e)}
 j,e=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)};defer j.close()
 if e=j.attachAnchor(q,id);e==nil{t.Fatal("restoration removed revocation")}
}
func TestDirectRevocationUncertainCommit(t *testing.T){
 path,sp,ep,app:=testJournal(t)
 j,e:=openReplay(path,sp,ep,app);if e!=nil{t.Fatal(e)};defer j.close()
 id,pin:=strings.Repeat("a",64),strings.Repeat("b",64)
 q:=&quorumAnchor{pin:pin}
 for i:=range q.members{q.members[i]=&fakeAnchor{tail:j.tail}}
 if e=j.attachAnchor(q,id);e!=nil{t.Fatal(e)}
 q.members[0]=directRevocationRejectAdvance{q.members[0]}
 q.members[1]=directRevocationRejectAdvance{q.members[1]}
 if e=commitDirectRevocation(j,id,pin,func()bool{return true});e==nil||!j.failed{t.Fatal("uncertain revocation reported success")}
 if e=directRevocationCheck(j,id,pin);e==nil{t.Fatal("uncertain state accepted")}
}
type directRevocationRejectAdvance struct{checkpointAnchor}
func(d directRevocationRejectAdvance)advance(string,int,[32]byte,[32]byte)error{return portableRefusal}
