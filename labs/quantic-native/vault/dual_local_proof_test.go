package main

import (
 "strings"
 "testing"
)
func TestLocalProofSequenceRequired(t *testing.T){
 q:=freshQuorum{pqBinding:strings.Repeat("a",64),dualRootPin:strings.Repeat("b",64),pqAddress:"alice~"+strings.Repeat("c",32)+"@quantic",pqDevice:"d-"+strings.Repeat("d",32),pqKemPin:strings.Repeat("e",64),pqDsaPin:strings.Repeat("f",64),localProof:&dualLocalProof{sequence:1}}
 d,_:=q.expectedDualDigest(2)
 v:=manifestVote{Sequence:1,Digest:strings.Repeat("1",64),Expires:2000,ProfileSequence:2,ProfileDigest:d,PQBinding:q.pqBinding}
 if q.accept([]manifestVote{v,v,v,v},1000)==nil{t.Fatal("new sequence without locally verified proof accepted")}
}
