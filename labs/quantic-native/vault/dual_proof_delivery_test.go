package main
import "testing"
func TestSelectDualProof(t *testing.T){
 a,b:=&dualLocalProof{sequence:1},&dualLocalProof{sequence:2}
 for _,v:=range [][]*dualLocalProof{{a,a,b,b},{a,a,nil,nil},{a,a,a},{nil,nil,nil,nil}}{
  if _,e:=selectDualProof(v);e==nil{t.Fatal("insufficient proof quorum accepted")}
 }
 p,e:=selectDualProof([]*dualLocalProof{a,a,a,b});if e!=nil||p.sequence!=1{t.Fatal("matching verified proofs refused")}
}
