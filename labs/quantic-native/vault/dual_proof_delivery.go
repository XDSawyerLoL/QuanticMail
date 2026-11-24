package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// A startup-only read over the existing independently pinned mTLS witnesses.
// No network-supplied root is trusted: verifyDualLocalProof checks the
// independently configured root pin and exact canonical grant.
func (a *remoteAnchor) fetchDualProof(p anchorRequest) (dualProofWire,error) {
	var proof dualProofWire
	body,e:=json.Marshal(p)
	if e!=nil{return proof,e}
	r,e:=a.client.Post(a.endpoint+"/compact-proof","application/json",bytes.NewReader(body))
	if e!=nil{return proof,e};defer r.Body.Close()
	if r.StatusCode!=200||r.ContentLength<1||r.ContentLength>8192{return proof,errors.New("proof response refused")}
	raw,e:=io.ReadAll(io.LimitReader(r.Body,8193))
	if e!=nil||int64(len(raw))!=r.ContentLength{return proof,errors.New("proof response bounds")}
	d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
	var extra any
	if d.Decode(&proof)!=nil||d.Decode(&extra)!=io.EOF{return proof,errors.New("invalid proof response")}
	return proof,nil
}
func(q *freshQuorum) fetchDualLocalProof(id string,count int,tail [32]byte)(*dualLocalProof,error){
	if q.q==nil||q.dualRootPin==""||q.pqBinding==""{return nil,portableRefusal}
	p:=anchorRequest{ID:id,Count:count,Tail:hex.EncodeToString(tail[:]),PQBinding:q.pqBinding}
	results:=make(chan *dualLocalProof,4)
	for _,m:=range q.q.members{
		a,ok:=m.(*remoteAnchor);if !ok{return nil,portableRefusal}
		go func(a *remoteAnchor){
			wire,e:=a.fetchDualProof(p);if e!=nil{results<-nil;return}
			proof,e:=q.verifyDualLocalProof(id,wire);if e!=nil{results<-nil;return}
			results<-proof
		}(a)
	}
	proofs:=make([]*dualLocalProof,0,4)
	for i:=0;i<4;i++{proofs=append(proofs,<-results)}
	return selectDualProof(proofs)
}
func selectDualProof(proofs []*dualLocalProof)(*dualLocalProof,error){
	if len(proofs)!=4{return nil,portableRefusal}
	counts:=map[int64]int{}
	for _,p:=range proofs{if p!=nil&&p.sequence>0{counts[p.sequence]++}}
	for seq,count:=range counts{if count>=3{return &dualLocalProof{sequence:seq},nil}}
	return nil,errors.New("no three independently verified matching proofs")
}
