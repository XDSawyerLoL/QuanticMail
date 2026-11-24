package main

import (
 "crypto/ecdsa"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "math/big"
 "sync"
)

const directRenewWindow int64 = 120000
const directLeaseMax int64 = 86400000

// The caller supplies the independently pinned contact, including its previous
// lease. An expired lease is not permission to send, only to request renewal.
// Revoked contacts must be removed by the caller, not passed to this protocol.
type directRenewRequest struct {
 Issuer string
 IssuerDevice string
 Recipient string
 RecipientDevice string
 Previous string
 Nonce string
 Issued int64
}
type directRenewProof struct {
 Request directRenewRequest
 Expires int64
 Auth senderAuth
}
type directRenewPending struct {
 mu sync.Mutex
 req directRenewRequest
 used bool
}
func directContactCommit(c senderContact)(string,error){
 if !strongAddr.MatchString(c.Address)||!strongDevice.MatchString(c.Device)||c.Expires<=0||len(c.PQRoot)!=1974{return "",portableRefusal}
 if _,e:=senderPublic(c.ClassicalRoot);e!=nil{return "",e}
 if _,e:=recipientKey(c);e!=nil{return "",e}
 raw,e:=json.Marshal(c);if e!=nil{return "",e}
 return hexHash(raw),nil
}
func directRenewValid(q directRenewRequest,now int64)bool{
 return now>0&&q.Issued>0&&q.Issued<=now&&now-q.Issued<=directRenewWindow&&
 strongAddr.MatchString(q.Issuer)&&strongDevice.MatchString(q.IssuerDevice)&&
 strongAddr.MatchString(q.Recipient)&&strongDevice.MatchString(q.RecipientDevice)&&
 q.Issuer!=q.Recipient&&q.IssuerDevice!=q.RecipientDevice&&
 hashRE.MatchString(q.Previous)&&hashRE.MatchString(q.Nonce)
}
func newDirectRenewPending(old senderContact,recipient,device string,now int64)(*directRenewPending,error){
 previous,e:=directContactCommit(old);if e!=nil{return nil,e}
 var nonce [32]byte
 if _,e=rand.Read(nonce[:]);e!=nil{return nil,e}
 q:=directRenewRequest{old.Address,old.Device,recipient,device,previous,hex.EncodeToString(nonce[:]),now}
 if !directRenewValid(q,now)||old.Expires-now>directLeaseMax{return nil,portableRefusal}
 return &directRenewPending{req:q},nil
}
func directRenewTranscript(q directRenewRequest,expires int64)([]byte,error){
 // Fixed field order and distinct domain; all string fields validated before use.
 return json.Marshal([]any{"quantic-direct-contact-renewal/v1",q.Issuer,q.IssuerDevice,q.Recipient,q.RecipientDevice,q.Previous,q.Nonce,q.Issued,expires})
}
func signDirectRenew(q directRenewRequest,expires,now int64,s signer,p *pqKeys)(directRenewProof,error){
 var out directRenewProof
 if s==nil||p==nil||!directRenewValid(q,now)||q.Issuer!=p.address||q.IssuerDevice!=p.device||
 expires<=now||expires-q.Issued>directLeaseMax{return out,portableRefusal}
 raw,e:=directRenewTranscript(q,expires);if e!=nil{return out,e}
 classical,e:=s.SignDigest(sha256.Sum256(raw));if e!=nil||len(classical)!=64{return out,portableRefusal}
 pq,e:=p.dsa.sign(raw);if e!=nil||len(pq)!=3309{return out,portableRefusal}
 return directRenewProof{q,expires,senderAuth{Classical:b64.EncodeToString(classical),PQ:b64.EncodeToString(pq)}},nil
}
func (p *directRenewPending) accept(old senderContact,proof directRenewProof,now int64)(senderContact,error){
 var fail senderContact
 if p==nil{return fail,portableRefusal}
 p.mu.Lock();defer p.mu.Unlock()
 q:=p.req
 previous,e:=directContactCommit(old)
 if e!=nil||p.used||!directRenewValid(q,now)||proof.Request!=q||previous!=q.Previous||
 old.Address!=q.Issuer||old.Device!=q.IssuerDevice||proof.Expires<=now||
 proof.Expires<=old.Expires||proof.Expires-q.Issued>directLeaseMax{return fail,portableRefusal}
 raw,e:=directRenewTranscript(q,proof.Expires);if e!=nil{return fail,e}
 classical,e:=decode(proof.Auth.Classical,64,64);if e!=nil{return fail,e}
 pq,e:=decode(proof.Auth.PQ,3309,3309);if e!=nil{return fail,e}
 pub,e:=senderPublic(old.ClassicalRoot);if e!=nil{return fail,e}
 h:=sha256.Sum256(raw)
 if !ecdsa.Verify(pub,h[:],new(big.Int).SetBytes(classical[:32]),new(big.Int).SetBytes(classical[32:]))||
 !pqVerifyRoot(old.PQRoot,raw,pq){return fail,portableRefusal}
 p.used=true
 old.Expires=proof.Expires
 return old,nil
}
