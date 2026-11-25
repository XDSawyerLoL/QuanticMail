package main

import (
 stdcontext "context"
 "crypto/ecdsa"
 "crypto/sha256"
 "encoding/json"
 "math/big"
)

const directRenewLead int64=3600000
const directRenewDuration int64=23*3600000

// Requester authentication is independent of the issuer's renewal proof.
// An expired pinned card can be used ONLY for renewal, never for mail.
// Both callers must enforce revocation through an independent policy.
type directSignedRenewRequest struct{
 Request directRenewRequest
 PreviousExpiry int64
 Auth senderAuth
}
type directRenewExchange func(stdcontext.Context,directSignedRenewRequest)(directRenewProof,error)
func directRequestTranscript(q directRenewRequest,previousExpiry int64)([]byte,error){
 if previousExpiry<=0||previousExpiry-q.Issued>directLeaseMax{return nil,portableRefusal}
 return json.Marshal([]any{"quantic-direct-renew-request-auth/v1",q.Issuer,q.IssuerDevice,q.Recipient,q.RecipientDevice,q.Previous,q.Nonce,q.Issued,previousExpiry})
}
func signDirectRenewRequest(q directRenewRequest,previousExpiry,now int64,s signer,p *pqKeys)(directSignedRenewRequest,error){
 var fail directSignedRenewRequest
 if s==nil||p==nil||!directRenewValid(q,now)||q.Recipient!=p.address||q.RecipientDevice!=p.device{return fail,portableRefusal}
 raw,e:=directRequestTranscript(q,previousExpiry);if e!=nil{return fail,e}
 classical,e:=s.SignDigest(sha256.Sum256(raw));if e!=nil||len(classical)!=64{return fail,portableRefusal}
 pq,e:=p.dsa.sign(raw);if e!=nil||len(pq)!=3309{return fail,portableRefusal}
 return directSignedRenewRequest{q,previousExpiry,senderAuth{Classical:b64.EncodeToString(classical),PQ:b64.EncodeToString(pq)}},nil
}
func verifyDirectRenewRequest(r directSignedRenewRequest,peer senderContact,now int64)bool{
 q:=r.Request
 if !directRenewValid(q,now)||q.Recipient!=peer.Address||q.RecipientDevice!=peer.Device{return false}
 if _,e:=directContactCommit(peer);e!=nil{return false}
 raw,e:=directRequestTranscript(q,r.PreviousExpiry);if e!=nil{return false}
 classical,e:=decode(r.Auth.Classical,64,64);if e!=nil{return false}
 pq,e:=decode(r.Auth.PQ,3309,3309);if e!=nil{return false}
 pub,e:=senderPublic(peer.ClassicalRoot);if e!=nil{return false}
 h:=sha256.Sum256(raw)
 return ecdsa.Verify(pub,h[:],new(big.Int).SetBytes(classical[:32]),new(big.Int).SetBytes(classical[32:]))&&pqVerifyRoot(peer.PQRoot,raw,pq)
}
// The issuer's dedicated authorization journal must be pinned to this exact
// pair of identities. Lease expiry is not part of the journal namespace.
func directRenewIssuerID(self,peer senderContact,rosterPin string)(string,error){
 if _,e:=directContactCommit(self);e!=nil{return "",e}
 if _,e:=directContactCommit(peer);e!=nil{return "",e}
 if !hashRE.MatchString(rosterPin)||self.Address==peer.Address||self.Device==peer.Device{return "",portableRefusal}
 self.Expires=1;peer.Expires=1
 a,e:=directContactCommit(self);if e!=nil{return "",e}
 b,e:=directContactCommit(peer);if e!=nil{return "",e}
 raw,e:=json.Marshal([]string{"quantic-direct-renew-issuer/v1",a,b,rosterPin});if e!=nil{return "",e}
 return hexHash(raw),nil
}
// No signature released until the independently anchored one-shot operation
// commits. The caller owns an unlocked signer and explicit revocation policy.
func issueDirectRenew(r directSignedRenewRequest,self,peer senderContact,now int64,j *replayLog,rosterPin string,
 allowed func(senderContact)bool,s signer,p *pqKeys)(directRenewProof,error){
 var fail directRenewProof
 id,e:=directRenewIssuerID(self,peer,rosterPin)
 if e!=nil||j==nil||j.failed||j.anchorID!=id||allowed==nil||!allowed(peer)||s==nil||p==nil{return fail,portableRefusal}
 q,ok:=j.anchor.(*quorumAnchor);if !ok||q.pin!=rosterPin{return fail,portableRefusal}
 if !verifyDirectRenewRequest(r,peer,now)||r.Request.Issuer!=self.Address||r.Request.IssuerDevice!=self.Device||
 p.address!=self.Address||p.device!=self.Device||r.PreviousExpiry-now>directRenewLead{return fail,portableRefusal}
 self.Expires=r.PreviousExpiry
 previous,e:=directContactCommit(self);if e!=nil||previous!=r.Request.Previous{return fail,portableRefusal}
 expires:=now+directRenewDuration
 if expires<=r.PreviousExpiry||expires-r.Request.Issued>directLeaseMax{return fail,portableRefusal}
 if len(j.seen)>=replayCap-1{return fail,portableRefusal} // reserve final slot for revocation
 if e=directRevocationCheck(j,id,rosterPin);e!=nil{return fail,e}
 // Nonce is scoped to the pinned issuer/recipient journal; changed expiry or
 // authentication bytes cannot cause a second private signing operation.
 k:=replayID("direct-renew-issuer-nonce/v1",[]byte(r.Request.Nonce))
 raw,e:=j.reservePrivateSignature(k,func()([]byte,error){
  if !allowed(peer){return nil,portableRefusal}
  proof,e:=signDirectRenew(r.Request,expires,now,s,p);if e!=nil{return nil,e}
  return json.Marshal(proof)
 })
 if e!=nil||!allowed(peer){return fail,portableRefusal}
 if e=directRevocationCheck(j,id,rosterPin);e!=nil{return fail,e}
 if e=json.Unmarshal(raw,&fail);e!=nil{return directRenewProof{},e}
 return fail,nil
}
// One renewal attempt, not a background scheduler. No network activity if the
// current lease has more than an hour left. No retry on uncertain commit.
func runDirectRenewal(ctx stdcontext.Context,store *directLeaseStore,clock func()int64,allowed func(senderContact)bool,
 s signer,p *pqKeys,exchange directRenewExchange)(senderContact,error){
 var fail senderContact
 if ctx==nil||ctx.Err()!=nil||store==nil||clock==nil||allowed==nil||exchange==nil{return fail,portableRefusal}
 now:=clock()
 old,e:=store.load(now);if e!=nil||!allowed(old){return fail,portableRefusal}
 if old.Expires-now>directLeaseLeadLimit(){return store.active(now)}
 pending,e:=store.begin(now);if e!=nil{return fail,e}
 req,e:=signDirectRenewRequest(pending.req,old.Expires,now,s,p);if e!=nil{return fail,e}
 proof,e:=exchange(ctx,req);if e!=nil||ctx.Err()!=nil||!allowed(old){return fail,portableRefusal}
 finished:=clock()
 if finished<now{return fail,portableRefusal}
 return store.commit(pending,proof,finished)
}
func directLeaseLeadLimit()int64{return directRenewLead}
