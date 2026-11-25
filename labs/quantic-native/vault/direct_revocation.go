package main

import "errors"

// Permanent, owner-authorized revocation of a single pinned relationship.
// The tombstone is part of the SAME checkpoint chain as the operations it
// disables. It requires no additional file or clock. There is no un-revoke
// operation, automatic new journal, or fallback to the original contact card.
var errDirectRevoked=errors.New("direct contact revoked")
func directRevocationRecord(id string)[32]byte{
 return replayID("quantic-direct-contact-revocation/v1",[]byte(id))
}
func directRevocationCheck(j *replayLog,id,pin string)error{
 if j==nil||j.failed||!hashRE.MatchString(id)||!hashRE.MatchString(pin)||j.anchorID!=id{return portableRefusal}
 q,ok:=j.anchor.(*quorumAnchor)
 if !ok||q==nil||q.pin!=pin{return portableRefusal}
 if e:=q.check(id,len(j.seen),j.tail);e!=nil{return e}
 if j.seen[directRevocationRecord(id)]{return errDirectRevoked}
 return nil
}
// Caller MUST hold the same exclusive journal lock used by renewal or mail.
// A lost quorum response is not a successful revocation; the divergent
// journal is quarantined and operations remain refused.
func commitDirectRevocation(j *replayLog,id,pin string,approve func()bool)error{
 e:=directRevocationCheck(j,id,pin)
 if e==errDirectRevoked{return nil} // independently verified idempotence
 if e!=nil{return e}
 if approve==nil||!approve(){return portableRefusal}
 if e=j.consume(directRevocationRecord(id));e!=nil{return e}
 if e=directRevocationCheck(j,id,pin);e!=errDirectRevoked{
  j.failed=true;return portableRefusal
 }
 return nil
}
// Revocation works even if the old lease is expired, the contact history
// cannot be read, or the remote correspondent is offline. Witnesses must
// still authorize the local tombstone.
func(s *directLeaseStore)revoke(approve func()bool)error{
 if s==nil||s.j==nil{return portableRefusal}
 q,ok:=s.j.anchor.(*quorumAnchor);if !ok||q==nil{return portableRefusal}
 id,e:=directLeaseJournalID(s.initial,s.recipient,s.device,q.pin);if e!=nil{return e}
 return commitDirectRevocation(s.j,id,q.pin,approve)
}
func revokeDirectIssuer(j *replayLog,self,peer senderContact,pin string,approve func()bool)error{
 id,e:=directRenewIssuerID(self,peer,pin);if e!=nil{return e}
 return commitDirectRevocation(j,id,pin,approve)
}
