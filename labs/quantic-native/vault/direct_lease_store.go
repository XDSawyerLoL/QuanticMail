package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "path/filepath"
)

// A dedicated journal for ONE independently pinned contact. The journal
// binding must be provisioned on independent witnesses before first use.
// Never share this journal with message operations. Caller owns exclusive
// journal handle, trusted clock, and revocation policy. No legacy fallback.
type directLeaseStore struct {
 j *replayLog
 dir string
 initial senderContact
 recipient,device string
 read func(string,int)([]byte,error)
 write func(string,[]byte)error
}
type directLeaseEntry struct {
 Accepted int64
 Proof directRenewProof
}
const directLeaseEntryMax=8192
const directLeaseHistoryMax=1024

// Bind the original approved contact and intended recipient to the independent
// checkpoint namespace. Roster pin and initial contact pin are not recovered
// from a restored local snapshot.
func directLeaseJournalID(initial senderContact,recipient,device,rosterPin string)(string,error){
 pin,e:=directContactCommit(initial)
 if e!=nil||!strongAddr.MatchString(recipient)||!strongDevice.MatchString(device)||
 recipient==initial.Address||device==initial.Device||!hashRE.MatchString(rosterPin){return "",portableRefusal}
 raw,e:=json.Marshal([]string{"quantic-direct-lease-journal/v1",pin,recipient,device,rosterPin})
 if e!=nil{return "",e};return hexHash(raw),nil
}
func newDirectLeaseStore(j *replayLog,dir string,initial senderContact,recipient,device,rosterPin string,
 read func(string,int)([]byte,error),write func(string,[]byte)error)(*directLeaseStore,error){
 id,e:=directLeaseJournalID(initial,recipient,device,rosterPin)
 if e!=nil||j==nil||j.failed||j.anchor==nil||j.anchorID!=id||!filepath.IsAbs(dir)||read==nil||write==nil{return nil,portableRefusal}
 q,ok:=j.anchor.(*quorumAnchor)
 if !ok||q.pin!=rosterPin{return nil,portableRefusal}
 // Copy all mutable public key bytes to retain the original pin.
 initial.ClassicalRoot=bytes.Clone(initial.ClassicalRoot)
 initial.PQRoot=bytes.Clone(initial.PQRoot)
 initial.Encryption=bytes.Clone(initial.Encryption)
 initial.KEM=bytes.Clone(initial.KEM)
 return &directLeaseStore{j,dir,initial,recipient,device,read,write},nil
}
func(s *directLeaseStore)path(index int)string{
 return filepath.Join(s.dir,fmt.Sprintf("lease-%04d.json",index))
}
func directLeaseDecode(raw []byte)(directLeaseEntry,error){
 var entry directLeaseEntry
 if len(raw)==0||len(raw)>directLeaseEntryMax{return entry,portableRefusal}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var extra any
 if d.Decode(&entry)!=nil||d.Decode(&extra)!=io.EOF{return entry,portableRefusal}
 canonical,e:=json.Marshal(entry)
 if e!=nil||!bytes.Equal(canonical,raw){return entry,portableRefusal}
 return entry,nil
}
func(s *directLeaseStore)check()error{
 if s==nil||s.j==nil||s.j.failed||s.j.anchor==nil||len(s.j.seen)>directLeaseHistoryMax{return portableRefusal}
 q,ok:=s.j.anchor.(*quorumAnchor);if !ok||q==nil{return portableRefusal}
 id,e:=directLeaseJournalID(s.initial,s.recipient,s.device,q.pin);if e!=nil{return e}
 return directRevocationCheck(s.j,id,q.pin)
}
// Historical proofs are verified at their recorded acceptance time, not at
// today's time; only the final lease can authorize a current mail operation.
func(s *directLeaseStore)load(now int64)(senderContact,error){
 var fail senderContact
 if now<=0{return fail,portableRefusal}
 if e:=s.check();e!=nil{return fail,e}
 current:=s.initial
 last:=int64(0)
 nonces:=map[string]bool{}
 for i:=0;i<len(s.j.seen);i++{
  raw,e:=s.read(s.path(i),directLeaseEntryMax);if e!=nil{return fail,e}
  if !s.j.seen[replayID("direct-lease-entry/v1",raw)]{return fail,portableRefusal}
  entry,e:=directLeaseDecode(raw);if e!=nil{return fail,e}
  q:=entry.Proof.Request
  if entry.Accepted<last||entry.Accepted>now||q.Recipient!=s.recipient||q.RecipientDevice!=s.device||nonces[q.Nonce]{return fail,portableRefusal}
  // Reconstruct historical challenge solely for verification of an already
  // independently committed entry. Live commits require a fresh pending object.
  pending:=directRenewPending{req:q}
  current,e=pending.accept(current,entry.Proof,entry.Accepted);if e!=nil{return fail,e}
  last=entry.Accepted;nonces[q.Nonce]=true
 }
 if e:=s.check();e!=nil{return fail,e}
 return current,nil
}
func(s *directLeaseStore)active(now int64)(senderContact,error){
 c,e:=s.load(now)
 if e!=nil||c.Expires<=now||c.Expires-now>directLeaseMax{return senderContact{},portableRefusal}
 return c,nil
}
func(s *directLeaseStore)begin(now int64)(*directRenewPending,error){
 old,e:=s.load(now);if e!=nil{return nil,e}
 return newDirectRenewPending(old,s.recipient,s.device,now)
}
func(s *directLeaseStore)commit(pending *directRenewPending,proof directRenewProof,now int64)(senderContact,error){
 var fail senderContact
 old,e:=s.load(now);if e!=nil{return fail,e}
 if pending==nil||len(s.j.seen)>=directLeaseHistoryMax||proof.Request.Recipient!=s.recipient||proof.Request.RecipientDevice!=s.device{return fail,portableRefusal}
 renewed,e:=pending.accept(old,proof,now);if e!=nil{return fail,e}
 raw,e:=json.Marshal(directLeaseEntry{now,proof});if e!=nil||len(raw)>directLeaseEntryMax{return fail,portableRefusal}
 path:=s.path(len(s.j.seen))
 // CREATE_NEW + fsync + exact readback BEFORE publishing the commitment.
 // A crash before checkpoint leaves an orphan; refuse automatic overwrite.
 if e=s.write(path,raw);e!=nil{return fail,e}
 saved,e:=s.read(path,directLeaseEntryMax);if e!=nil||!bytes.Equal(raw,saved){return fail,portableRefusal}
 if e=s.j.consume(replayID("direct-lease-entry/v1",raw));e!=nil{return fail,e}
 final,e:=s.active(now)
 if e!=nil||final.Expires!=renewed.Expires{return fail,portableRefusal}
 return final,nil
}
