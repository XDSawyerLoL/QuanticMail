package main

import (
 stdcontext "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "errors"
 "time"
)

// Transport-independent protocol for four owner-controlled native witnesses.
// No HTTP, hosted service, silent local fallback, or implicit enrollment.
// The transport must authenticate the requesting vault and respect cancellation.
// Witness keys and durable ledgers must be outside the vault's rollback domain.
type directWitnessRequest struct {
 Op string
 ID string
 Count int
 Tail [32]byte
 Record [32]byte
 Nonce [32]byte
}
type directWitnessExchange func(stdcontext.Context,directWitnessRequest)([]byte,error)
type directWitnessMember struct {
 Public ed25519.PublicKey
 Exchange directWitnessExchange
}
type directPeerAnchor struct {
 member directWitnessMember
}
func directWitnessTranscript(q directWitnessRequest)([]byte,error){
 if !hashRE.MatchString(q.ID)||q.Count<0||q.Count>replayCap||q.Nonce==([32]byte{})||
 (q.Op!="check"&&q.Op!="advance")||(q.Op=="check"&&q.Record!=([32]byte{}))||
 (q.Op=="advance"&&q.Count>=replayCap){return nil,portableRefusal}
 return json.Marshal([]any{"quantic-direct-witness/v1",q.Op,q.ID,q.Count,hex.EncodeToString(q.Tail[:]),hex.EncodeToString(q.Record[:]),hex.EncodeToString(q.Nonce[:])})
}
// Call only after authenticating the vault and checking the bound witness
// enrollment. The backend MUST durably compare-and-swap before returning nil.
func signDirectWitness(q directWitnessRequest,authorizedID string,store checkpointAnchor,key ed25519.PrivateKey)([]byte,error){
 raw,e:=directWitnessTranscript(q)
 if e!=nil||authorizedID!=q.ID||store==nil||len(key)!=ed25519.PrivateKeySize{return nil,portableRefusal}
 if q.Op=="check"{e=store.check(q.ID,q.Count,q.Tail)}else{e=store.advance(q.ID,q.Count,q.Tail,q.Record)}
 if e!=nil{return nil,e}
 return ed25519.Sign(key,raw),nil
}
func(a *directPeerAnchor)call(q directWitnessRequest)error{
 if _,e:=rand.Read(q.Nonce[:]);e!=nil{return e}
 raw,e:=directWitnessTranscript(q);if e!=nil{return e}
 ctx,cancel:=stdcontext.WithTimeout(stdcontext.Background(),5*time.Second);defer cancel()
 type response struct{sig []byte;err error}
 done:=make(chan response,1)
 go func(){sig,e:=a.member.Exchange(ctx,q);done<-response{sig,e}}()
 select{
 case <-ctx.Done():return ctx.Err()
 case r:=<-done:
  if ctx.Err()!=nil||r.err!=nil||len(r.sig)!=ed25519.SignatureSize||!ed25519.Verify(a.member.Public,raw,r.sig){return errors.New("independent witness refused")}
  return nil
 }
}
func(a *directPeerAnchor)check(id string,count int,tail [32]byte)error{
 return a.call(directWitnessRequest{Op:"check",ID:id,Count:count,Tail:tail})
}
func(a *directPeerAnchor)advance(id string,count int,tail,record [32]byte)error{
 return a.call(directWitnessRequest{Op:"advance",ID:id,Count:count,Tail:tail,Record:record})
}
func directWitnessRosterPin(members [4]directWitnessMember)(string,error){
 pins:=make([]string,4)
 for i,m:=range members{
  if len(m.Public)!=ed25519.PublicKeySize||m.Exchange==nil{return "",portableRefusal}
  pins[i]=hexHash([]byte("quantic-direct-witness-key/v1\x00"+string(m.Public)))
 }
 return quorumPin(pins)
}
func newDirectPeerQuorum(members [4]directWitnessMember,independentPin string)(*quorumAnchor,error){
 pin,e:=directWitnessRosterPin(members)
 if e!=nil||pin!=independentPin{return nil,portableRefusal}
 q:=&quorumAnchor{pin:pin}
 for i,m:=range members{
  // Do not retain a mutable alias to the supplied public key.
  m.Public=append(ed25519.PublicKey(nil),m.Public...)
  q.members[i]=&directPeerAnchor{member:m}
 }
 return q,nil
}
// Explicit opt-in only. Never call from unanchored legacy/direct operation.
// The independent pin may not be recovered from the same restored snapshot.
func attachDirectPeerQuorum(j *replayLog,id string,members [4]directWitnessMember,independentPin string)error{
 if j==nil||j.anchor!=nil||j.failed{return portableRefusal}
 q,e:=newDirectPeerQuorum(members,independentPin);if e!=nil{return e}
 return j.attachAnchor(q,id)
}
