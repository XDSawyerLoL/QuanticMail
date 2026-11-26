// Package vaultsession verifies the native Identity Vault pq-proof-lab
// protocol. It proves possession of a pinned device key, not permission to
// administer the operating system. No private key is handled by this package.
package vaultsession

import (
 "crypto/rand"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "regexp"
 "sync"
 "time"
)

var (
 addressPattern=regexp.MustCompile("^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$")
 devicePattern=regexp.MustCompile("^d-[0-9a-f]{32}$")
 machinePattern=regexp.MustCompile("^[a-zA-Z0-9._-]{1,128}$")
 pinPattern=regexp.MustCompile("^[0-9a-f]{64}$")
)
const maxLifetime=30*time.Second
type Identity struct {
 Address string
 Device string
 KEMPin string
 DSAPin string
 DSAPublicDER []byte
}
type Request struct {
 Op string `json:"op"`
 PQChallenge string `json:"pqChallenge"`
}
type Reply struct {
 OK bool `json:"ok"`
 PQProof string `json:"pqProof"`
}
type Session struct{
 mu sync.Mutex
 identity Identity
 machineID string
 brokerController ed25519.PublicKey
 revoked bool
 authorizationUsed bool
 challenge [32]byte
 born time.Time
 consumed bool
 exchangeStarted bool
}
func New(id Identity,machineID string,now time.Time)(*Session,error){
 if !addressPattern.MatchString(id.Address)||!devicePattern.MatchString(id.Device)||
  !machinePattern.MatchString(machineID)||!pinPattern.MatchString(id.KEMPin)||
  !pinPattern.MatchString(id.DSAPin)||len(id.DSAPublicDER)!=1974||now.IsZero(){
  return nil,errors.New("invalid pinned Vault identity or machine")
 }
 // Caller MUST obtain this pin from an independently trusted enrollment,
 // never from the proof reply or untrusted local file.
 digest:=sha256.Sum256(id.DSAPublicDER)
 if hex.EncodeToString(digest[:])!=id.DSAPin{return nil,errors.New("Vault public key pin mismatch")}
 if !providerAvailable(){return nil,errors.New("ML-DSA-65 verifier unavailable")}
 var nonce [32]byte
 if _,err:=rand.Read(nonce[:]);err!=nil{return nil,err}
 b:=append([]byte("quantic-sentinel/device-auth/v1\x00"+machineID+"\x00"),nonce[:]...)
 id.DSAPublicDER=append([]byte(nil),id.DSAPublicDER...)
 return &Session{identity:id,machineID:machineID,challenge:sha256.Sum256(b),born:now},nil
}
func(s *Session) Request()Request{
 return Request{Op:"pq-proof-lab",PQChallenge:base64.RawURLEncoding.EncodeToString(s.challenge[:])}
}
func(s *Session) message()[]byte{
 id:=s.identity
 // Exact existing Identity Vault pqKeys.proof message, not a new signing API.
 return append([]byte("quantic-pq-device-proof-lab/v1\x00"+id.Address+"\x00"+id.Device+"\x00"+id.KEMPin+id.DSAPin),s.challenge[:]...)
}
// Verify consumes one outstanding challenge. A successful proof only attests
// the pinned Vault key; no privileged operation or policy is authorized.
func(s *Session) Verify(raw []byte,now time.Time)error{
 s.mu.Lock();defer s.mu.Unlock()
 if s.revoked||s.consumed||now.Before(s.born)||now.Sub(s.born)>=maxLifetime{return errors.New("Vault challenge expired or consumed")}
 if len(raw)==0||len(raw)>8192{return errors.New("invalid Vault reply size")}
 var r Reply
 if err:=json.Unmarshal(raw,&r);err!=nil||!r.OK{return errors.New("Vault refused or invalid reply")}
 sig,err:=base64.RawURLEncoding.DecodeString(r.PQProof)
 if err!=nil||len(sig)!=3309||base64.RawURLEncoding.EncodeToString(sig)!=r.PQProof{return errors.New("invalid ML-DSA-65 proof encoding")}
 if !verifyMLDSA65(s.identity.DSAPublicDER,s.message(),sig){return errors.New("Vault proof invalid")}
 s.consumed=true
 return nil
}
