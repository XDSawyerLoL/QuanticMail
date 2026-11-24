//go:build (linux || windows) && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/binary"
 "encoding/json"
 "sort"
 "time"
)

type enrollmentRosterEntry struct {
 Pin string `json:"pin"`
 PublicKey string `json:"publicKey"`
}
type enrollmentVotePayload struct {
 Format string `json:"format"`
 AuthorityPin string `json:"authorityPin"`
 RosterPin string `json:"rosterPin"`
 RequestDigest string `json:"requestDigest"`
 ProofDigest string `json:"proofDigest"`
 IssuedAt int64 `json:"issuedAt"`
 Expires int64 `json:"expires"`
 Decision string `json:"decision"`
}
type enrollmentVote struct {
 Payload enrollmentVotePayload `json:"payload"`
 Signature string `json:"signature"`
}
type enrollmentApprovalBundle struct {
 Format string `json:"format"`
 Trusted []enrollmentRosterEntry `json:"trusted"`
 Votes []enrollmentVote `json:"votes"`
}
type enrollmentCredential struct {
 TokenHash string `json:"tokenHash"`
 Signature string `json:"signature"`
}
func nativeEnrollmentDigest(r enrollmentRequest)(string,error){
 c:=r.Claim
 if r.Format!="quantic-native-enrollment-request-lab/v1"||!c.LabOnly||c.RemotelyEnrolled||c.MailAuthorized||c.Status!="signed-claim-not-enrolled"||
 !strongAddr.MatchString(c.Address)||!strongDevice.MatchString(c.DeviceID){return "",portableRefusal}
 for _,v:=range []string{c.RootPin,c.PQRootPin,c.SigningPin,c.EncryptionPin,c.KemPin,c.DsaPin,c.ManifestDigest,c.ProfileDigest,r.QuorumPin}{
  if !hashRE.MatchString(v){return "",portableRefusal}
 }
 if _,e:=decode(r.ControllerPublic,32,32);e!=nil{return "",e}
 raw,e:=json.Marshal([]string{"quantic-enrollment-claim-binding-lab/v1",c.Address,c.DeviceID,c.RootPin,c.PQRootPin,c.SigningPin,c.EncryptionPin,c.KemPin,c.DsaPin,c.ManifestDigest,c.ProfileDigest,r.QuorumPin,r.ControllerPublic})
 if e!=nil{return "",e};return hexHash(raw),nil
}
func nativeEnrollmentVoteTranscript(v enrollmentVotePayload)([]byte,error){
 return json.Marshal([]any{v.Format,v.AuthorityPin,v.RosterPin,v.RequestDigest,v.ProofDigest,v.IssuedAt,v.Expires,v.Decision})
}
func checkEnrollmentApprovals(r enrollmentRequest,b enrollmentApprovalBundle,pin string,now time.Time)(string,error){
 digest,e:=nativeEnrollmentDigest(r);if e!=nil{return "",e}
 if b.Format!="quantic-enrollment-approvals-lab/v1"||!hashRE.MatchString(pin)||len(b.Trusted)!=4||len(b.Votes)<3||len(b.Votes)>4||now.IsZero(){return "",portableRefusal}
 keys:=map[string]ed25519.PublicKey{}
 pins:=[]string{}
 for _,entry:=range b.Trusted{
  der,e:=decode(entry.PublicKey,44,44);if e!=nil||hexHash(der)!=entry.Pin||keys[entry.Pin]!=nil{return "",portableRefusal}
  v,e:=x509.ParsePKIXPublicKey(der);if e!=nil{return "",portableRefusal}
  k,ok:=v.(ed25519.PublicKey);if !ok{return "",portableRefusal}
  keys[entry.Pin]=k;pins=append(pins,entry.Pin)
 }
 sort.Strings(pins)
 roster,_:=json.Marshal(append([]string{"quantic-enrollment-roster-lab/v1","3-of-4"},pins...))
 if hexHash(roster)!=pin{return "",portableRefusal}
 seen:=map[string]bool{};proofs:=map[string]bool{}
 ts:=now.UnixMilli()
 for _,vote:=range b.Votes{
  v:=vote.Payload
  if v.Format!="quantic-native-enrollment-vote-lab/v1"||v.Decision!="approve"||v.RosterPin!=pin||v.RequestDigest!=digest||
   !hashRE.MatchString(v.ProofDigest)||v.IssuedAt<=0||v.IssuedAt>ts||ts-v.IssuedAt>=900000||v.Expires!=v.IssuedAt+900000||
   keys[v.AuthorityPin]==nil||seen[v.AuthorityPin]||proofs[v.ProofDigest]{continue}
  raw,e:=nativeEnrollmentVoteTranscript(v);sig,se:=decode(vote.Signature,64,64)
  if e!=nil||se!=nil||!ed25519.Verify(keys[v.AuthorityPin],raw,sig){continue}
  seen[v.AuthorityPin]=true;proofs[v.ProofDigest]=true
 }
 if len(seen)<3{return "",portableRefusal}
 return digest,nil
}
func credentialHeader(digest string)[]byte{return []byte("QV-MAILBOX-CREDENTIAL-LAB-V1\x00"+digest+"\x00")}
func credentialPassword(pw,pqw []byte)([]byte,error){
 if !validPortablePassword(pw)||!validPortablePassword(pqw)||equalSecret(pw,pqw){return nil,portableRefusal}
 h:=sha256.New();h.Write([]byte("quantic-mailbox-two-secrets-lab/v1\x00"))
 var length [4]byte
 for _,p:=range [][]byte{pw,pqw}{binary.BigEndian.PutUint32(length[:],uint32(len(p)));h.Write(length[:]);h.Write(p)}
 return h.Sum(nil),nil
}
func sealNativeMailboxCredential(token []byte,digest string,pw,pqw []byte)([]byte,error){
 if len(token)!=32||!hashRE.MatchString(digest){return nil,portableRefusal}
 secret,e:=credentialPassword(pw,pqw);if e!=nil{return nil,e};defer clear(secret)
 var salt [16]byte;var nonce [12]byte
 if _,e=rand.Read(salt[:]);e!=nil{return nil,e};if _,e=rand.Read(nonce[:]);e!=nil{return nil,e}
 aead,e:=portableAEAD(secret,salt[:]);if e!=nil{return nil,e}
 header:=append(credentialHeader(digest),salt[:]...);header=append(header,nonce[:]...)
 return aead.Seal(header,nonce[:],token,header),nil
}
func openNativeMailboxCredential(raw []byte,digest string,pw,pqw []byte)([]byte,error){
 if !hashRE.MatchString(digest){return nil,portableRefusal}
 prefix:=credentialHeader(digest);n:=len(prefix)
 if len(raw)!=n+16+12+32+16||!bytes.Equal(prefix,raw[:n]){return nil,portableRefusal}
 secret,e:=credentialPassword(pw,pqw);if e!=nil{return nil,e};defer clear(secret)
 aead,e:=portableAEAD(secret,raw[n:n+16]);if e!=nil{return nil,e}
 b,e:=aead.Open(nil,raw[n+16:n+28],raw[n+28:],raw[:n+28])
 if e!=nil||len(b)!=32{clear(b);return nil,portableRefusal};return b,nil
}
func nativeMailboxCredentialProof(token []byte,digest string,key ed25519.PrivateKey)(enrollmentCredential,error){
 if len(token)!=32||!hashRE.MatchString(digest)||len(key)!=ed25519.PrivateKeySize{return enrollmentCredential{},portableRefusal}
 encoded:=make([]byte,b64.EncodedLen(len(token)));b64.Encode(encoded,token);defer clear(encoded)
 hash:=hexHash(encoded)
 msg,e:=json.Marshal([]string{"quantic-native-mailbox-credential-lab/v1",digest,hash});if e!=nil{return enrollmentCredential{},e}
 return enrollmentCredential{hash,b64.EncodeToString(ed25519.Sign(key,msg))},nil
}
