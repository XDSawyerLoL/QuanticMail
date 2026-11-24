//go:build (linux || windows) && cgo && pqopenssl

package main

import (
 "crypto/ed25519"
 "crypto/x509"
 "encoding/json"
 "strconv"
 "time"
)
const possessionDomain="quantic-native-enrollment-possession-lab/v1"
const possessionResponseDomain="quantic-native-enrollment-possession-response-lab/v1"
type possessionChallenge struct {
 Format string `json:"format"`
 AuthorityPin string `json:"authorityPin"`
 AuthorityPublic string `json:"authorityPublic"`
 QuorumPin string `json:"quorumPin"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 ManifestDigest string `json:"manifestDigest"`
 ProfileDigest string `json:"profileDigest"`
 Nonce string `json:"nonce"`
 Expires int64 `json:"expires"`
 Envelope pqEnvelope `json:"envelope"`
 Signature string `json:"signature"`
}
type possessionResponse struct {
 Format string `json:"format"`
 ChallengeHash string `json:"challengeHash"`
 SecretHash string `json:"secretHash"`
 P256Signature string `json:"p256Signature"`
 MLDSASignature string `json:"mlDsaSignature"`
}
func possessionTranscript(c possessionChallenge)([]byte,error){
 v:=c.Envelope
 return json.Marshal([]string{possessionDomain,c.AuthorityPin,c.QuorumPin,c.Address,c.DeviceID,c.ManifestDigest,c.ProfileDigest,c.Nonce,strconv.FormatInt(c.Expires,10),
  v.CryptoSuite,v.KeyMode,v.Ephemeral.Kty,v.Ephemeral.Crv,v.Ephemeral.X,v.Ephemeral.Y,v.KEM,v.IV,v.Ciphertext})
}
func validatePossessionChallenge(c possessionChallenge,r enrollmentRequest,operatorPin string,now time.Time)([]byte,error){
 claim:=r.Claim
 if c.Format!=possessionDomain||r.Format!="quantic-native-enrollment-request-lab/v1"||
  claim.Format!="quantic-native-enrollment-claim-lab/v1"||claim.Version!=1||!claim.LabOnly||
  claim.Status!="signed-claim-not-enrolled"||claim.RemotelyEnrolled||claim.MailAuthorized||
  !strongAddr.MatchString(c.Address)||!strongDevice.MatchString(c.DeviceID)||
  c.Address!=claim.Address||c.DeviceID!=claim.DeviceID||c.QuorumPin!=r.QuorumPin||
  c.ManifestDigest!=claim.ManifestDigest||c.ProfileDigest!=claim.ProfileDigest||
  c.AuthorityPin!=operatorPin||now.IsZero()||c.Expires<=now.UnixMilli()||c.Expires-now.UnixMilli()>300000{
  return nil,portableRefusal
 }
 for _,v:=range []string{c.AuthorityPin,c.QuorumPin,c.ManifestDigest,c.ProfileDigest,c.Nonce,claim.SigningPin,claim.EncryptionPin,claim.KemPin,claim.DsaPin}{
  if !hashRE.MatchString(v){return nil,portableRefusal}
 }
 v:=c.Envelope
 if v.CryptoSuite!=pqSuite||v.KeyMode!="hybrid-static-fallback"||len(v.Ephemeral.KeyOps)!=0||
  v.Ephemeral.Kty!="EC"||v.Ephemeral.Crv!="P-256"{return nil,portableRefusal}
 for _,s:=range []struct{v string;n int}{{v.Ephemeral.X,32},{v.Ephemeral.Y,32},{v.KEM,1088},{v.IV,12},{v.Ciphertext,48}}{
  if _,e:=decode(s.v,s.n,s.n);e!=nil{return nil,portableRefusal}
 }
 der,e:=decode(c.AuthorityPublic,44,44);if e!=nil||hexHash(der)!=operatorPin{return nil,portableRefusal}
 parsed,e:=x509.ParsePKIXPublicKey(der);if e!=nil{return nil,portableRefusal}
 key,ok:=parsed.(ed25519.PublicKey);if !ok{return nil,portableRefusal}
 sig,e:=decode(c.Signature,64,64);if e!=nil{return nil,portableRefusal}
 raw,e:=possessionTranscript(c);if e!=nil||!ed25519.Verify(key,raw,sig){return nil,portableRefusal}
 return raw,nil
}
func answerPossessionChallenge(c possessionChallenge,r enrollmentRequest,operatorPin string,k portableKeys,p *pqKeys,now time.Time)(possessionResponse,error){
 var empty possessionResponse
 transcript,e:=validatePossessionChallenge(c,r,operatorPin,now);if e!=nil{return empty,e}
 claim:=r.Claim
 if k.signing==nil||k.agreement==nil||p==nil{return empty,portableRefusal}
 s,a:=portablePins(k)
 if s!=claim.SigningPin||a!=claim.EncryptionPin||p.kemPin!=claim.KemPin||p.dsaPin!=claim.DsaPin||p.address!=c.Address||p.device!=c.DeviceID{return empty,portableRefusal}
 context:=pqContext{"enroll-"+c.Nonce,c.Address,c.DeviceID,c.Address,c.DeviceID}
 secret,e:=p.open(k.agreement,context,c.Envelope)
 if e!=nil||len(secret)!=32{clear(secret);return empty,portableRefusal}
 defer clear(secret)
 challengeHash,secretHash:=hexHash(transcript),hexHash(secret)
 proof,e:=json.Marshal([]string{possessionResponseDomain,challengeHash,secretHash});if e!=nil{return empty,e}
 ps,e:=enrollmentSignature(k.signing,proof);if e!=nil{return empty,e}
 qs,e:=p.dsa.sign(proof);if e!=nil||!pqVerifyRoot(p.dsaPub,proof,qs){return empty,portableRefusal}
 return possessionResponse{possessionResponseDomain,challengeHash,secretHash,ps,b64.EncodeToString(qs)},nil
}
