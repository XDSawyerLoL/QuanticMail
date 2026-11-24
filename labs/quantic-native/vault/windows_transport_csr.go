//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/hmac"
 "crypto/sha256"
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "encoding/pem"
 "os"
 "path/filepath"
 "time"
)
type nativeTransportRequest struct {
 Format string `json:"format"`
 RequestDigest string `json:"requestDigest"`
 TokenHash string `json:"tokenHash"`
 AnchorCSR string `json:"anchorCsr"`
 CheckpointCSR string `json:"checkpointCsr"`
 Signature string `json:"signature"`
}
func transportSubject(digest,role string)string{return "quantic-lab-"+role+"-"+digest[:32]}
// Storage keys are independent of the network bearer.
func transportSecret(pw,pqw []byte)([]byte,error){
 secret,e:=credentialPassword(pw,pqw);if e!=nil{return nil,e};defer clear(secret)
 mac:=hmac.New(sha256.New,secret);mac.Write([]byte("quantic-transport-storage-secret-lab/v2\x00"));return mac.Sum(nil),nil
}
func readLocalTransportKey(dir,role,digest string,secret []byte,create bool)(*ecdsa.PrivateKey,[]byte,error){
 if !hashRE.MatchString(digest)||len(secret)!=32||(role!="anchor"&&role!="checkpoint"){return nil,nil,portableRefusal}
 header:=[]byte("QV-TRANSPORT-KEY-LAB-V2\x00"+digest+"\x00"+role+"\x00")
 // Refuse the prior plaintext format, never silently migrate or rotate it.
 if _,e:=os.Lstat(filepath.Join(dir,"peer-"+role+"-key.pem"));!os.IsNotExist(e){return nil,nil,portableRefusal}
 path:=filepath.Join(dir,"peer-"+role+"-key.vault")
 raw,e:=winReadPrivate(path,4096)
 if e!=nil&&create{
  if _,statErr:=os.Lstat(path);!os.IsNotExist(statErr){return nil,nil,portableRefusal}
  k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{return nil,nil,e}
  der,e:=x509.MarshalPKCS8PrivateKey(k);if e!=nil{return nil,nil,e};defer clear(der)
  salt:=make([]byte,16);if _,e=rand.Read(salt);e!=nil{return nil,nil,e}
  g,e:=portableAEAD(secret,salt);if e!=nil{return nil,nil,e}
  nonce:=make([]byte,g.NonceSize());if _,e=rand.Read(nonce);e!=nil{return nil,nil,e}
  aad:=append(append([]byte(nil),header...),salt...)
  prefix:=append(append([]byte(nil),aad...),nonce...)
  sealed:=g.Seal(prefix,nonce,der,aad);defer clear(sealed)
  if e=winWritePrivate(path,sealed);e!=nil{return nil,nil,e}
 }
 if e!=nil{raw,e=winReadPrivate(path,4096)}
 if e!=nil{return nil,nil,e};defer clear(raw)
 n:=len(header);if len(raw)<=n+16+12+16||!bytes.Equal(raw[:n],header){return nil,nil,portableRefusal}
 g,e:=portableAEAD(secret,raw[n:n+16]);if e!=nil{return nil,nil,e};n+=16
 der,e:=g.Open(nil,raw[n:n+g.NonceSize()],raw[n+g.NonceSize():],raw[:n])
 if e!=nil{return nil,nil,portableRefusal};defer clear(der)
 v,e:=x509.ParsePKCS8PrivateKey(der);if e!=nil{return nil,nil,e}
 key,ok:=v.(*ecdsa.PrivateKey);if !ok||key.Curve!=elliptic.P256(){return nil,nil,portableRefusal}
 // PEM is constructed only in memory for the existing Go TLS API.
 return key,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der}),nil
}
func nativeTransportTranscript(r nativeTransportRequest)([]byte,error){
 return json.Marshal([]string{r.Format,r.RequestDigest,r.TokenHash,hexHash([]byte(r.AnchorCSR)),hexHash([]byte(r.CheckpointCSR))})
}
// The caller has just authenticated both vaults and three independent votes.
// Reconfirm the credential and approval expiry before returning public CSRs.
func prepareWindowsTransportRequests(dir string,b enrollmentApprovalBundle,roster string,proof enrollmentCredential,digest string,pw,pqw []byte,now time.Time)(nativeTransportRequest,error){
 var empty nativeTransportRequest
 r,e:=readPendingEnrollment(dir);if e!=nil{return empty,e}
 actual,e:=checkEnrollmentApprovals(r,b,roster,now);if e!=nil||actual!=digest{return empty,portableRefusal}
 raw,e:=winReadPrivate(filepath.Join(dir,"mailbox-token.vault"),1024);if e!=nil{return empty,e};defer clear(raw)
 token,e:=openNativeMailboxCredential(raw,digest,pw,pqw);if e!=nil{return empty,e};defer clear(token)
 controller,e:=readSyntheticControllerKey(dir,syntheticProfile{ControllerPublic:r.ControllerPublic});if e!=nil{return empty,e};defer clear(controller)
 expected,e:=nativeMailboxCredentialProof(token,digest,controller)
 if e!=nil||expected!=proof{return empty,portableRefusal}
 secret,e:=transportSecret(pw,pqw);if e!=nil{return empty,e};defer clear(secret)
 out:=nativeTransportRequest{Format:"quantic-native-transport-csr-lab/v1",RequestDigest:digest,TokenHash:proof.TokenHash}
 var keyPins []string
 for _,role:=range []string{"anchor","checkpoint"}{
  key,raw,e:=readLocalTransportKey(dir,role,digest,secret,true);if e!=nil{return empty,e};clear(raw)
  spki,e:=x509.MarshalPKIXPublicKey(&key.PublicKey);if e!=nil{return empty,e}
  keyPins=append(keyPins,hexHash(spki))
  csr,e:=x509.CreateCertificateRequest(rand.Reader,&x509.CertificateRequest{Subject:pkix.Name{CommonName:transportSubject(digest,role)},SignatureAlgorithm:x509.ECDSAWithSHA256},key)
  if e!=nil{return empty,e}
  text:=b64.EncodeToString(csr)
  if role=="anchor"{out.AnchorCSR=text}else{out.CheckpointCSR=text}
 }
 if keyPins[0]==keyPins[1]{return empty,portableRefusal}
 if _,e=checkEnrollmentApprovals(r,b,roster,time.Now());e!=nil{return empty,e}
 tr,e:=nativeTransportTranscript(out);if e!=nil{return empty,e}
 out.Signature=b64.EncodeToString(ed25519.Sign(controller,tr))
 return out,nil
}
