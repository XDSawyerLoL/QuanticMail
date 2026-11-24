//go:build windows && cgo && pqopenssl

package main

// Synthetic-only signed contact invitations. These establish continuity of a
// self-attested local controller key, NOT identity authority approval or an
// authorized address book. Validated candidates are never placed in
// contacts.json and cannot be used by the real encrypted-mail broker.
import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "encoding/pem"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"
)
const syntheticCardPrefix="QSALPHA1:"
const syntheticCardDomain="quantic-alpha-contact-candidate/v1\x00"
type syntheticCardPayload struct {
 Version int `json:"version"`
 LabOnly bool `json:"labOnly"`
 IndependentlyVerified bool `json:"independentlyVerified"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 ControllerPublic string `json:"controllerPublic"`
 SigningPin string `json:"signingPin"`
 EncryptionPin string `json:"encryptionPin"`
 KemPin string `json:"kemPin"`
 DsaPin string `json:"dsaPin"`
 IssuedAt int64 `json:"issuedAt"`
 ExpiresAt int64 `json:"expiresAt"`
 Nonce string `json:"nonce"`
}
type syntheticCard struct {
 Payload syntheticCardPayload `json:"payload"`
 Signature string `json:"signature"`
}
type syntheticContactCandidate struct {
 Status string `json:"status"`
 Address string `json:"address"`
 Fingerprint string `json:"fingerprint"`
 LabOnly bool `json:"labOnly"`
 IndependentlyVerified bool `json:"independentlyVerified"`
 MailAuthorized bool `json:"mailAuthorized"`
}
func cardBytes(p syntheticCardPayload)([]byte,error){
 b,e:=json.Marshal(p);if e!=nil{return nil,e}
 return append([]byte(syntheticCardDomain),b...),nil
}
func newSyntheticCard(p syntheticProfile,key ed25519.PrivateKey,now int64)(string,string,error){
 var nonce [16]byte
 if _,e:=rand.Read(nonce[:]);e!=nil{return "","",e}
 claim:=syntheticCardPayload{
  Version:1,LabOnly:true,Address:p.Address,DeviceID:p.DeviceID,
  ControllerPublic:p.ControllerPublic,SigningPin:p.SigningPin,
  EncryptionPin:p.EncryptionPin,KemPin:p.KemPin,DsaPin:p.DsaPin,
  IssuedAt:now,ExpiresAt:now+24*3600,
  Nonce:hex.EncodeToString(nonce[:]),
 }
 raw,e:=cardBytes(claim);if e!=nil{return "","",e}
 signature:=ed25519.Sign(key,raw)
 enc,e:=json.Marshal(syntheticCard{Payload:claim,
  Signature:base64.RawURLEncoding.EncodeToString(signature)})
 if e!=nil{return "","",e}
 code:=syntheticCardPrefix+base64.RawURLEncoding.EncodeToString(enc)
 if len(code)>4096{return "","",portableRefusal}
 candidate,e:=verifySyntheticCard(code,"",now)
 if e!=nil{return "","",e}
 return code,candidate.Fingerprint,nil
}
func verifySyntheticCard(code,ownAddress string,now int64)(syntheticContactCandidate,error){
 var none syntheticContactCandidate
 if !strings.HasPrefix(code,syntheticCardPrefix)||len(code)<150||len(code)>4096||now<1{return none,portableRefusal}
 encoded:=strings.TrimPrefix(code,syntheticCardPrefix)
 raw,e:=base64.RawURLEncoding.DecodeString(encoded)
 if e!=nil||base64.RawURLEncoding.EncodeToString(raw)!=encoded||len(raw)>3000{return none,portableRefusal}
 var c syntheticCard
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e=d.Decode(&c);e!=nil{return none,portableRefusal}
 var trailing any
 if e=d.Decode(&trailing);e!=io.EOF{return none,portableRefusal}
 p:=c.Payload
 if p.Version!=1||!p.LabOnly||p.IndependentlyVerified||
   !strongAddr.MatchString(p.Address)||p.Address==ownAddress||
   !strongDevice.MatchString(p.DeviceID)||
   p.IssuedAt>now+300||p.IssuedAt<now-24*3600||p.ExpiresAt!=p.IssuedAt+24*3600||p.ExpiresAt<=now||
   len(p.Nonce)!=32{return none,portableRefusal}
 if _,e=hex.DecodeString(p.Nonce);e!=nil{return none,portableRefusal}
 for _,h:=range []string{p.SigningPin,p.EncryptionPin,p.KemPin,p.DsaPin}{
  if !hashRE.MatchString(h){return none,portableRefusal}
 }
 pub,e:=base64.RawURLEncoding.DecodeString(p.ControllerPublic)
 if e!=nil||len(pub)!=ed25519.PublicKeySize||base64.RawURLEncoding.EncodeToString(pub)!=p.ControllerPublic{return none,portableRefusal}
 sig,e:=base64.RawURLEncoding.DecodeString(c.Signature)
 if e!=nil||len(sig)!=ed25519.SignatureSize||base64.RawURLEncoding.EncodeToString(sig)!=c.Signature{return none,portableRefusal}
 signed,e:=cardBytes(p);if e!=nil||!ed25519.Verify(pub,signed,sig){return none,portableRefusal}
 fingerprint:=sha256.Sum256(append([]byte("synthetic-self-attested-fingerprint/v1\x00"),pub...))
 return syntheticContactCandidate{
  Status:"contact-candidate-not-trusted",
  Address:p.Address,
  Fingerprint:hex.EncodeToString(fingerprint[:12]),
  LabOnly:true,IndependentlyVerified:false,MailAuthorized:false,
 },nil
}
func readSyntheticControllerKey(dir string,p syntheticProfile)(ed25519.PrivateKey,error){
 raw,e:=winReadPrivate(filepath.Join(dir,"controller.pem"),4096)
 if e!=nil{return nil,e}
 defer clear(raw)
 block,_:=pem.Decode(raw)
 if block==nil||block.Type!="PRIVATE KEY"{return nil,portableRefusal}
 defer clear(block.Bytes)
 value,e:=x509.ParsePKCS8PrivateKey(block.Bytes)
 if e!=nil{return nil,e}
 key,ok:=value.(ed25519.PrivateKey)
 if !ok{return nil,portableRefusal}
 expected,e:=base64.RawURLEncoding.DecodeString(p.ControllerPublic)
 if e!=nil||!bytes.Equal(key.Public().(ed25519.PublicKey),expected){clear(key);return nil,portableRefusal}
 return key,nil
}
func winGUIContactCard(args []string)error{
 if len(args)!=3{return portableRefusal}
 dir:=args[2]
 switch args[1]{
 case "--gui-share-synthetic-contact-card-lab":
  // The two credential dialogs prove human possession of both vault secrets.
  p,e:=openSyntheticGUIVault(dir);if e!=nil{return e}
  key,e:=readSyntheticControllerKey(dir,p);if e!=nil{return e};defer clear(key)
  code,fp,e:=newSyntheticCard(p,key,time.Now().Unix());if e!=nil{return e}
  return json.NewEncoder(os.Stdout).Encode(struct {
   Status string `json:"status"`
   Address string `json:"address"`
   Fingerprint string `json:"fingerprint"`
   Code string `json:"code"`
   LabOnly bool `json:"labOnly"`
   MailAuthorized bool `json:"mailAuthorized"`
  }{Status:"synthetic-card-self-signed-not-authorized",Address:p.Address,
   Fingerprint:fp,Code:code,LabOnly:true})
 case "--gui-add-synthetic-contact-candidate-lab":
  p,e:=readSyntheticGUIProfile(dir);if e!=nil{return e}
  input,e:=io.ReadAll(io.LimitReader(os.Stdin,4097))
  if e!=nil||len(input)<150||len(input)>4096{return portableRefusal}
  code:=strings.TrimSpace(string(input))
  candidate,e:=verifySyntheticCard(code,p.Address,time.Now().Unix())
  if e!=nil{return e}
  if !winGUIApprove("CARTE AUTO-SIGNEE FICTIVE, PAS UNE AUTORITE. Comparer son empreinte avec votre contact: "+candidate.Fingerprint+". Sauver en attente seulement ?"){return portableRefusal}
  // Deterministic path rejects silent replacement of previously reviewed
  // identities and refuses any overwrite of live contacts.json.
  destination:=filepath.Join(dir,"candidate-"+candidate.Fingerprint+".json")
  if _,_,e=winPathParts(destination);e!=nil{return e}
  record,e:=json.Marshal(struct{
   Card string `json:"card"`
   Status string `json:"status"`
   MailAuthorized bool `json:"mailAuthorized"`
  }{Card:code,Status:"pending-external-verification"})
  if e!=nil{return e};defer clear(record)
  if e=winWritePrivate(destination,append(record,'\n'));e!=nil{return e}
  return json.NewEncoder(os.Stdout).Encode(candidate)
 }
 return portableRefusal
}
