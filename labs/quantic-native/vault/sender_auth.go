package main

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/sha256"
 "crypto/x509"
 "encoding/json"
 "io"
 "math/big"
 "os"
 "path/filepath"
 "time"
)

// Explicitly provisioned, owner-controlled public contact keys. This is
// short-lived local trust, NOT a distributed sender manifest or revocation.
type senderContact struct {
 Address string `json:"address"`
 Device string `json:"deviceId"`
 ClassicalRoot []byte `json:"classicalSigningSpki"`
 PQRoot []byte `json:"mlDsaSigningSpki"`
 Encryption []byte `json:"classicalEncryptionSpki,omitempty"`
 KEM []byte `json:"mlKemEncryptionSpki,omitempty"`
 Expires int64 `json:"expires"`
}
type senderTrust struct { contacts map[string]senderContact }
type senderAuth struct {
 Classical string `json:"classicalSignature"`
 PQ string `json:"pqSignature"`
}
func senderKey(address,device string)string{return address+"\x00"+device}
func senderPublic(raw []byte)(*ecdsa.PublicKey,error){
 if len(raw)>256{return nil,portableRefusal}
 key,e:=x509.ParsePKIXPublicKey(raw);if e!=nil{return nil,portableRefusal}
 p,ok:=key.(*ecdsa.PublicKey);if !ok||p.Curve!=elliptic.P256(){return nil,portableRefusal};return p,nil
}
func (t *senderTrust) contact(c pqContext,now int64)(senderContact,bool){
 if t==nil{return senderContact{},false}
 s,ok:=t.contacts[senderKey(c.From,c.FromDeviceID)]
 return s,ok&&s.Expires>now
}
func loadSenderTrust(path string)(*senderTrust,error){
 if !filepath.IsAbs(path){return nil,portableRefusal}
 if e:=checkPortableDirectory(filepath.Dir(path));e!=nil{return nil,e}
 info,e:=os.Lstat(path);if e!=nil||!info.Mode().IsRegular()||!privatePortableFile(info)||info.Size()>131072{return nil,portableRefusal}
 f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
 current,e:=f.Stat();if e!=nil||!os.SameFile(info,current){return nil,portableRefusal}
 raw,e:=io.ReadAll(io.LimitReader(f,131073));if e!=nil||len(raw)>131072{return nil,portableRefusal}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var list []senderContact;var extra any
 if d.Decode(&list)!=nil||d.Decode(&extra)!=io.EOF||len(list)<1||len(list)>32{return nil,portableRefusal}
 t:=&senderTrust{contacts:map[string]senderContact{}}
 now:=time.Now().UnixMilli()
 for _,s:=range list{
  if !strongAddr.MatchString(s.Address)||!strongDevice.MatchString(s.Device)||s.Expires<=now||s.Expires>now+86400000||len(s.PQRoot)!=1974{return nil,portableRefusal}
  if _,e:=senderPublic(s.ClassicalRoot);e!=nil{return nil,e}
  if len(s.Encryption)!=0||len(s.KEM)!=0{if _,e:=recipientKey(s);e!=nil{return nil,e}}
  key:=senderKey(s.Address,s.Device);if _,ok:=t.contacts[key];ok{return nil,portableRefusal};t.contacts[key]=s
 }
 return t,nil
}
func senderTranscript(c pqContext,v pqEnvelope)([]byte,error){
 if !msgID.MatchString(c.ClientMessageID)||!strongAddr.MatchString(c.From)||!strongDevice.MatchString(c.FromDeviceID)||!strongAddr.MatchString(c.To)||!strongDevice.MatchString(c.ToDeviceID)||v.CryptoSuite!=pqSuite||v.KeyMode!="hybrid-static-fallback"||v.Ephemeral.Kty!="EC"||v.Ephemeral.Crv!="P-256"||len(v.Ephemeral.KeyOps)!=0{return nil,portableRefusal}
 for _,x:=range []struct{s string;min,max int}{{v.Ephemeral.X,32,32},{v.Ephemeral.Y,32,32},{v.KEM,1088,1088},{v.IV,12,12},{v.Ciphertext,17,maxPlain+16}}{
  if _,e:=decode(x.s,x.min,x.max);e!=nil{return nil,e}
 }
 // No serialization ambiguity: validated ASCII fields, canonical fixed array.
 return json.Marshal([]string{"quantic-mail-sender-auth-lab/v1",c.ClientMessageID,c.From,c.FromDeviceID,c.To,c.ToDeviceID,v.CryptoSuite,v.KeyMode,v.Ephemeral.Kty,v.Ephemeral.Crv,v.Ephemeral.X,v.Ephemeral.Y,v.KEM,v.IV,v.Ciphertext})
}
func(t *senderTrust)verify(c pqContext,v pqEnvelope,a *senderAuth,now int64)bool{
 s,ok:=t.contact(c,now);if !ok||a==nil{return false}
 raw,e:=senderTranscript(c,v);if e!=nil{return false}
 sig,e:=decode(a.Classical,64,64);if e!=nil{return false}
 pq,e:=decode(a.PQ,3309,3309);if e!=nil{return false}
 key,e:=senderPublic(s.ClassicalRoot);if e!=nil{return false}
 digest:=sha256.Sum256(raw)
 return ecdsa.Verify(key,digest[:],new(big.Int).SetBytes(sig[:32]),new(big.Int).SetBytes(sig[32:]))&&pqVerifyRoot(s.PQRoot,raw,pq)
}
