package main

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdh"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/json"
 "strings"
 "unicode/utf8"
)

func recipientKey(s senderContact)(*ecdh.PublicKey,error){
 if len(s.Encryption)>256||len(s.KEM)!=1206{return nil,portableRefusal}
 k,e:=x509.ParsePKIXPublicKey(s.Encryption);if e!=nil{return nil,portableRefusal}
 // Go parses P-256 SPKI as ECDSA; convert to ECDH through its exact point.
 _=k
 p,e:=senderPublic(s.Encryption);if e!=nil{return nil,e}
 key,e:=p.ECDH();if e!=nil{return nil,e}
 b:=key.Bytes()
 if s.Device!="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(b[1:33])+":"+b64.EncodeToString(b[33:])) )[:32]{return nil,portableRefusal}
 return key,nil
}
func (p *pqKeys) sealOutgoing(s signer,c pqContext,recipient senderContact,plain []byte)(pqEnvelope,senderAuth,error){
 var v pqEnvelope;var a senderAuth
 if c.From!=p.address||c.FromDeviceID!=p.device||recipient.Address!=c.To||recipient.Device!=c.ToDeviceID||!msgID.MatchString(c.ClientMessageID)||!strongAddr.MatchString(c.To)||!strongDevice.MatchString(c.ToDeviceID)||len(plain)<1||len(plain)>maxPlain||!utf8.Valid(plain)||!json.Valid(plain){return v,a,portableRefusal}
 peer,e:=recipientKey(recipient);if e!=nil{return v,a,e}
 eph,e:=ecdh.P256().GenerateKey(rand.Reader);if e!=nil{return v,a,e}
 z,e:=eph.ECDH(peer);if e!=nil{return v,a,e};defer clear(z)
 kem,secret,e:=pqEncapPublic(recipient.KEM);if e!=nil{return v,a,e};defer clear(secret)
 ctx:=strings.Join([]string{"quantic-hybrid-envelope-context-v1",pqSuite,c.ClientMessageID,c.From,c.FromDeviceID,c.To,c.ToDeviceID},"\n")
 salt:=sha256.Sum256([]byte("quantic-hybrid-kdf-salt-v1\n"+ctx))
 mac:=hmac.New(sha256.New,salt[:]);mac.Write(z);mac.Write(secret);prk:=mac.Sum(nil);defer clear(prk)
 mac=hmac.New(sha256.New,prk);mac.Write([]byte(ctx));mac.Write([]byte{1});ak:=mac.Sum(nil);defer clear(ak)
 block,e:=aes.NewCipher(ak);if e!=nil{return v,a,e}
 g,e:=cipher.NewGCM(block);if e!=nil{return v,a,e}
 iv:=make([]byte,12);if _,e=rand.Read(iv);e!=nil{return v,a,e}
 pt:=eph.PublicKey().Bytes()
 v=pqEnvelope{CryptoSuite:pqSuite,KeyMode:"hybrid-static-fallback",Ephemeral:mailPublicJWK{Kty:"EC",Crv:"P-256",X:b64.EncodeToString(pt[1:33]),Y:b64.EncodeToString(pt[33:])},KEM:b64.EncodeToString(kem),IV:b64.EncodeToString(iv),Ciphertext:b64.EncodeToString(g.Seal(nil,iv,plain,[]byte(ctx+"\nquantic-aes-gcm-aad-v1")))}
 raw,e:=senderTranscript(c,v);if e!=nil{return pqEnvelope{},a,e}
 sig,e:=s.SignDigest(sha256.Sum256(raw));if e!=nil||len(sig)!=64{return pqEnvelope{},a,portableRefusal}
 ps,e:=p.dsa.sign(raw);if e!=nil{return pqEnvelope{},a,e}
 return v,senderAuth{Classical:b64.EncodeToString(sig),PQ:b64.EncodeToString(ps)},nil
}
