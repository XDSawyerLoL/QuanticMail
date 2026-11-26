//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "regexp"
)

// Separate domains, independent random salt/nonce, no raw network bearer.
func localCustodyDigest(r enrollmentRequest,role string)(string,error){
 if role!="controller"&&role!="receipt"&&role!="draft"{return "",portableRefusal}
 digest,e:=nativeEnrollmentDigest(r);if e!=nil{return "",e}
 return hexHash([]byte("quantic-local-custody-lab/v1\x00"+role+"\x00"+digest)),nil
}
func writeLocalCustody(dir,role string,r enrollmentRequest,value,pw,pqw []byte)error{
 digest,e:=localCustodyDigest(r,role);if e!=nil{return e}
 raw,e:=sealNativeMailboxCredential(value,digest,pw,pqw);if e!=nil{return e};defer clear(raw)
 return winWritePrivate(filepath.Join(dir,role+".vault"),raw)
}
func readLocalCustody(dir,role string,r enrollmentRequest,pw,pqw []byte)([]byte,error){
 digest,e:=localCustodyDigest(r,role);if e!=nil{return nil,e}
 old:="";if role=="controller"{old="controller.pem"}else if role=="receipt"{old="receipt.key"}
 if old!=""{if _,e=os.Lstat(filepath.Join(dir,old));!os.IsNotExist(e){return nil,portableRefusal}}
 raw,e:=winReadPrivate(filepath.Join(dir,role+".vault"),1024);if e!=nil{return nil,e};defer clear(raw)
 return openNativeMailboxCredential(raw,digest,pw,pqw)
}
func readEnrollmentController(dir string,r enrollmentRequest,pw,pqw []byte)(ed25519.PrivateKey,error){
 seed,e:=readLocalCustody(dir,"controller",r,pw,pqw);if e!=nil{return nil,e};defer clear(seed)
 key:=ed25519.NewKeyFromSeed(seed)
 pub,e:=appPublic(r.ControllerPublic);if e!=nil||!bytes.Equal(key.Public().(ed25519.PublicKey),pub){clear(key);return nil,portableRefusal}
 return key,nil
}

var receiptID=regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
type nativeReceiptPayload struct{Subject string `json:"subject"`;Body string `json:"body"`}
type nativeReceipt struct{
 Format string `json:"format"`
 Version int `json:"version"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 ID string `json:"id"`
 Digest string `json:"digest"`
 IV string `json:"iv"`
 Ciphertext string `json:"ciphertext"`
 Tag string `json:"tag"`
}
func exactReceiptDecode(raw []byte,v any)error{
 if len(raw)<2||len(raw)>24000{return portableRefusal}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var extra any;if d.Decode(v)!=nil||d.Decode(&extra)!=io.EOF{return portableRefusal};return nil
}
func receiptAAD(p nativeReceipt,address,device string)([]byte,error){
 if p.Format!="quantic-local-receipt"||p.Version!=1||p.Address!=address||p.DeviceID!=device||!strongAddr.MatchString(address)||!strongDevice.MatchString(device)||!receiptID.MatchString(p.ID)||!hashRE.MatchString(p.Digest){return nil,portableRefusal}
 return json.Marshal([]string{"quantic-local-receipt/v1",p.Address,p.DeviceID,p.ID,p.Digest})
}
func nativeReceiptCipher(key []byte)(cipher.AEAD,error){
 if len(key)!=32{return nil,portableRefusal};b,e:=aes.NewCipher(key);if e!=nil{return nil,e};return cipher.NewGCM(b)
}
func nativeReceiptTransport(address,device string,key []byte)(mailboxTransport,func(),error){
 g,e:=nativeReceiptCipher(key);if e!=nil{return nil,nil,e};closed:=false
 return func(op string,body json.RawMessage)(json.RawMessage,error){
  if closed{return nil,portableRefusal}
  switch op{
  case "receipt-seal":
   var q struct{ID string `json:"id"`;Digest string `json:"digest"`;Payload *nativeReceiptPayload `json:"payload"`}
   if e:=exactReceiptDecode(body,&q);e!=nil||q.Payload==nil{return nil,portableRefusal}
   p:=nativeReceipt{Format:"quantic-local-receipt",Version:1,Address:address,DeviceID:device,ID:q.ID,Digest:q.Digest}
   aad,e:=receiptAAD(p,address,device);if e!=nil{return nil,e}
   raw,e:=json.Marshal(q.Payload);if e!=nil||len(raw)>8192{return nil,portableRefusal};defer clear(raw)
   nonce:=make([]byte,12);if _,e=rand.Read(nonce);e!=nil{return nil,e}
   out:=g.Seal(nil,nonce,raw,aad);defer clear(out)
   p.IV=b64.EncodeToString(nonce);p.Ciphertext=b64.EncodeToString(out[:len(out)-16]);p.Tag=b64.EncodeToString(out[len(out)-16:])
   return json.Marshal(p)
  case "receipt-open":
   var p nativeReceipt;if e:=exactReceiptDecode(body,&p);e!=nil{return nil,e}
   aad,e:=receiptAAD(p,address,device);if e!=nil{return nil,e}
   iv,e:=decode(p.IV,12,12);if e!=nil{return nil,e};ct,e:=decode(p.Ciphertext,1,8192);if e!=nil{return nil,e};tag,e:=decode(p.Tag,16,16);if e!=nil{return nil,e}
   raw,e:=g.Open(nil,iv,append(ct,tag...),aad);if e!=nil{return nil,portableRefusal};defer clear(raw)
   var payload nativeReceiptPayload;if e=exactReceiptDecode(raw,&payload);e!=nil{return nil,e}
   return json.Marshal(struct{ID string `json:"id"`;Digest string `json:"digest"`;Payload nativeReceiptPayload `json:"payload"`}{p.ID,p.Digest,payload})
  }
  return nil,portableRefusal
 },func(){closed=true;g=nil},nil
}
