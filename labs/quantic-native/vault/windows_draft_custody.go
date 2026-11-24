//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/rand"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "unicode/utf8"
 "time"
)
var sealedDraftName=regexp.MustCompile("^draft-[0-9a-f]{32}[.]json$")
var draftMessageID=regexp.MustCompile("^qs-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
type nativeDraft struct{
 Context pqContext `json:"context"`
 Payload nativeReceiptPayload `json:"payload"`
}
type sealedNativeDraft struct{
 Format string `json:"format"`
 Version int `json:"version"`
 File string `json:"file"`
 IV string `json:"iv"`
 Ciphertext string `json:"ciphertext"`
}
func validateNativeDraft(d nativeDraft,name,address,device string)error{
 c:=d.Context
 if !sealedDraftName.MatchString(name)||!draftMessageID.MatchString(c.ClientMessageID)||name!="draft-"+strings.ReplaceAll(strings.TrimPrefix(c.ClientMessageID,"qs-"),"-","")+".json"||
 c.From!=address||c.FromDeviceID!=device||!strongAddr.MatchString(c.From)||!strongDevice.MatchString(c.FromDeviceID)||
 !strongAddr.MatchString(c.To)||!strongDevice.MatchString(c.ToDeviceID)||c.To==c.From||
 !utf8.ValidString(d.Payload.Subject)||!utf8.ValidString(d.Payload.Body)||strings.TrimSpace(d.Payload.Subject)==""||strings.TrimSpace(d.Payload.Body)==""||len([]rune(d.Payload.Subject))>160{return portableRefusal}
 return nil
}
func draftAAD(name,address,device string)[]byte{
 b,_:=json.Marshal([]string{"quantic-local-draft/v1",address,device,name});return b
}
func sealNativeDraft(key []byte,name,address,device string,d nativeDraft)(sealedNativeDraft,error){
 var p sealedNativeDraft
 if e:=validateNativeDraft(d,name,address,device);e!=nil{return p,e}
 raw,e:=json.Marshal(d);if e!=nil||len(raw)>8192{return p,portableRefusal};defer clear(raw)
 g,e:=nativeReceiptCipher(key);if e!=nil{return p,e}
 nonce:=make([]byte,12);if _,e=rand.Read(nonce);e!=nil{return p,e}
 ct:=g.Seal(nil,nonce,raw,draftAAD(name,address,device));defer clear(ct)
 return sealedNativeDraft{"quantic-local-draft",1,name,b64.EncodeToString(nonce),b64.EncodeToString(ct)},nil
}
func openNativeDraft(key []byte,name,address,device string,p sealedNativeDraft)(nativeDraft,error){
 var d nativeDraft
 if p.Format!="quantic-local-draft"||p.Version!=1||p.File!=name||!sealedDraftName.MatchString(name){return d,portableRefusal}
 g,e:=nativeReceiptCipher(key);if e!=nil{return d,e}
 nonce,e:=decode(p.IV,12,12);if e!=nil{return d,e}
 ct,e:=decode(p.Ciphertext,17,8208);if e!=nil{return d,e}
 raw,e:=g.Open(nil,nonce,ct,draftAAD(name,address,device));if e!=nil{return d,portableRefusal};defer clear(raw)
 if e=exactReceiptDecode(raw,&d);e!=nil{return nativeDraft{},e}
 if e=validateNativeDraft(d,name,address,device);e!=nil{return nativeDraft{},e};return d,nil
}
func saveNativeDraft(dir,name string,r enrollmentRequest,key []byte,d nativeDraft)error{
 c:=r.Claim
 if e:=validateNativeDraft(d,name,c.Address,c.DeviceID);e!=nil{return e}
 raw,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return e}
 trust,e:=parseSenderTrust(raw);if e!=nil{return e}
 peer,ok:=trust.contacts[senderKey(d.Context.To,d.Context.ToDeviceID)];if !ok||peer.Expires<=time.Now().UnixMilli(){return portableRefusal}
 p,e:=sealNativeDraft(key,name,c.Address,c.DeviceID,d);if e!=nil{return e}
 encoded,e:=json.Marshal(p);if e!=nil{return e}
 path:=filepath.Join(dir,name)
 if e=winWritePrivate(path,encoded);e!=nil{return e}
 stored,e:=winReadPrivate(path,24000);if e!=nil{return e}
 var reopened sealedNativeDraft
 if e=exactReceiptDecode(stored,&reopened);e!=nil{return e}
 actual,e:=openNativeDraft(key,name,c.Address,c.DeviceID,reopened)
 if e!=nil||actual!=d||!bytes.Equal(stored,encoded){return portableRefusal}
 return nil
}
func windowsSaveEncryptedDraftCLI(args []string)error{
 if len(args)!=4||!sealedDraftName.MatchString(args[3]){return portableRefusal}
 dir,name:=args[2],args[3]
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,8193));if e!=nil||len(raw)>8192{return portableRefusal};defer clear(raw)
 var d nativeDraft
 if e=exactReceiptDecode(raw,&d);e!=nil{return e}
 if e=validateNativeDraft(d,name,r.Claim.Address,r.Claim.DeviceID);e!=nil{return e}
 if !winGUIApprove("Enregistrer un brouillon chiffre local pour "+d.Context.To+" ? Aucun envoi ni connexion reseau."){return portableRefusal}
 pw,e:=winGUIPassphrase("Secret classique de l'appareil",true);if e!=nil{return e};defer clear(pw)
 pqw,e:=winGUIPassphrase("Secret post-quantique de l'appareil",true);if e!=nil{return e};defer clear(pqw)
 key,e:=readLocalCustody(dir,"draft",r,pw,pqw);if e!=nil{return e};defer clear(key)
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 return saveNativeDraft(dir,name,r,key,d)
}
func nativeDraftTransport(address,device string,key []byte)(mailboxTransport,func(),error){
 if len(key)!=32{return nil,nil,portableRefusal}
 secret:=append([]byte(nil),key...);closed:=false
 return func(op string,body json.RawMessage)(json.RawMessage,error){
  if closed||op!="draft-open"{return nil,portableRefusal}
  var q struct{File string `json:"file"`;Record sealedNativeDraft `json:"record"`}
  if e:=exactReceiptDecode(body,&q);e!=nil{return nil,e}
  d,e:=openNativeDraft(secret,q.File,address,device,q.Record);if e!=nil{return nil,e}
  return json.Marshal(d)
 },func(){closed=true;clear(secret)},nil
}
