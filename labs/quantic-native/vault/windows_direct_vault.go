//go:build windows && cgo && pqopenssl

package main

// New, explicitly local-only laboratory identities. No fallback from quorum
// mode. Trust is a short-lived, independently approved contact file. The
// journal resists accidental reuse, not rollback by the local administrator.
import (
 "bytes"
 "crypto/rand"
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "strings"
 "regexp"
 "time"
)

var directAlias=regexp.MustCompile("^[a-z0-9][a-z0-9._-]{2,31}$")
type directIdentity struct {
 Format string `json:"format"`
 Address string `json:"address"`
 Device string `json:"deviceId"`
 SigningPin string `json:"signingPin"`
 EncryptionPin string `json:"encryptionPin"`
 KemPin string `json:"kemPin"`
 DsaPin string `json:"dsaPin"`
 Signing string `json:"signing"`
 Encryption string `json:"encryption"`
 KemPublic string `json:"kemPublic"`
 DsaPublic string `json:"dsaPublic"`
 ControllerPublic string `json:"controllerPublic"`
 LocalPin string `json:"localPin"`
}
func directDecode(raw []byte,v any)error{
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var extra any
 if d.Decode(v)!=nil||d.Decode(&extra)!=io.EOF{return portableRefusal};return nil
}
func winProvisionDirect(dir,alias string,pw,pqw []byte)(directIdentity,error){
 var out directIdentity
 if !directAlias.MatchString(alias){return out,portableRefusal}
 var random [48]byte
 if _,e:=rand.Read(random[:]);e!=nil{return out,e};defer clear(random[:])
 addr:=alias+"~"+hex.EncodeToString(random[:16])+"@quantic"
 local:=hex.EncodeToString(random[16:])
 // This domain uses only a public controller identifier; private operations
 // occur inside the one-shot native GUI process, not a controller broker.
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{return out,e};clear(priv)
 app:=b64.EncodeToString(pub)
 m,e:=winProvisionVaultMode(dir,app,local,addr,pw,pqw,nil,true)
 if e!=nil{return out,e}
 out=directIdentity{"quantic-local-direct-identity/v1",addr,m["deviceId"],m["signingPin"],m["encryptionPin"],m["kemPin"],m["dsaPin"],m["signing"],m["encryption"],m["kemPublic"],m["dsaPublic"],app,local}
 raw,e:=json.Marshal(out);if e!=nil{return directIdentity{},e}
 if e=winWritePrivate(filepath.Join(dir,"direct-identity.json"),raw);e!=nil{return directIdentity{},e}
 return out,nil
}
func winReadDirectIdentity(dir string)(directIdentity,error){
 var id directIdentity
 raw,e:=winReadPrivate(filepath.Join(dir,"direct-identity.json"),16384);if e!=nil{return id,e}
 if directDecode(raw,&id)!=nil||id.Format!="quantic-local-direct-identity/v1"||!strongAddr.MatchString(id.Address)||!strongDevice.MatchString(id.Device){return id,portableRefusal}
 for _,pin:=range []string{id.SigningPin,id.EncryptionPin,id.KemPin,id.DsaPin,id.LocalPin}{if !hashRE.MatchString(pin){return id,portableRefusal}}
 pub,e:=appPublic(id.ControllerPublic);if e!=nil{return id,e}
 marker,e:=winReadPrivate(filepath.Join(dir,"direct-provisioned"),64);if e!=nil||string(marker)!=hexHash(pub){return id,portableRefusal}
 // A legacy or quorum marker is not accepted even alongside a direct one.
 if _,e=os.Lstat(filepath.Join(dir,"lab-provisioned"));!os.IsNotExist(e){return id,portableRefusal}
 return id,nil
}
func winDirectTrust(dir,pin string)(*senderTrust,error){
 if !hashRE.MatchString(pin){return nil,portableRefusal}
 raw,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return nil,e};defer clear(raw)
 if hexHash(raw)!=pin{return nil,portableRefusal}
 return parseSenderTrust(raw)
}
func winDirectImport(dir,pin string,raw []byte)error{
 id,e:=winReadDirectIdentity(dir);if e!=nil{return e}
 if !hashRE.MatchString(pin)||hexHash(raw)!=pin{return portableRefusal}
 t,e:=parseSenderTrust(raw);if e!=nil{return e}
 for _,s:=range t.contacts{
  if s.Address==id.Address||s.Device==id.Device{return portableRefusal}
  if _,e=recipientKey(s);e!=nil{return e}
 }
 return winWritePrivate(filepath.Join(dir,"contacts.json"),raw)
}
type directOperation struct{
 Op string `json:"op"`
 File string `json:"file"`
 ContactPin string `json:"contactPin"`
 Recover bool `json:"recover"`
}
type directDraft struct{
 Context pqContext `json:"context"`
 Payload json.RawMessage `json:"payload"`
}
type directWire struct{
 Format string `json:"format"`
 Version int `json:"version"`
 Context pqContext `json:"context"`
 Envelope pqEnvelope `json:"envelope"`
 Auth senderAuth `json:"senderAuth"`
}
func winDirectMail(dir string,op directOperation,prompt func(string,bool)([]byte,error),approve func(string)bool)(reply,error){
 var fail reply
 if op.Op!="seal"&&op.Op!="open"{return fail,portableRefusal}
 if op.Op=="seal"&&!clientDraftName.MatchString(op.File)||op.Op=="open"&&(!clientWireName.MatchString(op.File)||!strings.HasPrefix(op.File,"wire-in-")){return fail,portableRefusal}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return fail,e};defer winClose(hs)
 id,e:=winReadDirectIdentity(dir);if e!=nil{return fail,e}
 pub,e:=appPublic(id.ControllerPublic);if e!=nil{return fail,e}
 t,e:=winDirectTrust(dir,op.ContactPin);if e!=nil{return fail,e}
 if !approve("Ouvrir le coffre DIRECT LOCAL "+id.Address+" ? Sans quorum distant ; protection locale seulement."){return fail,portableRefusal}
 pw,e:=prompt("Phrase secrete classique",true);if e!=nil{return fail,e};defer clear(pw)
 local:=hexHash([]byte("quantic-direct-local-vault/v1\x00"+id.LocalPin))
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"direct-local-only:"+local+"\x00",pw,id.SigningPin,id.EncryptionPin);clear(pw);if e!=nil{return fail,e}
 binding,e:=pqBinding(id.SigningPin,id.EncryptionPin,hexHash(pub),local,id.Address,id.Device);if e!=nil{return fail,e}
 pqw,e:=prompt("Phrase secrete post-quantique",true);if e!=nil{return fail,e};defer clear(pqw)
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,id.Address,id.Device,id.KemPin,id.DsaPin);clear(pqw);if e!=nil{return fail,e};defer p.close()
 j,e:=winOpenReplay(filepath.Join(dir,"journal.log"),id.SigningPin,id.EncryptionPin,hexHash(pub));if e!=nil{return fail,e};defer j.close()
 if j.anchor!=nil{return fail,portableRefusal}
 j.anchorID=hexHash([]byte("quantic-direct-local-result/v1\x00"+local+"\x00"+id.Address+"\x00"+id.Device))
 var q request
 var logical [32]byte
 var contact senderContact
 var action func()(reply,error)
 if op.Op=="seal"{
  raw,e:=winReadEncryptedDraft(filepath.Join(dir,op.File));if e!=nil{return fail,e};defer clear(raw)
  var d directDraft
  if directDecode(raw,&d)!=nil||d.Context.From!=id.Address||d.Context.FromDeviceID!=id.Device||!msgID.MatchString(d.Context.ClientMessageID)||len(d.Payload)>maxPlain||!json.Valid(d.Payload){return fail,portableRefusal}
  var ok bool
  contact,ok=t.contacts[senderKey(d.Context.To,d.Context.ToDeviceID)];if !ok{return fail,portableRefusal}
  q=request{Op:"direct-seal-v1",PQContext:&d.Context,Message:b64.EncodeToString(d.Payload)}
  logical=replayID("direct-outgoing-id-v1",[]byte(d.Context.From+"\x00"+d.Context.FromDeviceID+"\x00"+d.Context.ClientMessageID))
  action=func()(reply,error){
   env,auth,e:=p.sealOutgoing(softwareSigner{k.signing},d.Context,contact,d.Payload);if e!=nil{return fail,e}
   return reply{OK:true,HybridEnvelope:&env,SenderAuth:&auth},nil
  }
 }else{
  raw,e:=winReadPrivate(filepath.Join(dir,op.File),32768);if e!=nil{return fail,e};defer clear(raw)
  var w directWire
  if directDecode(raw,&w)!=nil||w.Format!="quantic-native-mail"||w.Version!=1||w.Context.To!=id.Address||w.Context.ToDeviceID!=id.Device||!t.verify(w.Context,w.Envelope,&w.Auth,time.Now().UnixMilli()){return fail,portableRefusal}
  var ok bool
  contact,ok=t.contact(w.Context,time.Now().UnixMilli());if !ok{return fail,portableRefusal}
  q=request{Op:"direct-open-v1",PQContext:&w.Context,PQEnvelope:&w.Envelope,SenderAuth:&w.Auth}
  logical=replayID("direct-incoming-id-v1",[]byte(w.Context.From+"\x00"+w.Context.FromDeviceID+"\x00"+w.Context.ClientMessageID))
  action=func()(reply,error){
   plain,e:=p.open(k.agreement,w.Context,w.Envelope);if e!=nil{return fail,e};defer clear(plain)
   if !json.Valid(plain){return fail,portableRefusal}
   msg:=b64.EncodeToString(plain);return reply{OK:true,Message:&msg},nil
  }
 }
 req:=recoveryRequest(q)
 // No content in the dialog or stdout until explicit authorization.
 if !approve("Operation directe "+op.Op+" avec "+contact.Address+" / SHA256 "+hex.EncodeToString(req[:])){return fail,portableRefusal}
 if _,e=winDirectTrust(dir,op.ContactPin);e!=nil||contact.Expires<=time.Now().UnixMilli(){return fail,portableRefusal}
 var result reply
 if op.Recover{
  if !j.seen[logical]||j.failed{return fail,portableRefusal}
  result,e=p.readResult(j,logical,req)
 }else{
  if e=j.consume(logical);e!=nil{return fail,e}
  result,e=action()
  if e==nil{e=p.saveResult(j,logical,req,result)}
  if e==nil{result,e=p.readResult(j,logical,req)}
 }
 if e!=nil{return fail,e}
 if _,e=winDirectTrust(dir,op.ContactPin);e!=nil||contact.Expires<=time.Now().UnixMilli(){return fail,portableRefusal}
 if op.Op=="seal"{
  if result.HybridEnvelope==nil||result.SenderAuth==nil||result.Message!=nil{return fail,portableRefusal}
 }else if result.Message==nil||result.HybridEnvelope!=nil||result.SenderAuth!=nil{return fail,portableRefusal}
 return result,nil
}
func winDirectVaultCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
 switch args[1]{
 case "--provision-windows-direct-gui-lab":
  if len(args)!=4||!directAlias.MatchString(args[3]){return true,portableRefusal}
  if _,_,e:=winPathParts(args[2]);e!=nil{return true,e}
  if _,e:=os.Lstat(args[2]);!os.IsNotExist(e){return true,portableRefusal}
  if !winGUIApprove("Creer une NOUVELLE identite locale directe ? Aucun compte serveur ; journal local sans protection contre restauration malveillante."){return true,portableRefusal}
  pw,e:=winGUIConfirmSecret("Nouvelle phrase secrete classique");if e!=nil{return true,e};defer clear(pw)
  pqw,e:=winGUIConfirmSecret("Autre phrase secrete post-quantique");if e!=nil{return true,e};defer clear(pqw)
  out,e:=winProvisionDirect(args[2],args[3],pw,pqw);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(out)
 case "--import-windows-direct-contact-gui-lab":
  if len(args)!=4||!hashRE.MatchString(args[3]){return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,131073));if e!=nil||len(raw)>131072{return true,portableRefusal};defer clear(raw)
  if hexHash(raw)!=args[3]||!winGUIApprove("Approuver ce nouveau carnet DIRECT ? Empreinte independante : "+args[3]){return true,portableRefusal}
  return true,winDirectImport(args[2],args[3],raw)
 case "--windows-direct-mail-gui-lab":
  if len(args)!=3{return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,4097));if e!=nil||len(raw)>4096{return true,portableRefusal};defer clear(raw)
  var op directOperation
  if directDecode(raw,&op)!=nil{return true,portableRefusal}
  out,e:=winDirectMail(args[2],op,winGUISecret,winGUIApprove);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(out)
 }
 return false,nil
}
