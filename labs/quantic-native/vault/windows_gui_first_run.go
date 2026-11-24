//go:build windows && cgo && pqopenssl

package main

// Synthetic, local-only first run. The locally generated "quorum" value is
// deliberately NOT an independent authority or Quantic ID enrollment.
// A successful unlock proves only local decryption and key consistency.
import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "encoding/pem"
 "io"
 "os"
 "path/filepath"
)

const syntheticProfileName="synthetic-profile.json"
type syntheticProfile struct {
 Version int `json:"version"`
 LabOnly bool `json:"labOnly"`
 RemotelyEnrolled bool `json:"remotelyEnrolled"`
 IndependentQuorum bool `json:"independentQuorum"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 QuorumPin string `json:"quorumPin"`
 ControllerPublic string `json:"controllerPublic"`
 SigningPin string `json:"signingPin"`
 EncryptionPin string `json:"encryptionPin"`
 KemPin string `json:"kemPin"`
 DsaPin string `json:"dsaPin"`
}
func validateSyntheticProfile(p syntheticProfile)error{
 if p.Version!=1||!p.LabOnly||p.RemotelyEnrolled||p.IndependentQuorum||
    !strongAddr.MatchString(p.Address)||!strongDevice.MatchString(p.DeviceID){return portableRefusal}
 for _,h:=range []string{p.QuorumPin,p.SigningPin,p.EncryptionPin,p.KemPin,p.DsaPin}{
  if !hashRE.MatchString(h){return portableRefusal}
 }
 pub,e:=b64.DecodeString(p.ControllerPublic)
 if e!=nil||len(pub)!=ed25519.PublicKeySize{return portableRefusal}
 return nil
}
func guiNewPassword(label string)([]byte,error){
 p,e:=winGUIPassphrase(label+" (20 caracteres ASCII minimum).",true);if e!=nil{return nil,e}
 if !validPortablePassword(p){clear(p);return nil,portableRefusal}
 confirmed,e:=winGUIPassphrase("Confirmer exactement : "+label,true)
 if e!=nil{clear(p);return nil,e}
 same:=equalSecret(p,confirmed);clear(confirmed)
 if !same{clear(p);return nil,portableRefusal}
 return p,nil
}
func createSyntheticGUIVault(parent string)(syntheticProfile,string,error){
 var empty syntheticProfile
 if _,_,e:=winPathParts(parent);e!=nil{return empty,"",e}
 hs,e:=winLockDirectory(parent,false);if e!=nil{return empty,"",e};defer winClose(hs)
 var name [16]byte;var quorum [32]byte
 if _,e=rand.Read(name[:]);e!=nil{return empty,"",e}
 if _,e=rand.Read(quorum[:]);e!=nil{return empty,"",e}
 token:=hex.EncodeToString(name[:])
 dir:=filepath.Join(parent,"quantic-test-"+token[:16])
 if _,_,e=winPathParts(dir);e!=nil{return empty,"",e}
 addr:="alpha~"+token+"@quantic"
 pin:=hex.EncodeToString(quorum[:])
 if !winGUIApprove("CREATION FICTIVE UNIQUEMENT. Deux secrets differents, aucun compte distant ni autorite independante. Creer un coffre prive neuf ?"){return empty,"",portableRefusal}
 pw,e:=guiNewPassword("Secret du coffre classique")
 if e!=nil{return empty,"",e};defer clear(pw)
 pqw,e:=guiNewPassword("Secret du coffre post-quantique")
 if e!=nil{return empty,"",e};defer clear(pqw)
 if equalSecret(pw,pqw){return empty,"",portableRefusal}
 result,e:=winProvisionAutoController(dir,pin,addr,pw,pqw)
 if e!=nil{return empty,"",e}
 p:=syntheticProfile{Version:1,LabOnly:true,Address:addr,QuorumPin:pin,
  DeviceID:result["deviceId"],ControllerPublic:result["controllerPublic"],
  SigningPin:result["signingPin"],EncryptionPin:result["encryptionPin"],
  KemPin:result["kemPin"],DsaPin:result["dsaPin"]}
 if e=validateSyntheticProfile(p);e!=nil{return empty,"",e}
 raw,e:=json.Marshal(p);if e!=nil{return empty,"",e};defer clear(raw)
 // Last write: failure leaves a non-reusable partial directory. No cleanup.
 if e=winWritePrivate(filepath.Join(dir,syntheticProfileName),append(raw,'\n'));e!=nil{return empty,"",e}
 return p,dir,nil
}
func readSyntheticGUIProfile(dir string)(syntheticProfile,error){
 var p syntheticProfile
 if _,_,e:=winPathParts(dir);e!=nil{return p,e}
 raw,e:=winReadPrivate(filepath.Join(dir,syntheticProfileName),4096)
 if e!=nil{return p,e};defer clear(raw)
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 if e=dec.Decode(&p);e!=nil{return syntheticProfile{},e}
 var extra any
 if e=dec.Decode(&extra);e!=io.EOF{return syntheticProfile{},portableRefusal}
 if e=validateSyntheticProfile(p);e!=nil{return syntheticProfile{},e}
 return p,nil
}
func openSyntheticGUIVault(dir string)(syntheticProfile,error){
 p,e:=readSyntheticGUIProfile(dir);if e!=nil{return syntheticProfile{},e}
 if !winGUIApprove("VERIFICATION LOCALE FICTIVE : aucun compte en ligne. Deverrouiller les deux coffres pour verifier les cles ?"){return syntheticProfile{},portableRefusal}
 pw,e:=winGUIPassphrase("Deverrouiller le coffre classique (secret local).",true)
 if e!=nil{return syntheticProfile{},e};defer clear(pw)
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+p.QuorumPin+"\x00",pw,p.SigningPin,p.EncryptionPin)
 clear(pw);if e!=nil{return syntheticProfile{},e}
 point:=k.agreement.PublicKey().Bytes()
 if len(point)!=65||p.DeviceID!="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(point[1:33])+":"+b64.EncodeToString(point[33:])))[:32]{
  return syntheticProfile{},portableRefusal
 }
 pub,e:=b64.DecodeString(p.ControllerPublic);if e!=nil{return syntheticProfile{},e}
 pemBytes,e:=winReadPrivate(filepath.Join(dir,"controller.pem"),4096)
 if e!=nil{return syntheticProfile{},e}
 block,_:=pem.Decode(pemBytes);clear(pemBytes)
 if block==nil{return syntheticProfile{},portableRefusal}
 pk,e:=x509.ParsePKCS8PrivateKey(block.Bytes);defer clear(block.Bytes)
 if e!=nil{return syntheticProfile{},e}
 private,ok:=pk.(ed25519.PrivateKey)
 if !ok||!bytes.Equal(private.Public().(ed25519.PublicKey),pub){return syntheticProfile{},portableRefusal}
 binding,e:=pqBinding(p.SigningPin,p.EncryptionPin,hexHash(pub),p.QuorumPin,p.Address,p.DeviceID)
 if e!=nil{return syntheticProfile{},e}
 pqw,e:=winGUIPassphrase("Deverrouiller le coffre post-quantique (secret distinct).",true)
 if e!=nil{return syntheticProfile{},e};defer clear(pqw)
 pq,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,p.Address,p.DeviceID,p.KemPin,p.DsaPin)
 clear(pqw);if e!=nil{return syntheticProfile{},e};pq.close()
 // This checks key consistency, NOT contact/authority or remote session.
 return p,nil
}
func winGUIFirstRun(args []string)error{
 if len(args)!=3{return portableRefusal}
 switch args[1]{
 case "--gui-create-synthetic-identity-lab":
  p,dir,e:=createSyntheticGUIVault(args[2]);if e!=nil{return e}
  return json.NewEncoder(os.Stdout).Encode(struct{
   Status string `json:"status"`
   Dir string `json:"dir"`
   Address string `json:"address"`
   LabOnly bool `json:"labOnly"`
   RemotelyEnrolled bool `json:"remotelyEnrolled"`
  }{Status:"synthetic-identity-created-local-only",Dir:dir,Address:p.Address,LabOnly:true})
 case "--gui-open-synthetic-identity-lab":
  p,e:=openSyntheticGUIVault(args[2]);if e!=nil{return e}
  return json.NewEncoder(os.Stdout).Encode(struct{
   Status string `json:"status"`
   Address string `json:"address"`
   LabOnly bool `json:"labOnly"`
   RemotelyEnrolled bool `json:"remotelyEnrolled"`
  }{Status:"synthetic-identity-keys-unlocked-local-only",Address:p.Address,LabOnly:true})
 }
 return portableRefusal
}
