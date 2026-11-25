//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 stdcontext "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "path/filepath"
 "testing"
 "time"
)

func TestWindowsProtectedDirectMail(t *testing.T){
 root:=t.TempDir()
 var keys [4]ed25519.PrivateKey
 var template [4]directWitnessMember
 for i:=range keys{
  pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  keys[i]=key
  template[i]=directWitnessMember{pub,func(stdcontext.Context,directWitnessRequest)([]byte,error){return nil,portableRefusal}}
 }
 roster,e:=directWitnessRosterPin(template);if e!=nil{t.Fatal(e)}
 pass:=[]byte("Synthetic protected classical passphrase only")
 pqpass:=[]byte("Different synthetic protected PQ passphrase")
 dir:=filepath.Join(root,"a")
 self,e:=winProvisionDirectMode(dir,"alice",pass,pqpass,roster);if e!=nil{t.Fatal(e)}
 peer,e:=winProvisionDirect(filepath.Join(root,"b"),"bobby",pass,pqpass);if e!=nil{t.Fatal(e)}
 if _,e=winReadDirectIdentity(dir);e==nil{t.Fatal("protected identity opened in local mode")}
 local:=hexHash([]byte("quantic-direct-local-vault/v1\x00"+roster))
 if _,e=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"direct-local-only:"+local+"\x00",pass,self.SigningPin,self.EncryptionPin);e==nil{t.Fatal("legacy key domain opened protected vault")}
 contact:=fixtureContact(t,map[string]string{"address":peer.Address,"deviceId":peer.Device,"signing":peer.Signing,"encryption":peer.Encryption,"kemPublic":peer.KemPublic,"dsaPublic":peer.DsaPublic})
 contact.Expires=time.Now().Add(time.Hour).UnixMilli()
 raw,e:=json.Marshal([]senderContact{contact});if e!=nil{t.Fatal(e)}
 pin:=hexHash(raw)
 if e=winDirectImportMode(dir,pin,raw,true);e!=nil{t.Fatal(e)}
 leaseDir:=filepath.Join(dir,"renewal")
 if e=winCreatePrivateDirectory(leaseDir);e!=nil{t.Fatal(e)}
 leaseID,e:=directLeaseJournalID(contact,self.Address,self.Device,roster);if e!=nil{t.Fatal(e)}
 if e=winInitReplay(filepath.Join(leaseDir,"lease-journal.log"),self.SigningPin,self.EncryptionPin,leaseID);e!=nil{t.Fatal(e)}
 makeMembers:=func(label,id,app string)[4]directWitnessMember{
  result:=template
  for i:=range result{
   path:=filepath.Join(root,label+string(rune('0'+i)))
   if e:=initReplay(path,self.SigningPin,self.EncryptionPin,app);e!=nil{t.Fatal(e)}
   store:=directTestStore{path,self.SigningPin,self.EncryptionPin,app,id}
   key:=keys[i]
   result[i].Exchange=func(_ stdcontext.Context,q directWitnessRequest)([]byte,error){return signDirectWitness(q,id,store,key)}
  }
  return result
 }
 leaseMembers:=makeMembers("l",leaseID,leaseID)
 pub,e:=appPublic(self.ControllerPublic);if e!=nil{t.Fatal(e)}
 mailMembers:=makeMembers("m",directProtectedMailID(self),hexHash(pub))
 lease,e:=winOpenDirectLeaseStore(leaseDir,self,contact,leaseMembers,roster);if e!=nil{t.Fatal(e)}
 defer lease.close()
 c:=pqContext{ClientMessageID:"qs-protected-test-0001",From:self.Address,FromDeviceID:self.Device,To:peer.Address,ToDeviceID:peer.Device}
 raw,e=json.Marshal(directDraft{c,[]byte("{\"subject\":\"Protected test\",\"body\":\"Synthetic\"}")});if e!=nil{t.Fatal(e)}
 file:="draft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"
 if e=winWriteEncryptedDraft(filepath.Join(dir,file),raw);e!=nil{t.Fatal(e)}
 prompt:=func(s string,_ bool)([]byte,error){if s=="Phrase secrete classique"{return bytes.Clone(pass),nil};return bytes.Clone(pqpass),nil}
 approve:=func(string)bool{return true}
 op:=directOperation{"seal",file,pin,false}
 if _,e=winDirectMail(dir,op,prompt,approve);e==nil{t.Fatal("legacy entry point accepted protected identity")}
 absent:=mailMembers
 for i:=0;i<2;i++{absent[i].Exchange=func(stdcontext.Context,directWitnessRequest)([]byte,error){return nil,portableRefusal}}
 if _,e=winDirectMailMode(dir,op,prompt,approve,lease,&absent,roster);e==nil{t.Fatal("mail without quorum")}
 r,e:=winDirectMailMode(dir,op,prompt,approve,lease,&mailMembers,roster);if e!=nil||r.HybridEnvelope==nil||r.SenderAuth==nil{t.Fatal("protected seal",e)}
 op.Recover=true
 if _,e=winDirectMailMode(dir,op,prompt,approve,lease,&mailMembers,roster);e!=nil{t.Fatal("protected recovery",e)}
 if e=lease.revoke(func()bool{return true});e!=nil{t.Fatal(e)}
 if _,e=winDirectMailMode(dir,op,prompt,approve,lease,&mailMembers,roster);e==nil{t.Fatal("revoked contact recovery")}
 op.Recover=false
 if _,e=winDirectMailMode(dir,op,prompt,approve,lease,&mailMembers,roster);e==nil{t.Fatal("revoked contact send")}
}
