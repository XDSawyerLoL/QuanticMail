//go:build windows && cgo && pqopenssl

package main
import(
 "encoding/json"
 "encoding/hex"
 "path/filepath"
 "testing"
 "time"
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
)
func TestWindowsDirectLocalVault(t *testing.T){
 root:=t.TempDir()
 dirs:=[]string{filepath.Join(root,"a"),filepath.Join(root,"b")}
 ids:=make([]directIdentity,2)
 pins:=make([]string,2)
 pass:=[]byte("Synthetic direct classical passphrase only")
 pqpass:=[]byte("Different synthetic PQ passphrase only")
 for i,d:=range dirs{
  alias:=[]string{"alice","bobby"}[i]
  id,e:=winProvisionDirect(d,alias,pass,pqpass);if e!=nil{t.Fatal(e)}
  ids[i]=id
  if _,e=winProvisionDirect(d,alias,pass,pqpass);e==nil{t.Fatal("overwrote identity")}
  if _,e=winReadClassical(filepath.Join(d,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+id.LocalPin+"\x00",pass,id.SigningPin,id.EncryptionPin);e==nil{t.Fatal("legacy quorum domain opened direct key")}
 }
 for i,d:=range dirs{
  other:=ids[1-i]
  c:=fixtureContact(t,map[string]string{"address":other.Address,"deviceId":other.Device,"signing":other.Signing,"encryption":other.Encryption,"kemPublic":other.KemPublic,"dsaPublic":other.DsaPublic})
  c.Expires=time.Now().Add(time.Hour).UnixMilli()
  raw,e:=json.Marshal([]senderContact{c});if e!=nil{t.Fatal(e)}
  pins[i]=hexHash(raw)
  if e=winDirectImport(d,pins[i],raw);e!=nil{t.Fatal(e)}
  if e=winDirectImport(d,pins[i],raw);e==nil{t.Fatal("contact overwritten")}
 }
 c:=pqContext{ClientMessageID:"qs-direct-test-0001",From:ids[0].Address,FromDeviceID:ids[0].Device,To:ids[1].Address,ToDeviceID:ids[1].Device}
 plain:=[]byte("{\"subject\":\"Direct local test\",\"body\":\"No external service\"}")
 raw,e:=json.Marshal(directDraft{c,plain});if e!=nil{t.Fatal(e)}
 draft:="draft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"
 if e=winWriteEncryptedDraft(filepath.Join(dirs[0],draft),raw);e!=nil{t.Fatal(e)}
 prompt:=func(s string,_ bool)([]byte,error){if s=="Phrase secrete classique"{return bytes.Clone(pass),nil};return bytes.Clone(pqpass),nil}
 approve:=func(string)bool{return true}
 no:=func(string)bool{return false}
 seal:=directOperation{"seal",draft,pins[0],false}
 if _,e=winDirectMail(dirs[0],seal,prompt,no);e==nil{t.Fatal("no consent")}
 r,e:=winDirectMail(dirs[0],seal,prompt,approve);if e!=nil||r.HybridEnvelope==nil||r.SenderAuth==nil{t.Fatal("seal",e)}
 if _,e=winDirectMail(dirs[0],seal,prompt,approve);e==nil{t.Fatal("duplicate encryption")}
 seal.Recover=true
 rec,e:=winDirectMail(dirs[0],seal,prompt,approve);if e!=nil{t.Fatal(e)}
 a,_:=json.Marshal(r);b,_:=json.Marshal(rec);if !bytes.Equal(a,b){t.Fatal("result changed on reopen")}
 w:=directWire{"quantic-native-mail",1,c,*r.HybridEnvelope,*r.SenderAuth}
 wire,e:=json.Marshal(w);if e!=nil{t.Fatal(e)}
 name:="wire-in-"+hex.EncodeToString(make([]byte,20))+".json"
 if e=winWritePrivate(filepath.Join(dirs[1],name),wire);e!=nil{t.Fatal(e)}
 open:=directOperation{"open",name,pins[1],false}
 got,e:=winDirectMail(dirs[1],open,prompt,approve);if e!=nil||got.Message==nil{t.Fatal("open",e)}
 decrypted,e:=b64.DecodeString(*got.Message);if e!=nil||!bytes.Equal(decrypted,plain){t.Fatal("message changed")}
 if _,e=winDirectMail(dirs[1],open,prompt,approve);e==nil{t.Fatal("duplicate open")}
 open.Recover=true
 got,e=winDirectMail(dirs[1],open,prompt,approve);if e!=nil||got.Message==nil{t.Fatal("recover",e)}
 open.ContactPin=hex.EncodeToString(make([]byte,32))
 if _,e=winDirectMail(dirs[1],open,prompt,approve);e==nil{t.Fatal("wrong trust pin")}
 if _,e=winReadDirectIdentity(filepath.Join(root,"missing"));e==nil{t.Fatal("invalid identity")}
 // Exercise real private NTFS persistence with the actual peer vault keys.
 now:=time.Now().UnixMilli()
 peer:=ids[1]
 old:=fixtureContact(t,map[string]string{"address":peer.Address,"deviceId":peer.Device,"signing":peer.Signing,"encryption":peer.Encryption,"kemPublic":peer.KemPublic,"dsaPublic":peer.DsaPublic})
 old.Expires=now-1000
 self:=ids[0]
 leaseDir:=filepath.Join(dirs[0],"renewal")
 if e=winCreatePrivateDirectory(leaseDir);e!=nil{t.Fatal(e)}
 var members [4]directWitnessMember
 var witnessKeys [4]ed25519.PrivateKey
 for i:=range members{
  pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  witnessKeys[i]=key
  members[i]=directWitnessMember{pub,func(context.Context,directWitnessRequest)([]byte,error){return nil,portableRefusal}}
 }
 roster,e:=directWitnessRosterPin(members);if e!=nil{t.Fatal(e)}
 journalID,e:=directLeaseJournalID(old,self.Address,self.Device,roster);if e!=nil{t.Fatal(e)}
 journal:=filepath.Join(leaseDir,"lease-journal.log")
 if e=winInitReplay(journal,self.SigningPin,self.EncryptionPin,journalID);e!=nil{t.Fatal(e)}
 for i:=range members{
  path:=filepath.Join(root,"witness-"+string(rune('0'+i)))
  if e=initReplay(path,self.SigningPin,self.EncryptionPin,journalID);e!=nil{t.Fatal(e)}
  store:=directTestStore{path,self.SigningPin,self.EncryptionPin,journalID,journalID}
  key:=witnessKeys[i]
  members[i].Exchange=func(_ context.Context,q directWitnessRequest)([]byte,error){return signDirectWitness(q,journalID,store,key)}
 }
 lease,e:=winOpenDirectLeaseStore(leaseDir,self,old,members,roster);if e!=nil{t.Fatal(e)}
 if _,e=lease.active(now);e==nil{lease.close();t.Fatal("expired original lease accepted")}
 pending,e:=lease.begin(now);if e!=nil{lease.close();t.Fatal(e)}
 pub,e:=appPublic(peer.ControllerPublic);if e!=nil{lease.close();t.Fatal(e)}
 local:=hexHash([]byte("quantic-direct-local-vault/v1\x00"+peer.LocalPin))
 keys,e:=winReadClassical(filepath.Join(dirs[1],"classical.vault"),anchoredMagic+"direct-local-only:"+local+"\x00",pass,peer.SigningPin,peer.EncryptionPin);if e!=nil{lease.close();t.Fatal(e)}
 binding,e:=pqBinding(peer.SigningPin,peer.EncryptionPin,hexHash(pub),local,peer.Address,peer.Device);if e!=nil{lease.close();t.Fatal(e)}
 pq,e:=winReadPQ(filepath.Join(dirs[1],"pq.vault"),binding,pqpass,peer.Address,peer.Device,peer.KemPin,peer.DsaPin);if e!=nil{lease.close();t.Fatal(e)}
 defer pq.close()
 proof,e:=signDirectRenew(pending.req,now+23*3600000,now,softwareSigner{keys.signing},pq);if e!=nil{lease.close();t.Fatal(e)}
 if _,e=lease.commit(pending,proof,now);e!=nil{lease.close();t.Fatal(e)}
 lease.close()
 lease,e=winOpenDirectLeaseStore(leaseDir,self,old,members,roster);if e!=nil{t.Fatal(e)}
 defer lease.close()
 if c,e:=lease.active(now+directRenewWindow+1);e!=nil||c.Expires!=proof.Expires{t.Fatal("native renewal restart",e)}
}

