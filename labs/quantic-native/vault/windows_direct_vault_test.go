//go:build windows && cgo && pqopenssl

package main
import(
 "encoding/json"
 "encoding/hex"
 "path/filepath"
 "testing"
 "time"
 "bytes"
 stdcontext "context"
 "crypto/ed25519"
 "crypto/rand"
 "net"
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
  members[i]=directWitnessMember{pub,func(stdcontext.Context,directWitnessRequest)([]byte,error){return nil,portableRefusal}}
 }
 roster,e:=directWitnessRosterPin(members);if e!=nil{t.Fatal(e)}
 journalID,e:=directLeaseJournalID(old,self.Address,self.Device,roster);if e!=nil{t.Fatal(e)}
 journal:=filepath.Join(leaseDir,"lease-journal.log")
 if e=winInitReplay(journal,self.SigningPin,self.EncryptionPin,journalID);e!=nil{t.Fatal(e)}
 ctx,cancel:=stdcontext.WithCancel(stdcontext.Background());defer cancel()
 var config [4]directUDPConfig
 for i:=range members{
  path:=filepath.Join(root,"witness-"+string(rune('0'+i)))
  if e=initReplay(path,self.SigningPin,self.EncryptionPin,journalID);e!=nil{t.Fatal(e)}
  store:=directTestStore{path,self.SigningPin,self.EncryptionPin,journalID,journalID}
  key:=witnessKeys[i]
  secret:=make([]byte,32);if _,e=rand.Read(secret);e!=nil{t.Fatal(e)}
  sock,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if e!=nil{t.Fatal(e)}
  defer sock.Close()
  done:=make(chan error,1)
  go func(){done<-serveDirectUDPWitness(ctx,sock,secret,journalID,store,key)}()
  defer func(){cancel();<-done}()
  config[i]=directUDPConfig{sock.LocalAddr().(*net.UDPAddr),secret,members[i].Public}
 }
 lease,e:=winOpenDirectUDPLeaseStore(leaseDir,self,old,config,roster);if e!=nil{t.Fatal(e)}
 if _,e=lease.active(now);e==nil{lease.close();t.Fatal("expired original lease accepted")}
 pub,e:=appPublic(peer.ControllerPublic);if e!=nil{lease.close();t.Fatal(e)}
 local:=hexHash([]byte("quantic-direct-local-vault/v1\x00"+peer.LocalPin))
 keys,e:=winReadClassical(filepath.Join(dirs[1],"classical.vault"),anchoredMagic+"direct-local-only:"+local+"\x00",pass,peer.SigningPin,peer.EncryptionPin);if e!=nil{lease.close();t.Fatal(e)}
 binding,e:=pqBinding(peer.SigningPin,peer.EncryptionPin,hexHash(pub),local,peer.Address,peer.Device);if e!=nil{lease.close();t.Fatal(e)}
 pq,e:=winReadPQ(filepath.Join(dirs[1],"pq.vault"),binding,pqpass,peer.Address,peer.Device,peer.KemPin,peer.DsaPin);if e!=nil{lease.close();t.Fatal(e)}
 defer pq.close()
 own:=fixtureContact(t,map[string]string{"address":self.Address,"deviceId":self.Device,"signing":self.Signing,"encryption":self.Encryption,"kemPublic":self.KemPublic,"dsaPublic":self.DsaPublic})
 own.Expires=now-1000
 ownPub,e:=appPublic(self.ControllerPublic);if e!=nil{lease.close();t.Fatal(e)}
 ownLocal:=hexHash([]byte("quantic-direct-local-vault/v1\x00"+self.LocalPin))
 ownKeys,e:=winReadClassical(filepath.Join(dirs[0],"classical.vault"),anchoredMagic+"direct-local-only:"+ownLocal+"\x00",pass,self.SigningPin,self.EncryptionPin);if e!=nil{lease.close();t.Fatal(e)}
 ownBinding,e:=pqBinding(self.SigningPin,self.EncryptionPin,hexHash(ownPub),ownLocal,self.Address,self.Device);if e!=nil{lease.close();t.Fatal(e)}
 ownPQ,e:=winReadPQ(filepath.Join(dirs[0],"pq.vault"),ownBinding,pqpass,self.Address,self.Device,self.KemPin,self.DsaPin);if e!=nil{lease.close();t.Fatal(e)}
 defer ownPQ.close()
 // The issuer has its own separate authorization journal. Test witnesses
 // below are in memory; receiver witnesses above use real UDP and files.
 issuerID,e:=directRenewIssuerID(old,own,roster);if e!=nil{lease.close();t.Fatal(e)}
 issuerPath:=filepath.Join(dirs[1],"renew-issuer.log")
 if e=winInitReplay(issuerPath,peer.SigningPin,peer.EncryptionPin,issuerID);e!=nil{lease.close();t.Fatal(e)}
 issuer,e:=winOpenReplay(issuerPath,peer.SigningPin,peer.EncryptionPin,issuerID);if e!=nil{lease.close();t.Fatal(e)}
 defer issuer.close()
 issuerQuorum:=&quorumAnchor{pin:roster}
 for i:=range issuerQuorum.members{issuerQuorum.members[i]=&fakeAnchor{tail:issuer.tail}}
 if e=issuer.attachAnchor(issuerQuorum,issuerID);e!=nil{lease.close();t.Fatal(e)}
 allowed:=func(senderContact)bool{return true}
 refused:=func(senderContact)bool{return false}
 calls:=0
 exchange:=func(_ stdcontext.Context,req directSignedRenewRequest)(directRenewProof,error){
  calls++
  bad:=req;bad.PreviousExpiry++
  if _,e:=issueDirectRenew(bad,old,own,now,issuer,roster,allowed,softwareSigner{keys.signing},pq);e==nil{t.Fatal("tampered signed request accepted")}
  if _,e:=issueDirectRenew(req,old,own,now,issuer,roster,refused,softwareSigner{keys.signing},pq);e==nil{t.Fatal("revoked requester accepted")}
  if len(issuer.seen)!=0{t.Fatal("refused request consumed authorization")}
  proof,e:=issueDirectRenew(req,old,own,now,issuer,roster,allowed,softwareSigner{keys.signing},pq)
  if e!=nil{return proof,e}
  if _,e=issueDirectRenew(req,old,own,now,issuer,roster,allowed,softwareSigner{keys.signing},pq);e==nil{t.Fatal("issuer signed replay")}
  return proof,nil
 }
 renewed,e:=runDirectRenewal(ctx,lease,func()int64{return now},allowed,softwareSigner{ownKeys.signing},ownPQ,exchange);if e!=nil{lease.close();t.Fatal(e)}
 if renewed.Expires!=now+directRenewDuration||calls!=1{lease.close();t.Fatal("automatic renewal refused")}
 if _,e=runDirectRenewal(ctx,lease,func()int64{return now},allowed,softwareSigner{ownKeys.signing},ownPQ,exchange);e!=nil||calls!=1{lease.close();t.Fatal("unnecessary network renewal",e)}
 if _,e=runDirectRenewal(ctx,lease,func()int64{return now},refused,softwareSigner{ownKeys.signing},ownPQ,exchange);e==nil||calls!=1{lease.close();t.Fatal("revoked contact returned")}
 lease.close()
 lease,e=winOpenDirectUDPLeaseStore(leaseDir,self,old,config,roster);if e!=nil{t.Fatal(e)}
 defer lease.close()
 if c,e:=lease.active(now+directRenewWindow+1);e!=nil||c.Expires!=renewed.Expires{t.Fatal("native renewal restart",e)}
 if e=revokeDirectIssuer(issuer,old,own,roster,func()bool{return true});e!=nil{t.Fatal("issuer revoke",e)}
 // A genuinely fresh signed request after revocation must not produce a proof.
 later:=renewed.Expires-directRenewLead
 next,e:=lease.begin(later);if e!=nil{t.Fatal(e)}
 signed,e:=signDirectRenewRequest(next.req,renewed.Expires,later,softwareSigner{ownKeys.signing},ownPQ);if e!=nil{t.Fatal(e)}
 if _,e=issueDirectRenew(signed,old,own,later,issuer,roster,allowed,softwareSigner{keys.signing},pq);e==nil{t.Fatal("revoked requester signed")}
 if e=lease.revoke(func()bool{return true});e!=nil{t.Fatal("receiver revoke",e)}
 if _,e=lease.active(now);e==nil{t.Fatal("revoked contact active")}
 if _,e=lease.begin(now);e==nil{t.Fatal("revoked contact can renew")}
 lease.close()
 reopened,e:=winOpenDirectUDPLeaseStore(leaseDir,self,old,config,roster);if e!=nil{t.Fatal(e)}
 defer reopened.close()
 if _,e=reopened.active(now);e==nil{t.Fatal("revocation lost on restart")}
}

