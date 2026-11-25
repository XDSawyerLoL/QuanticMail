//go:build windows && cgo && pqopenssl

package main

import (
 stdcontext "context"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ed25519"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "net"
 "os"
 "os/signal"
 "path/filepath"
)

// One owner-controlled machine per card. The signing key and the ML-KEM
// pairing key never leave the witness. DPAPI CurrentUser is a local OS trust
// boundary, not protection from a compromised user or administrator.
type directWitnessCard struct{
 Format string
 IP string
 LeasePort,MailPort int
 Public,KEM string
}
type directWitnessPrivate struct{ Signing,KEM []byte }
type directWitnessPairing struct{
 Format,CardPin,LeaseID,MailID,Sign,Enc,App string
 LeaseSecret,MailSecret []byte
}
type directWitnessCapsule struct{ CardPin string; KEM,Nonce,Data []byte }
func directWitnessCardCheck(c directWitnessCard)(ed25519.PublicKey,[]byte,error){
 ip:=net.ParseIP(c.IP)
 if c.Format!="quantic-witness-card/v1"||ip==nil||ip.String()!=c.IP||c.LeasePort<1024||c.MailPort<1024||c.LeasePort==c.MailPort||
 !directUDPAddress(&net.UDPAddr{IP:ip,Port:c.LeasePort})||!directUDPAddress(&net.UDPAddr{IP:ip,Port:c.MailPort}){return nil,nil,portableRefusal}
 pub,e:=decode(c.Public,32,32);if e!=nil{return nil,nil,e}
 kem,e:=decode(c.KEM,1206,1206);if e!=nil{return nil,nil,e}
 return ed25519.PublicKey(pub),kem,nil
}
func directWitnessCardPin(c directWitnessCard)string{raw,_:=json.Marshal(c);return hexHash(raw)}
func winWriteWitnessSecret(path string,raw []byte)error{
 encrypted,e:=draftDPAPI(path,raw,false);if e!=nil{return e};defer clear(encrypted)
 return winWritePrivate(path,encrypted)
}
func winReadWitnessSecret(path string)([]byte,error){
 raw,e:=winReadPrivate(path,16384);if e!=nil{return nil,e};defer clear(raw)
 return draftDPAPI(path,raw,true)
}
func winCreateDirectWitness(dir,ip string,lp,mp int)(directWitnessCard,error){
 var fail directWitnessCard
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{return fail,e};defer clear(priv)
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{return fail,e};defer kem.close()
 kpub,e:=kem.der(false);if e!=nil{return fail,e}
 kpriv,e:=kem.der(true);if e!=nil{return fail,e};defer clear(kpriv)
 card:=directWitnessCard{"quantic-witness-card/v1",ip,lp,mp,b64.EncodeToString(pub),b64.EncodeToString(kpub)}
 if _,_,e=directWitnessCardCheck(card);e!=nil{return fail,e}
 raw,e:=json.Marshal(directWitnessPrivate{priv,kpriv});if e!=nil{return fail,e};defer clear(raw)
 if e=winCreatePrivateDirectory(dir);e!=nil{return fail,e}
 if e=winWriteWitnessSecret(filepath.Join(dir,"witness-key.dpapi"),raw);e!=nil{return fail,e}
 cardRaw,e:=json.Marshal(card);if e!=nil{return fail,e}
 if e=winWritePrivate(filepath.Join(dir,"witness-card.json"),cardRaw);e!=nil{return fail,e}
 return card,nil
}
func winLoadDirectWitness(dir string)(directWitnessCard,directWitnessPrivate,error){
 var card directWitnessCard
 var priv directWitnessPrivate
 raw,e:=winReadPrivate(filepath.Join(dir,"witness-card.json"),4096);if e!=nil{return card,priv,e}
 if directDecode(raw,&card)!=nil{return card,priv,portableRefusal}
 pub,kpub,e:=directWitnessCardCheck(card);if e!=nil{return card,priv,e}
 raw,e=winReadWitnessSecret(filepath.Join(dir,"witness-key.dpapi"));if e!=nil{return card,priv,e};defer clear(raw)
 if directDecode(raw,&priv)!=nil||len(priv.Signing)!=64||!hmac.Equal(ed25519.PrivateKey(priv.Signing).Public().(ed25519.PublicKey),pub){clear(priv.Signing);clear(priv.KEM);return card,directWitnessPrivate{},portableRefusal}
 k,e:=pqImport(priv.KEM,"ML-KEM-768");if e!=nil{clear(priv.Signing);clear(priv.KEM);return card,directWitnessPrivate{},e};defer k.close()
 actual,e:=k.der(false);if e!=nil||!hmac.Equal(actual,kpub){clear(priv.Signing);clear(priv.KEM);return card,directWitnessPrivate{},portableRefusal}
 return card,priv,nil
}
func directPairAEAD(secret []byte,pin string)(cipher.AEAD,error){
 h:=hmac.New(sha256.New,secret);h.Write([]byte("quantic-witness-pairing/v1\x00"+pin))
 key:=h.Sum(nil);defer clear(key)
 block,e:=aes.NewCipher(key);if e!=nil{return nil,e};return cipher.NewGCM(block)
}
func sealDirectWitnessPair(c directWitnessCard,p directWitnessPairing)(directWitnessCapsule,error){
 var fail directWitnessCapsule
 _,kem,e:=directWitnessCardCheck(c);if e!=nil{return fail,e}
 pin:=directWitnessCardPin(c)
 if p.CardPin!=pin{return fail,portableRefusal}
 ct,secret,e:=pqEncapPublic(kem);if e!=nil{return fail,e};defer clear(secret)
 g,e:=directPairAEAD(secret,pin);if e!=nil{return fail,e}
 nonce:=make([]byte,g.NonceSize());if _,e=rand.Read(nonce);e!=nil{return fail,e}
 raw,e:=json.Marshal(p);if e!=nil{return fail,e};defer clear(raw)
 return directWitnessCapsule{pin,ct,nonce,g.Seal(nil,nonce,raw,[]byte(pin))},nil
}
func openDirectWitnessPair(c directWitnessCard,priv directWitnessPrivate,cap directWitnessCapsule)(directWitnessPairing,error){
 var p directWitnessPairing
 if cap.CardPin!=directWitnessCardPin(c)||len(cap.KEM)!=1088||len(cap.Nonce)!=12||len(cap.Data)<16||len(cap.Data)>4096{return p,portableRefusal}
 k,e:=pqImport(priv.KEM,"ML-KEM-768");if e!=nil{return p,e};defer k.close()
 secret,e:=k.dec(cap.KEM);if e!=nil{return p,e};defer clear(secret)
 g,e:=directPairAEAD(secret,cap.CardPin);if e!=nil{return p,e}
 raw,e:=g.Open(nil,cap.Nonce,cap.Data,[]byte(cap.CardPin));if e!=nil{return p,e};defer clear(raw)
 if directDecode(raw,&p)!=nil||!validDirectWitnessPair(p,c){clear(p.LeaseSecret);clear(p.MailSecret);return directWitnessPairing{},portableRefusal}
 return p,nil
}
func validDirectWitnessPair(p directWitnessPairing,c directWitnessCard)bool{
 if p.Format!="quantic-witness-pairing/v1"||p.CardPin!=directWitnessCardPin(c)||p.LeaseID==p.MailID||len(p.LeaseSecret)!=32||len(p.MailSecret)!=32||hmac.Equal(p.LeaseSecret,p.MailSecret)||hmac.Equal(p.LeaseSecret,make([]byte,32))||hmac.Equal(p.MailSecret,make([]byte,32)){return false}
 for _,v:=range []string{p.LeaseID,p.MailID,p.Sign,p.Enc,p.App}{if !hashRE.MatchString(v){return false}}
 return true
}
// The entire card bundle must be authenticated out of band, not merely the
// signing roster: the pairing KEM keys and endpoints are also trust inputs.
func winPrepareDirectWitnesses(dir,contactPin,cardsPin string,raw []byte,approve func()bool)([4]directWitnessCapsule,error){
 var caps [4]directWitnessCapsule
 var cards []directWitnessCard
 if !hashRE.MatchString(contactPin)||!hashRE.MatchString(cardsPin)||hexHash(raw)!=cardsPin||directDecode(raw,&cards)!=nil||len(cards)!=4{return caps,portableRefusal}
 id,e:=winReadDirectIdentityMode(dir,true);if e!=nil{return caps,e}
 var roster [4]directWitnessMember
 used:=map[string]bool{}
 for i,c:=range cards{
  pub,_,e:=directWitnessCardCheck(c);if e!=nil||used[c.IP]{return caps,portableRefusal};used[c.IP]=true
  roster[i]=directWitnessMember{pub,func(stdcontext.Context,directWitnessRequest)([]byte,error){return nil,portableRefusal}}
 }
 pin,e:=directWitnessRosterPin(roster);if e!=nil||pin!=id.LocalPin{return caps,portableRefusal}
 card,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return caps,e};defer clear(card)
 var contacts []senderContact
 if hexHash(card)!=contactPin||directDecode(card,&contacts)!=nil||len(contacts)!=1{return caps,portableRefusal}
 leaseID,e:=directLeaseJournalID(contacts[0],id.Address,id.Device,pin);if e!=nil{return caps,e}
 pub,e:=appPublic(id.ControllerPublic);if e!=nil{return caps,e}
 if approve==nil||!approve(){return caps,portableRefusal}
 cfg:=directProtectedDisk{Format:"quantic-protected-witnesses/v1",ContactPin:contactPin}
 for i,c:=range cards{
  ls,ms:=make([]byte,32),make([]byte,32)
  if _,e=rand.Read(ls);e!=nil{return caps,e};if _,e=rand.Read(ms);e!=nil{clear(ls);return caps,e}
  p:=directWitnessPairing{"quantic-witness-pairing/v1",directWitnessCardPin(c),leaseID,directProtectedMailID(id),id.SigningPin,id.EncryptionPin,hexHash(pub),ls,ms}
  caps[i],e=sealDirectWitnessPair(c,p)
  cfg.Lease[i]=directWitnessDisk{c.IP,c.LeasePort,c.Public,hex.EncodeToString(ls)}
  cfg.Mail[i]=directWitnessDisk{c.IP,c.MailPort,c.Public,hex.EncodeToString(ms)}
  clear(ls);clear(ms);if e!=nil{return caps,e}
 }
 // Exportable encrypted capsules saved before enabling config. Never
 // overwrite or regenerate on an uncertain write; preserve partial state.
 packed,e:=json.Marshal(caps);if e!=nil{return caps,e}
 if e=winWritePrivate(filepath.Join(dir,"protected-pairing.json"),packed);e!=nil{return caps,e}
 config,e:=json.Marshal(cfg);if e!=nil{return caps,e};defer clear(config)
 if e=winWriteWitnessSecret(filepath.Join(dir,"protected-witnesses.json"),config);e!=nil{return caps,e}
 return caps,nil
}
func winEnrollDirectWitness(dir,pin string,raw []byte,approve func()bool)error{
 if !hashRE.MatchString(pin)||hexHash(raw)!=pin{return portableRefusal}
 var cap directWitnessCapsule
 if directDecode(raw,&cap)!=nil{return portableRefusal}
 c,priv,e:=winLoadDirectWitness(dir);if e!=nil{return e};defer clear(priv.Signing);defer clear(priv.KEM)
 p,e:=openDirectWitnessPair(c,priv,cap);if e!=nil{return e};defer clear(p.LeaseSecret);defer clear(p.MailSecret)
 if approve==nil||!approve(){return portableRefusal}
 packed,e:=json.Marshal(p);if e!=nil{return e};defer clear(packed)
 if e=winWriteWitnessSecret(filepath.Join(dir,"witness-pair.dpapi"),packed);e!=nil{return e}
 if e=winInitReplay(filepath.Join(dir,"lease.log"),p.Sign,p.Enc,p.LeaseID);e!=nil{return e}
 if e=winInitReplay(filepath.Join(dir,"mail.log"),p.Sign,p.Enc,p.App);e!=nil{return e}
 return winWritePrivate(filepath.Join(dir,"witness-ready"),[]byte(pin))
}
type winDirectWitnessStore struct{path,id,sign,enc,app string}
func(s winDirectWitnessStore)check(id string,n int,h [32]byte)error{
 if id!=s.id{return portableRefusal}
 j,e:=winOpenReplay(s.path,s.sign,s.enc,s.app);if e!=nil{return e};defer j.close()
 if len(j.seen)!=n||j.tail!=h{return portableRefusal};return nil
}
func(s winDirectWitnessStore)advance(id string,n int,h,k [32]byte)error{
 if id!=s.id{return portableRefusal}
 j,e:=winOpenReplay(s.path,s.sign,s.enc,s.app);if e!=nil{return e};defer j.close()
 if len(j.seen)!=n||j.tail!=h{return portableRefusal};return j.consume(k)
}
func winServeDirectWitness(ctx stdcontext.Context,dir string)error{
 c,priv,e:=winLoadDirectWitness(dir);if e!=nil{return e};defer clear(priv.Signing);defer clear(priv.KEM)
 ready,e:=winReadPrivate(filepath.Join(dir,"witness-ready"),64);if e!=nil||!hashRE.MatchString(string(ready)){return portableRefusal}
 raw,e:=winReadWitnessSecret(filepath.Join(dir,"witness-pair.dpapi"));if e!=nil{return e};defer clear(raw)
 var p directWitnessPairing
 if directDecode(raw,&p)!=nil||!validDirectWitnessPair(p,c){return portableRefusal}
 defer clear(p.LeaseSecret);defer clear(p.MailSecret)
 l:=winDirectWitnessStore{filepath.Join(dir,"lease.log"),p.LeaseID,p.Sign,p.Enc,p.LeaseID}
 m:=winDirectWitnessStore{filepath.Join(dir,"mail.log"),p.MailID,p.Sign,p.Enc,p.App}
 // Validate durable journals before listening; never initialize at startup.
 for _,s:=range []winDirectWitnessStore{l,m}{j,e:=winOpenReplay(s.path,s.sign,s.enc,s.app);if e!=nil{return e};j.close()}
 ls,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.ParseIP(c.IP),Port:c.LeasePort});if e!=nil{return e};defer ls.Close()
 ms,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.ParseIP(c.IP),Port:c.MailPort});if e!=nil{return e};defer ms.Close()
 ctx,cancel:=stdcontext.WithCancel(ctx);defer cancel()
 done:=make(chan error,2)
 go func(){done<-serveDirectUDPWitness(ctx,ls,p.LeaseSecret,p.LeaseID,l,ed25519.PrivateKey(priv.Signing))}()
 go func(){done<-serveDirectUDPWitness(ctx,ms,p.MailSecret,p.MailID,m,ed25519.PrivateKey(priv.Signing))}()
 e=<-done;cancel();<-done
 return e
}
func winDirectWitnessCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
 switch args[1]{
 case "--windows-witness-roster-lab":
  if len(args)!=2{return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil||len(raw)>32768{return true,portableRefusal}
  var cards []directWitnessCard
  if directDecode(raw,&cards)!=nil||len(cards)!=4{return true,portableRefusal}
  var roster [4]directWitnessMember
  seen:=map[string]bool{}
  for i,c:=range cards{
   pub,_,e:=directWitnessCardCheck(c);if e!=nil||seen[c.IP]{return true,portableRefusal};seen[c.IP]=true
   roster[i]=directWitnessMember{pub,func(stdcontext.Context,directWitnessRequest)([]byte,error){return nil,portableRefusal}}
  }
  pin,e:=directWitnessRosterPin(roster);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(map[string]string{"rosterPin":pin,"cardsPin":hexHash(raw)})
 case "--windows-witness-create-gui-lab":
  if len(args)!=3{return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,4097));if e!=nil||len(raw)>4096{return true,portableRefusal}
  var v struct{IP string;LeasePort,MailPort int}
  if directDecode(raw,&v)!=nil||!winGUIApprove("Creer ce temoin independant sur cette machine ?"){return true,portableRefusal}
  c,e:=winCreateDirectWitness(args[2],v.IP,v.LeasePort,v.MailPort);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(c)
 case "--windows-witness-prepare-gui-lab":
  if len(args)!=5{return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil||len(raw)>32768{return true,portableRefusal}
  caps,e:=winPrepareDirectWitnesses(args[2],args[3],args[4],raw,func()bool{return winGUIApprove("Associer les quatre temoins dont les cartes ont ete verifiees ?")})
  if e!=nil{return true,e};return true,json.NewEncoder(os.Stdout).Encode(caps)
 case "--windows-witness-enroll-gui-lab":
  if len(args)!=4{return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,16385));if e!=nil||len(raw)>16384{return true,portableRefusal}
  return true,winEnrollDirectWitness(args[2],args[3],raw,func()bool{return winGUIApprove("Associer definitivement ce temoin au coffre dont le paquet a ete verifie ?")})
 case "--windows-witness-serve-lab":
  if len(args)!=3{return true,portableRefusal}
  ctx,stop:=signal.NotifyContext(stdcontext.Background(),os.Interrupt);defer stop()
  return true,winServeDirectWitness(ctx,args[2])
 }
 return false,nil
}
