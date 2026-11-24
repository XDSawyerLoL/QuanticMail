//go:build windows && cgo && pqopenssl

package main

import(
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "net"
 "os"
 "path/filepath"
 "time"
)

// Operator-provisioned private configuration. Secrets never enter Node or
// the GUI. No auto-enrollment, no witness reset, and no public endpoints.
type directWitnessDisk struct{
 IP string
 Port int
 Public string
 Secret string
}
type directProtectedDisk struct{
 Format string
 ContactPin string
 Lease [4]directWitnessDisk
 Mail [4]directWitnessDisk
}
func winProtectedConfigs(dir string,id directIdentity,pin string)(senderContact,[4]directUDPConfig,[4]directUDPConfig,error){
 var contact senderContact
 var lease,mail [4]directUDPConfig
 fail:=func()(senderContact,[4]directUDPConfig,[4]directUDPConfig,error){
  for i:=range lease{clear(lease[i].Secret);clear(mail[i].Secret)}
  return senderContact{},[4]directUDPConfig{},[4]directUDPConfig{},portableRefusal
 }
 if !hashRE.MatchString(pin){return fail()}
 raw,e:=winReadPrivate(filepath.Join(dir,"protected-witnesses.json"),16384);if e!=nil{return fail()};defer clear(raw)
 var cfg directProtectedDisk
 if directDecode(raw,&cfg)!=nil||cfg.Format!="quantic-protected-witnesses/v1"||cfg.ContactPin!=pin{return fail()}
 card,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return fail()};defer clear(card)
 var list []senderContact
 if hexHash(card)!=pin||directDecode(card,&list)!=nil||len(list)!=1{return fail()}
 contact=list[0]
 if contact.Address==id.Address||contact.Device==id.Device{return fail()}
 if _,e=directContactCommit(contact);e!=nil{return fail()}
 used:=map[string]bool{}
 for lane,entries:=range [2][4]directWitnessDisk{cfg.Lease,cfg.Mail}{
  for i,w:=range entries{
   ip:=net.ParseIP(w.IP)
   addr:=&net.UDPAddr{IP:ip,Port:w.Port}
   if ip==nil||ip.String()!=w.IP||!directUDPAddress(addr)||!hashRE.MatchString(w.Secret)||used[w.Secret]||used[addr.String()]{return fail()}
   pub,e:=decode(w.Public,ed25519.PublicKeySize,ed25519.PublicKeySize);if e!=nil{return fail()}
   secret,e:=hex.DecodeString(w.Secret);if e!=nil{return fail()}
   used[w.Secret]=true;used[addr.String()]=true
   item:=directUDPConfig{addr,secret,ed25519.PublicKey(pub)}
   if lane==0{lease[i]=item}else{mail[i]=item}
  }
 }
 return contact,lease,mail,nil
}
func winProtectedOperation(dir,pin string,op *directOperation,action string,approve func(string)bool,prompt func(string,bool)([]byte,error))(any,error){
 id,e:=winReadDirectIdentityMode(dir,true);if e!=nil{return nil,e}
 initial,lc,mc,e:=winProtectedConfigs(dir,id,pin);if e!=nil{return nil,e}
 defer func(){for i:=range lc{clear(lc[i].Secret);clear(mc[i].Secret)}}()
 leaseID,e:=directLeaseJournalID(initial,id.Address,id.Device,id.LocalPin);if e!=nil{return nil,e}
 lm,e:=directUDPQuorumMembers(lc,leaseID,id.LocalPin);if e!=nil{return nil,e}
 mm,e:=directUDPQuorumMembers(mc,directProtectedMailID(id),id.LocalPin);if e!=nil{return nil,e}
 leaseDir:=filepath.Join(dir,"renewal")
 if action=="initialize"{
  if approve==nil||!approve("Activer le contact protege "+initial.Address+" ? Les temoins doivent deja etre provisionnes independamment."){return nil,portableRefusal}
  // Explicit initialization only, never automatic recreation of a missing
  // journal. A current quorum must attest to the exact empty state first.
  h,e:=replayBinding(id.SigningPin,id.EncryptionPin,leaseID);if e!=nil{return nil,e}
  q,e:=newDirectPeerQuorum(lm,id.LocalPin);if e!=nil{return nil,e}
  if e=q.check(leaseID,0,replayIDHeader(h));e!=nil{return nil,e}
  if e=winCreatePrivateDirectory(leaseDir);e!=nil{return nil,e}
  if e=winInitReplay(filepath.Join(leaseDir,"lease-journal.log"),id.SigningPin,id.EncryptionPin,leaseID);e!=nil{return nil,e}
 }
 lease,e:=winOpenDirectLeaseStore(leaseDir,id,initial,lm,id.LocalPin);if e!=nil{return nil,e};defer lease.close()
 switch action{
 case "initialize","status":
  c,e:=lease.active(time.Now().UnixMilli());if e!=nil{return nil,e}
  return map[string]any{"status":"direct-protected-active","address":c.Address,"deviceId":c.Device,"expires":c.Expires},nil
 case "revoke":
  if e=lease.revoke(func()bool{return approve!=nil&&approve("Revoquer definitivement "+initial.Address+" ?")});e!=nil{return nil,e}
  return map[string]string{"status":"direct-protected-revoked"},nil
 case "mail":
  if op==nil||op.ContactPin!=pin{return nil,portableRefusal}
  return winDirectMailMode(dir,*op,prompt,approve,lease,&mm,id.LocalPin)
 }
 return nil,portableRefusal
}
func replayIDHeader(h []byte)[32]byte{return sha256.Sum256(h)}
func winProtectedDirectCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
 switch args[1]{
 case "--provision-windows-protected-direct-gui-lab":
  if len(args)!=5||!directAlias.MatchString(args[3])||!hashRE.MatchString(args[4]){return true,portableRefusal}
  if _,_,e:=winPathParts(args[2]);e!=nil{return true,e}
  if _,e:=os.Lstat(args[2]);!os.IsNotExist(e){return true,portableRefusal}
  if !winGUIApprove("Creer un nouveau coffre protege ? Empreinte independante des quatre temoins : "+args[4]){return true,portableRefusal}
  pw,e:=winGUIConfirmSecret("Nouvelle phrase secrete classique");if e!=nil{return true,e};defer clear(pw)
  pq,e:=winGUIConfirmSecret("Autre phrase secrete post-quantique");if e!=nil{return true,e};defer clear(pq)
  id,e:=winProvisionDirectMode(args[2],args[3],pw,pq,args[4]);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(id)
 case "--import-windows-protected-contact-gui-lab":
  if len(args)!=4||!hashRE.MatchString(args[3]){return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,131073));if e!=nil||len(raw)>131072{return true,portableRefusal};defer clear(raw)
  if hexHash(raw)!=args[3]||!winGUIApprove("Approuver le contact protege ? Empreinte : "+args[3]){return true,portableRefusal}
  return true,winDirectImportMode(args[2],args[3],raw,true)
 case "--windows-protected-direct-gui-lab":
  if len(args)!=5||!hashRE.MatchString(args[3]){return true,portableRefusal}
  action:=args[4]
  var op *directOperation
  if action=="mail"{
   raw,e:=io.ReadAll(io.LimitReader(os.Stdin,4097));if e!=nil||len(raw)>4096{return true,portableRefusal};defer clear(raw)
   op=&directOperation{}
   if directDecode(raw,op)!=nil{return true,portableRefusal}
  }
  result,e:=winProtectedOperation(args[2],args[3],op,action,winGUIApprove,winGUISecret);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(result)
 }
 return false,nil
}
