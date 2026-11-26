//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "io"
 "net"
 "net/url"
 "os"
 "path/filepath"
 "strconv"
 "time"
)
type activationTLS struct {
 CA []byte `json:"ca"`
 Cert []byte `json:"cert"`
}
type activationAnchor struct {
 URL string `json:"url"`
 TLSPin string `json:"tlsPin"`
}
type activationCheckpoint struct {
 URL string `json:"url"`
 Pin string `json:"pin"`
 PublicKey string `json:"publicKey"`
 TLSPin string `json:"tlsPin"`
}
type managedCarrierProfile struct{
 ConfigPin string `json:"configPin"`
 Listen string `json:"listen"`
 Target string `json:"target"`
}
func managedCarrierEndpoint(s string)bool{
 host,p,e:=net.SplitHostPort(s);if e!=nil{return false}
 ip:=net.ParseIP(host);port,e:=strconv.Atoi(p)
 return e==nil&&port>0&&port<=65535&&p==strconv.Itoa(port)&&ip!=nil&&ip.To4()!=nil&&ip.String()==host&&ip.To4()[0]>0&&ip.To4()[0]<224
}
func verifyManagedCarrierProfile(dir,endpoint string,p *managedCarrierProfile)error{
 if p==nil{return nil}
 if !hashRE.MatchString(p.ConfigPin)||!managedCarrierEndpoint(p.Listen)||!managedCarrierEndpoint(p.Target)||p.Listen==p.Target{return portableRefusal}
 carrier:=filepath.Join(dir,"carrier")
 raw,e:=winReadPrivate(filepath.Join(carrier,"scattering.json"),16384);if e!=nil{return e};defer clear(raw)
 if hexHash(raw)!=p.ConfigPin{return portableRefusal}
 var cfg struct{
 LabOnly bool `json:"labOnly"`
 Role string `json:"role"`
 SecretHex string `json:"secretHex"`
 EpochHex string `json:"epochHex"`
 RecvPort int `json:"recvPort"`
 HTTPPort int `json:"httpPort"`
 QueueDir string `json:"queueDir"`
 StateDir string `json:"stateDir"`
 }
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields();var extra any
 if d.Decode(&cfg)!=nil||d.Decode(&extra)!=io.EOF||!cfg.LabOnly||cfg.Role!="client"||!hashRE.MatchString(cfg.SecretHex)||!hashRE.MatchString(cfg.EpochHex)||cfg.SecretHex==cfg.EpochHex||cfg.SecretHex==string(bytes.Repeat([]byte("0"),64))||cfg.EpochHex==string(bytes.Repeat([]byte("0"),64))||
 cfg.RecvPort<1||cfg.RecvPort>65535||cfg.HTTPPort<1||cfg.HTTPPort>65535||cfg.RecvPort==cfg.HTTPPort||endpoint!="http://127.0.0.1:"+strconv.Itoa(cfg.HTTPPort)+"/"||cfg.QueueDir!=filepath.Join(carrier,"queue")||cfg.StateDir!=filepath.Join(carrier,"state")||p.Listen=="127.0.0.1:"+strconv.Itoa(cfg.RecvPort){return portableRefusal}
 return nil
}
// No pre-shared transport keys, filesystem paths or remote HTTP endpoints
// are accepted in the negotiated profile.
type managedHybridCarrierProfile struct{
 Version int `json:"version"`
 Channel string `json:"channel"`
 PeerAddress string `json:"peerAddress"`
 PeerDeviceID string `json:"peerDeviceId"`
 BootstrapListen string `json:"bootstrapListen"`
 BootstrapTarget string `json:"bootstrapTarget"`
 Listen string `json:"listen"`
 Target string `json:"target"`
 Epochs int `json:"epochs"`
}
func verifyManagedHybridProfile(endpoint string,p *managedHybridCarrierProfile,trust *senderTrust,ownAddress,ownDevice string,now time.Time)error{
 if p==nil{return nil}
 if p.Version!=1||!scatteringHex.MatchString(p.Channel)||p.Channel==scatteringZero||p.Epochs<1||p.Epochs>4||!strongAddr.MatchString(p.PeerAddress)||!strongDevice.MatchString(p.PeerDeviceID)||p.PeerAddress==ownAddress||p.PeerDeviceID==ownDevice||trust==nil{return portableRefusal}
 peer,ok:=trust.contacts[senderKey(p.PeerAddress,p.PeerDeviceID)]
 if !ok||peer.Expires<=now.UnixMilli(){return portableRefusal}
 seen:=map[string]bool{}
 for _,v:=range []string{p.BootstrapListen,p.BootstrapTarget,p.Listen,p.Target}{
  if !managedCarrierEndpoint(v)||seen[v]{return portableRefusal}
  seen[v]=true
 }
 u,e:=url.Parse(endpoint);if e!=nil||u.Scheme!="http"||u.Hostname()!="127.0.0.1"||u.User!=nil||u.Path!="/"||u.RawPath!=""||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.Opaque!=""{return portableRefusal}
 port,e:=strconv.Atoi(u.Port());if e!=nil||port<1||port>65535||u.Host!="127.0.0.1:"+strconv.Itoa(port){return portableRefusal}
 _,bPort,_:=net.SplitHostPort(p.BootstrapListen);_,lPort,_:=net.SplitHostPort(p.Listen)
 if bPort==lPort||bPort==u.Port()||lPort==u.Port(){return portableRefusal}
 return nil
}
type windowsActivationBundle struct {
 Format string `json:"format"`
 LabOnly bool `json:"labOnly"`
 RequestDigest string `json:"requestDigest"`
 RosterPin string `json:"rosterPin"`
 Approvals enrollmentApprovalBundle `json:"approvals"`
 Credential enrollmentCredential `json:"credential"`
 Endpoint string `json:"endpoint"`
 Anchors []activationAnchor `json:"anchors"`
 Checkpoints []activationCheckpoint `json:"checkpoints"`
 AnchorTLS activationTLS `json:"anchorTls"`
 CheckpointTLS activationTLS `json:"checkpointTls"`
 Contacts []senderContact `json:"contacts"`
 ManagedCarrier *managedCarrierProfile `json:"managedCarrier,omitempty"`
 ManagedHybridCarrier *managedHybridCarrierProfile `json:"managedHybridCarrier,omitempty"`
}
type activationFile struct {name string;raw []byte}
func parseWindowsActivation(raw []byte,pin string)(windowsActivationBundle,error){
 var b windowsActivationBundle
 if len(raw)<2||len(raw)>131072||!hashRE.MatchString(pin)||hexHash(raw)!=pin{return b,portableRefusal}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var trailing any
 if d.Decode(&b)!=nil||d.Decode(&trailing)!=io.EOF||b.Format!="quantic-native-windows-activation-lab/v2"||!b.LabOnly||b.ManagedCarrier!=nil&&b.ManagedHybridCarrier!=nil{return windowsActivationBundle{},portableRefusal}
 return b,nil
}
func activationTLSValid(t activationTLS,key []byte,digest,role string,now time.Time)bool{
 for _,b:=range [][]byte{t.CA,t.Cert,key}{if len(b)<1||len(b)>16384{return false}}
 roots:=x509.NewCertPool()
 if !roots.AppendCertsFromPEM(t.CA){return false}
 pair,e:=tls.X509KeyPair(t.Cert,key)
 if e!=nil||len(pair.Certificate)==0{return false}
 leaf,e:=x509.ParseCertificate(pair.Certificate[0]);if e!=nil||leaf.IsCA||leaf.Subject.CommonName!=transportSubject(digest,role){return false}
 clientAuth:=false
 for _,u:=range leaf.ExtKeyUsage{if u==x509.ExtKeyUsageClientAuth{clientAuth=true}}
 if !clientAuth||leaf.KeyUsage&x509.KeyUsageDigitalSignature==0{return false}
 intermediates:=x509.NewCertPool()
 for _,der:=range pair.Certificate[1:]{c,e:=x509.ParseCertificate(der);if e!=nil{return false};intermediates.AddCert(c)}
 _,e=leaf.Verify(x509.VerifyOptions{Roots:roots,Intermediates:intermediates,CurrentTime:now,KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
 return e==nil
}
func activationEndpoint(raw,path string)(string,bool){
 u,e:=url.Parse(raw)
 if e!=nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||u.Path!=path||u.RawPath!=""||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.Opaque!=""{return "",false}
 if len(raw)>512{return "",false}
 return u.Scheme+"://"+u.Host,true
}
func activationPlan(dir,binary,binaryPin string,r enrollmentRequest,b windowsActivationBundle,secret []byte,now time.Time)([]activationFile,error){
 digest,e:=checkEnrollmentApprovals(r,b.Approvals,b.RosterPin,now)
 if e!=nil||digest!=b.RequestDigest||b.Format!="quantic-native-windows-activation-lab/v2"||!b.LabOnly||!hashRE.MatchString(binaryPin){return nil,portableRefusal}
 if _,_,e=winPathParts(dir);e!=nil{return nil,e}
 if _,_,e=winPathParts(binary);e!=nil{return nil,e}
 u,e:=url.Parse(b.Endpoint)
 if e!=nil||u.Scheme!="http"||u.Hostname()!="127.0.0.1"||u.User!=nil||u.Path!="/"||u.RawPath!=""||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.Opaque!=""{return nil,portableRefusal}
 port,e:=strconv.Atoi(u.Port());if e!=nil||port<1||port>65535||u.Host!="127.0.0.1:"+strconv.Itoa(port){return nil,portableRefusal}
 if len(b.Anchors)!=4||len(b.Checkpoints)!=4{return nil,portableRefusal}
 ak,anchorKey,e:=readLocalTransportKey(dir,"anchor",digest,secret,false);if e!=nil{return nil,e};defer clear(anchorKey)
 ck,checkpointKey,e:=readLocalTransportKey(dir,"checkpoint",digest,secret,false);if e!=nil{return nil,e};defer clear(checkpointKey)
 if publicPin(&ak.PublicKey)==publicPin(&ck.PublicKey)||!activationTLSValid(b.AnchorTLS,anchorKey,digest,"anchor",now)||!activationTLSValid(b.CheckpointTLS,checkpointKey,digest,"checkpoint",now){return nil,portableRefusal}
 files:=[]activationFile{
  {"peer-anchor-ca.pem",append([]byte(nil),b.AnchorTLS.CA...)},{"peer-anchor-cert.pem",append([]byte(nil),b.AnchorTLS.Cert...)},
  {"peer-checkpoint-ca.pem",append([]byte(nil),b.CheckpointTLS.CA...)},{"peer-checkpoint-cert.pem",append([]byte(nil),b.CheckpointTLS.Cert...)},
 }
 path:=func(n string)string{return filepath.Join(dir,n)}
 configs:=make([]anchorConfig,0,4);pins:=[]string{};origins:=map[string]bool{}
 for _,a:=range b.Anchors{
  origin,ok:=activationEndpoint(a.URL,"")
  if !ok||origins[origin]||!hashRE.MatchString(a.TLSPin){return nil,portableRefusal}
  origins[origin]=true;pins=append(pins,a.TLSPin)
  configs=append(configs,anchorConfig{URL:a.URL,ServerPin:a.TLSPin,ServerCA:path(files[0].name),ClientCert:path(files[1].name),ClientKey:path("peer-anchor-key.vault")})
 }
 q,e:=quorumPin(pins);if e!=nil||q!=r.QuorumPin{return nil,portableRefusal}
 quorum,e:=json.Marshal(configs);if e!=nil{return nil,e}
 // Exercise the same TLS construction as the broker, using only the verified
 // in-memory package before any file is created.
 if _,e=parseQuorumAnchor(bytes.NewReader(quorum),func(c anchorConfig)(*remoteAnchor,error){
  return remoteFromConfigReader(c,func(p string)([]byte,error){
   if p==path("peer-anchor-key.vault"){return append([]byte(nil),anchorKey...),nil}
   for _,f:=range files[:2]{if path(f.name)==p{return append([]byte(nil),f.raw...),nil}}
   return nil,portableRefusal
  })
 });e!=nil{return nil,e}
 allowed:=map[string]string{};for _,a:=range b.Approvals.Trusted{allowed[a.Pin]=a.PublicKey}
 seen:=map[string]bool{};tlsSeen:=map[string]bool{};origins=map[string]bool{}
 for _,a:=range b.Checkpoints{
  origin,ok:=activationEndpoint(a.URL,"/native-checkpoint")
  if !ok||origins[origin]||seen[a.Pin]||tlsSeen[a.TLSPin]||!hashRE.MatchString(a.TLSPin)||allowed[a.Pin]==""||allowed[a.Pin]!=a.PublicKey{return nil,portableRefusal}
  seen[a.Pin]=true;tlsSeen[a.TLSPin]=true;origins[origin]=true
 }
 contacts,e:=json.Marshal(b.Contacts);if e!=nil{return nil,e}
 trust,e:=parseSenderTrust(contacts);if e!=nil{return nil,e}
 for _,c:=range trust.contacts{
  if c.Address==r.Claim.Address||c.Device==r.Claim.DeviceID||len(c.Encryption)==0||len(c.KEM)==0||c.Expires>now.Add(24*time.Hour).UnixMilli(){return nil,portableRefusal}
 }
 c:=r.Claim
 config:=map[string]any{
  "labOnly":true,"binary":binary,"binarySha256":binaryPin,
  "vault":path("classical.vault"),"journal":path("journal.log"),"quorum":path("quorum.json"),"controllerKeyFile":path("controller.vault"),"controllerPublic":r.ControllerPublic,
  "signingPin":c.SigningPin,"encryptionPin":c.EncryptionPin,
  "windowsLab":map[string]any{"enabled":true,"dir":dir},
  "pqMode":map[string]any{"enabled":true,"sidecar":path("pq.vault"),"contactDirectory":path("contacts.json"),"address":c.Address,"deviceId":c.DeviceID,"kemPin":c.KemPin,"dsaPin":c.DsaPin,"rootPin":c.PQRootPin,
   "authority":map[string]any{"authorities":b.Checkpoints,"caFile":path(files[2].name),"clientCertFile":path(files[3].name),"clientKeyFile":path("peer-checkpoint-key.vault")}},
  "windowsScattering":map[string]any{"enabled":true,"credentialMode":"vault-sealed-v1","endpoint":b.Endpoint,"address":c.Address,"deviceId":c.DeviceID,"receiptKeyFile":path("receipt.vault")},
 }
 if b.ManagedCarrier!=nil&&b.ManagedHybridCarrier!=nil{return nil,portableRefusal}
 if e=verifyManagedCarrierProfile(dir,b.Endpoint,b.ManagedCarrier);e!=nil{return nil,e}
 if e=verifyManagedHybridProfile(b.Endpoint,b.ManagedHybridCarrier,trust,c.Address,c.DeviceID,now);e!=nil{return nil,e}
 if b.ManagedCarrier!=nil{config["managedScattering"]=b.ManagedCarrier}
 if b.ManagedHybridCarrier!=nil{config["managedHybridScattering"]=b.ManagedHybridCarrier}
 desktop,e:=json.Marshal(config);if e!=nil{return nil,e}
 checkpointConfig,e:=json.Marshal(b.Checkpoints);if e!=nil{return nil,e}
 return append(files,activationFile{"quorum.json",quorum},activationFile{"contacts.json",contacts},activationFile{"checkpoint-authorities.json",checkpointConfig},activationFile{"desktop.json",desktop}),nil
}
func applyActivationFiles(dir string,files []activationFile)error{
 // Preflight all conflicts before writing anything. CREATE_NEW, never
 // replacement; exact-byte resumption after a partial import is allowed.
 if len(files)!=8||files[7].name!="desktop.json"{return portableRefusal}
 for _,f:=range files{
  p:=filepath.Join(dir,f.name)
  if _,e:=os.Lstat(p);e==nil{
   raw,e:=winReadPrivate(p,131072);if e!=nil{return e}
   same:=bytes.Equal(raw,f.raw);clear(raw);if !same{return portableRefusal}
  }else if !os.IsNotExist(e){return e}
 }
 for _,f:=range files{
  p:=filepath.Join(dir,f.name)
  if _,e:=os.Lstat(p);os.IsNotExist(e){if e=winWritePrivate(p,f.raw);e!=nil{return e}}else if e!=nil{return e}
  raw,e:=winReadPrivate(p,131072);if e!=nil{return e}
  same:=bytes.Equal(raw,f.raw);clear(raw);if !same{return portableRefusal}
 }
 return nil
}
func importWindowsActivation(dir,binary,binaryPin string,b windowsActivationBundle,pw,pqw []byte,now time.Time)error{
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 // The local token must already exist, decrypt with both secrets, and match
 // the exact public credential delivered for this account.
 raw,e:=winReadPrivate(filepath.Join(dir,"mailbox-token.vault"),1024);if e!=nil{return e};defer clear(raw)
 token,e:=openNativeMailboxCredential(raw,b.RequestDigest,pw,pqw);if e!=nil{return e};defer clear(token)
 key,e:=readEnrollmentController(dir,r,pw,pqw);if e!=nil{return e};defer clear(key)
 proof,e:=nativeMailboxCredentialProof(token,b.RequestDigest,key)
 if e!=nil||proof!=b.Credential{return portableRefusal}
 secret,e:=transportSecret(pw,pqw);if e!=nil{return e};defer clear(secret)
 files,e:=activationPlan(dir,binary,binaryPin,r,b,secret,now);if e!=nil{return e}
 for _,f:=range files{defer clear(f.raw)}
 if _,e=checkEnrollmentApprovals(r,b.Approvals,b.RosterPin,time.Now());e!=nil{return e}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 return applyActivationFiles(dir,files)
}
func windowsActivationCLI(args []string)error{
 if len(args)!=6||args[1]!="--gui-import-mailbox-activation-lab"||!hashRE.MatchString(args[4])||!hashRE.MatchString(args[5]){return portableRefusal}
 dir,source,pin,binaryPin:=args[2],args[3],args[4],args[5]
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 // Version 2 has only public certificates and authenticated metadata.
 // Retain the private NTFS package policy until a separate safe import is available.
 raw,e:=winReadPrivate(source,131072);if e!=nil{return e};defer clear(raw)
 b,e:=parseWindowsActivation(raw,pin);if e!=nil{return e}
 binary,e:=os.Executable();if e!=nil{return e}
 f,e:=os.Open(binary);if e!=nil{return e}
 h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(f,256*1024*1024+1));f.Close()
 if e!=nil||n<1||n>256*1024*1024||hex.EncodeToString(h.Sum(nil))!=binaryPin{return portableRefusal}
 digest,e:=checkEnrollmentApprovals(r,b.Approvals,b.RosterPin,time.Now());if e!=nil||digest!=b.RequestDigest{return portableRefusal}
 if !winGUIApprove("Configuration de messagerie de laboratoire pour "+r.Claim.Address+". L'empreinte du dossier a ete verifiee. Aucun compte actif ni connexion distante prouvee. Importer ? Le profil hybride ne contient aucun secret partage. Une session commune du coffre est requise pour son activation."){return portableRefusal}
 pw,e:=winGUIPassphrase("Secret classique de l'appareil",true);if e!=nil{return e};defer clear(pw)
 pqw,e:=winGUIPassphrase("Secret post-quantique de l'appareil",true);if e!=nil{return e};defer clear(pqw)
 if e=importWindowsActivation(dir,binary,binaryPin,b,pw,pqw,time.Now());e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  Address string `json:"address"`
  MailAuthorized bool `json:"mailAuthorized"`
 }{"native-mailbox-configured-pending-live-verification",r.Claim.Address,false})
}
