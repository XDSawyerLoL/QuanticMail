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
 "net/url"
 "os"
 "path/filepath"
 "strconv"
 "time"
)
type activationTLS struct {
 CA []byte `json:"ca"`
 Cert []byte `json:"cert"`
 Key []byte `json:"key"`
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
}
type activationFile struct {name string;raw []byte}
func parseWindowsActivation(raw []byte,pin string)(windowsActivationBundle,error){
 var b windowsActivationBundle
 if len(raw)<2||len(raw)>131072||!hashRE.MatchString(pin)||hexHash(raw)!=pin{return b,portableRefusal}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var trailing any
 if d.Decode(&b)!=nil||d.Decode(&trailing)!=io.EOF||b.Format!="quantic-native-windows-activation-lab/v1"||!b.LabOnly{return windowsActivationBundle{},portableRefusal}
 return b,nil
}
func activationTLSValid(t activationTLS)bool{
 for _,b:=range [][]byte{t.CA,t.Cert,t.Key}{if len(b)<1||len(b)>16384{return false}}
 roots:=x509.NewCertPool()
 if !roots.AppendCertsFromPEM(t.CA){return false}
 pair,e:=tls.X509KeyPair(t.Cert,t.Key)
 return e==nil&&len(pair.Certificate)>0
}
func activationEndpoint(raw,path string)(string,bool){
 u,e:=url.Parse(raw)
 if e!=nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||u.Path!=path||u.RawPath!=""||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.Opaque!=""{return "",false}
 if len(raw)>512{return "",false}
 return u.Scheme+"://"+u.Host,true
}
func activationPlan(dir,binary,binaryPin string,r enrollmentRequest,b windowsActivationBundle,now time.Time)([]activationFile,error){
 digest,e:=checkEnrollmentApprovals(r,b.Approvals,b.RosterPin,now)
 if e!=nil||digest!=b.RequestDigest||b.Format!="quantic-native-windows-activation-lab/v1"||!b.LabOnly||!hashRE.MatchString(binaryPin){return nil,portableRefusal}
 if _,_,e=winPathParts(dir);e!=nil{return nil,e}
 if _,_,e=winPathParts(binary);e!=nil{return nil,e}
 u,e:=url.Parse(b.Endpoint)
 if e!=nil||u.Scheme!="http"||u.Hostname()!="127.0.0.1"||u.User!=nil||u.Path!="/"||u.RawPath!=""||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.Opaque!=""{return nil,portableRefusal}
 port,e:=strconv.Atoi(u.Port());if e!=nil||port<1||port>65535||u.Host!="127.0.0.1:"+strconv.Itoa(port){return nil,portableRefusal}
 if len(b.Anchors)!=4||len(b.Checkpoints)!=4||!activationTLSValid(b.AnchorTLS)||!activationTLSValid(b.CheckpointTLS){return nil,portableRefusal}
 files:=[]activationFile{
  {"peer-anchor-ca.pem",b.AnchorTLS.CA},{"peer-anchor-cert.pem",b.AnchorTLS.Cert},{"peer-anchor-key.pem",b.AnchorTLS.Key},
  {"peer-checkpoint-ca.pem",b.CheckpointTLS.CA},{"peer-checkpoint-cert.pem",b.CheckpointTLS.Cert},{"peer-checkpoint-key.pem",b.CheckpointTLS.Key},
 }
 path:=func(n string)string{return filepath.Join(dir,n)}
 configs:=make([]anchorConfig,0,4);pins:=[]string{};origins:=map[string]bool{}
 for _,a:=range b.Anchors{
  origin,ok:=activationEndpoint(a.URL,"")
  if !ok||origins[origin]||!hashRE.MatchString(a.TLSPin){return nil,portableRefusal}
  origins[origin]=true;pins=append(pins,a.TLSPin)
  configs=append(configs,anchorConfig{URL:a.URL,ServerPin:a.TLSPin,ServerCA:path(files[0].name),ClientCert:path(files[1].name),ClientKey:path(files[2].name)})
 }
 q,e:=quorumPin(pins);if e!=nil||q!=r.QuorumPin{return nil,portableRefusal}
 quorum,e:=json.Marshal(configs);if e!=nil{return nil,e}
 // Exercise the same TLS construction as the broker, using only the verified
 // in-memory package before any file is created.
 if _,e=parseQuorumAnchor(bytes.NewReader(quorum),func(c anchorConfig)(*remoteAnchor,error){
  return remoteFromConfigReader(c,func(p string)([]byte,error){
   for _,f:=range files[:3]{if path(f.name)==p{return append([]byte(nil),f.raw...),nil}}
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
  "vault":path("classical.vault"),"journal":path("journal.log"),"quorum":path("quorum.json"),"controllerKeyFile":path("controller.pem"),
  "signingPin":c.SigningPin,"encryptionPin":c.EncryptionPin,
  "windowsLab":map[string]any{"enabled":true,"dir":dir},
  "pqMode":map[string]any{"enabled":true,"sidecar":path("pq.vault"),"contactDirectory":path("contacts.json"),"address":c.Address,"deviceId":c.DeviceID,"kemPin":c.KemPin,"dsaPin":c.DsaPin,"rootPin":c.PQRootPin,
   "authority":map[string]any{"authorities":b.Checkpoints,"caFile":path(files[3].name),"clientCertFile":path(files[4].name),"clientKeyFile":path(files[5].name)}},
  "windowsScattering":map[string]any{"enabled":true,"credentialMode":"vault-sealed-v1","endpoint":b.Endpoint,"address":c.Address,"deviceId":c.DeviceID,"receiptKeyFile":path("receipt.key")},
 }
 desktop,e:=json.Marshal(config);if e!=nil{return nil,e}
 return append(files,activationFile{"quorum.json",quorum},activationFile{"contacts.json",contacts},activationFile{"desktop.json",desktop}),nil
}
func applyActivationFiles(dir string,files []activationFile)error{
 // Preflight all conflicts before writing anything. CREATE_NEW, never
 // replacement; exact-byte resumption after a partial import is allowed.
 if len(files)!=9||files[8].name!="desktop.json"{return portableRefusal}
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
 files,e:=activationPlan(dir,binary,binaryPin,r,b,now);if e!=nil{return e}
 for _,f:=range files{defer clear(f.raw)}
 // The local token must already exist, decrypt with both secrets, and match
 // the exact public credential delivered for this account.
 raw,e:=winReadPrivate(filepath.Join(dir,"mailbox-token.vault"),1024);if e!=nil{return e};defer clear(raw)
 token,e:=openNativeMailboxCredential(raw,b.RequestDigest,pw,pqw);if e!=nil{return e};defer clear(token)
 key,e:=readSyntheticControllerKey(dir,syntheticProfile{ControllerPublic:r.ControllerPublic});if e!=nil{return e};defer clear(key)
 proof,e:=nativeMailboxCredentialProof(token,b.RequestDigest,key)
 if e!=nil||proof!=b.Credential{return portableRefusal}
 if _,e=checkEnrollmentApprovals(r,b.Approvals,b.RosterPin,time.Now());e!=nil{return e}
 return applyActivationFiles(dir,files)
}
func windowsActivationCLI(args []string)error{
 if len(args)!=6||args[1]!="--gui-import-mailbox-activation-lab"||!hashRE.MatchString(args[4])||!hashRE.MatchString(args[5]){return portableRefusal}
 dir,source,pin,binaryPin:=args[2],args[3],args[4],args[5]
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 // The package includes transport client credentials, so require the same
 // private NTFS file/directory policy as the vault, not an ordinary download.
 raw,e:=winReadPrivate(source,131072);if e!=nil{return e};defer clear(raw)
 b,e:=parseWindowsActivation(raw,pin);if e!=nil{return e}
 defer clear(b.AnchorTLS.Key);defer clear(b.CheckpointTLS.Key)
 binary,e:=os.Executable();if e!=nil{return e}
 f,e:=os.Open(binary);if e!=nil{return e}
 h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(f,256*1024*1024+1));f.Close()
 if e!=nil||n<1||n>256*1024*1024||hex.EncodeToString(h.Sum(nil))!=binaryPin{return portableRefusal}
 if _,e=activationPlan(dir,binary,binaryPin,r,b,time.Now());e!=nil{return e}
 if !winGUIApprove("Configuration de messagerie de laboratoire pour "+r.Claim.Address+". L'empreinte du dossier a ete verifiee. Aucun compte actif ni connexion distante prouvee. Importer ?"){return portableRefusal}
 pw,e:=winGUIPassphrase("Secret classique de l'appareil",true);if e!=nil{return e};defer clear(pw)
 pqw,e:=winGUIPassphrase("Secret post-quantique de l'appareil",true);if e!=nil{return e};defer clear(pqw)
 if e=importWindowsActivation(dir,binary,binaryPin,b,pw,pqw,time.Now());e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  Address string `json:"address"`
  MailAuthorized bool `json:"mailAuthorized"`
 }{"native-mailbox-configured-pending-live-verification",r.Claim.Address,false})
}
