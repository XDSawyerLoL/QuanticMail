//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "encoding/json"
 "encoding/base64"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
)

var mailKitPEM=regexp.MustCompile("^peer-[a-z0-9-]{1,48}[.]pem$")
type windowsMailKit struct{
 Format string `json:"format"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 Files map[string]string `json:"files"`
}
type mailKitDesktop struct{
 LabOnly bool `json:"labOnly"`
 Binary string `json:"binary"`
 BinaryPin string `json:"binarySha256"`
 Vault string `json:"vault"`
 Journal string `json:"journal"`
 Quorum string `json:"quorum"`
 Controller string `json:"controllerKeyFile"`
 SigningPin string `json:"signingPin"`
 EncryptionPin string `json:"encryptionPin"`
 Windows struct{Enabled bool;Dir string} `json:"windowsLab"`
 PQ struct{
  Enabled bool
  Address,DeviceID,KemPin,DsaPin,RootPin,Sidecar,ContactDirectory string
  Authority struct{CAFile,ClientCertFile,ClientKeyFile string;Authorities []struct{URL,Pin,TLSPin,PublicKey string}}
 } `json:"pqMode"`
 NativeRelay json.RawMessage `json:"nativeRelay"`
}
func clearMailKit(files map[string][]byte){for _,b:=range files{clear(b)}}
func decodeMailKit(raw []byte,identity map[string]string)(map[string][]byte,error){
 if len(raw)<1||len(raw)>131072{return nil,portableRefusal}
 var kit windowsMailKit
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var extra any
 if dec.Decode(&kit)!=nil||dec.Decode(&extra)!=io.EOF||kit.Format!="quantic-windows-mail-kit-lab/v1"||
  kit.Address!=identity["address"]||kit.DeviceID!=identity["deviceId"]||len(kit.Files)<6||len(kit.Files)>19{return nil,portableRefusal}
 files:=map[string][]byte{};ok:=false;defer func(){if !ok{clearMailKit(files)}}()
 for name,encoded:=range kit.Files{
  if name!="desktop.json"&&name!="quorum.json"&&name!="contacts.json"&&!mailKitPEM.MatchString(name){return nil,portableRefusal}
  b,e:=base64.RawURLEncoding.DecodeString(encoded)
  if e!=nil||len(b)<1||len(b)>65536||base64.RawURLEncoding.EncodeToString(b)!=encoded{return nil,portableRefusal}
  files[name]=b
 }
 for _,n:=range []string{"desktop.json","quorum.json","contacts.json"}{if !json.Valid(files[n]){return nil,portableRefusal}}
 ok=true;return files,nil
}
func checkMailKitConfig(dir,binary,pin string,r map[string]string,files map[string][]byte)error{
 var d mailKitDesktop
 if json.Unmarshal(files["desktop.json"],&d)!=nil||!d.LabOnly||!d.Windows.Enabled||!d.PQ.Enabled||len(d.NativeRelay)!=0||
 d.Binary!=binary||d.BinaryPin!=pin||d.Windows.Dir!=dir||d.SigningPin!=r["signingPin"]||d.EncryptionPin!=r["encryptionPin"]||
 d.PQ.Address!=r["address"]||d.PQ.DeviceID!=r["deviceId"]||d.PQ.KemPin!=r["kemPin"]||d.PQ.DsaPin!=r["dsaPin"]||!hashRE.MatchString(d.PQ.RootPin){return portableRefusal}
 for name,path:=range map[string]string{"classical.vault":d.Vault,"journal.log":d.Journal,"quorum.json":d.Quorum,"controller.pem":d.Controller,"pq.vault":d.PQ.Sidecar,"contacts.json":d.PQ.ContactDirectory}{if path!=filepath.Join(dir,name){return portableRefusal}}
 used:=map[string]bool{}
 read:=func(path string)([]byte,error){
  name:=filepath.Base(path)
  if filepath.Join(dir,name)!=path||!mailKitPEM.MatchString(name)||len(files[name])==0{return nil,portableRefusal}
  used[name]=true
  return append([]byte(nil),files[name]...),nil
 }
 // Validate all four replay authorities and their TLS client keypairs
 // before importing anything, without contacting a remote service.
 q,e:=parseQuorumAnchor(bytes.NewReader(files["quorum.json"]),func(c anchorConfig)(*remoteAnchor,error){return remoteFromConfigReader(c,read)})
 if e!=nil||q.pin!=r["quorumPin"]{return portableRefusal}
 if len(d.PQ.Authority.Authorities)!=4{return portableRefusal}
 pins:=map[string]bool{};tlsPins:=map[string]bool{};urls:=map[string]bool{}
 for _,a:=range d.PQ.Authority.Authorities{
  if !hashRE.MatchString(a.Pin)||!hashRE.MatchString(a.TLSPin)||pins[a.Pin]||tlsPins[a.TLSPin]||urls[a.URL]{return portableRefusal}
  pins[a.Pin]=true;tlsPins[a.TLSPin]=true;urls[a.URL]=true
 }
 for _,p:=range []string{d.PQ.Authority.CAFile,d.PQ.Authority.ClientCertFile,d.PQ.Authority.ClientKeyFile}{b,e:=read(p);if e!=nil{return e};clear(b)}
 for n:=range files{if mailKitPEM.MatchString(n)&&!used[n]{return portableRefusal}}
 if _,e=parseSenderTrust(files["contacts.json"]);e!=nil{return e}
 return nil
}
// A repeated import may resume only identical bytes. Preflight all existing
// targets before writing. Partial writes are preserved, not rolled back.
func writeMailKit(dir string,files map[string][]byte)error{
 names:=make([]string,0,len(files));for n:=range files{names=append(names,n)};sort.Strings(names)
 pending:=[]string{}
 for _,n:=range names{
  path:=filepath.Join(dir,n)
  if _,e:=os.Lstat(path);os.IsNotExist(e){pending=append(pending,n);continue}else if e!=nil{return e}
  got,e:=winReadPrivate(path,131072);if e!=nil{return e}
  same:=bytes.Equal(got,files[n]);clear(got);if !same{return portableRefusal}
 }
 for _,n:=range pending{if e:=winImportLabFile(dir,n,hexHash(files[n]),files[n]);e!=nil{return e}}
 for _,n:=range names{got,e:=winReadPrivate(filepath.Join(dir,n),131072);if e!=nil{return e};same:=bytes.Equal(got,files[n]);clear(got);if !same{return portableRefusal}}
 return nil
}
func winImportMailKitGUI(args []string)error{
 if len(args)!=6||!hashRE.MatchString(args[4])||!hashRE.MatchString(args[5])||filepath.Base(args[3])!="onboarding.json"{return portableRefusal}
 dir,source:=args[2],args[3]
 if filepath.Dir(source)==dir{return portableRefusal}
 raw,e:=winReadPrivate(source,131072);if e!=nil{return e};defer clear(raw)
 if hexHash(raw)!=args[4]{return portableRefusal}
 binary,e:=os.Executable();if e!=nil{return e}
 r,e:=winGUIReadIdentity(dir);if e!=nil{return e}
 files,e:=decodeMailKit(raw,r);if e!=nil{return e};defer clearMailKit(files)
 if e=checkMailKitConfig(dir,binary,args[5],r,files);e!=nil{return e}
 if !winGUIApproveText("Importer la configuration de messagerie pour "+r["address"]+" ? Aucun remplacement de cle ou inscription distante."){return portableRefusal}
 if e=writeMailKit(dir,files);e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(map[string]string{"status":"local-mail-kit-imported-not-enrolled","address":r["address"],"deviceId":r["deviceId"]})
}
