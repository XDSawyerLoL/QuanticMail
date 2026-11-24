//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/tls"
 "crypto/x509"
 "encoding/base64"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
)

type sessionKitConfig struct{
 Format string
 LabOnly bool
 ClientPin string
 Expected map[string]string
 TLSFiles map[string]string
 EnrollmentReceipts []json.RawMessage
}
const sessionApprovalName="session-approval.json"
func decodeSessionKit(raw []byte,identity map[string]string)(map[string][]byte,error){
 if len(raw)<1||len(raw)>131072{return nil,portableRefusal}
 var kit windowsMailKit
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var extra any
 if dec.Decode(&kit)!=nil||dec.Decode(&extra)!=io.EOF||kit.Format!="quantic-windows-session-kit-lab/v1"||kit.Address!=identity["address"]||kit.DeviceID!=identity["deviceId"]||len(kit.Files)!=4{return nil,portableRefusal}
 files:=map[string][]byte{};ok:=false;defer func(){if !ok{clearMailKit(files)}}()
 for n,s:=range kit.Files{
  if n!="session.json"&&!mailKitPEM.MatchString(n){return nil,portableRefusal}
  b,e:=base64.RawURLEncoding.DecodeString(s)
  if e!=nil||len(b)==0||len(b)>65536||base64.RawURLEncoding.EncodeToString(b)!=s{return nil,portableRefusal}
  files[n]=b
 }
 var cfg sessionKitConfig
 if json.Unmarshal(files["session.json"],&cfg)!=nil||cfg.Format!="quantic-native-session-config-lab/v1"||!cfg.LabOnly||!hashRE.MatchString(cfg.ClientPin)||len(cfg.TLSFiles)!=3||cfg.EnrollmentReceipts==nil||(len(cfg.EnrollmentReceipts)!=0&&len(cfg.EnrollmentReceipts)<3)||len(cfg.EnrollmentReceipts)>4{return nil,portableRefusal}
 for _,n:=range []string{"address","deviceId","signingPin","encryptionPin","kemPin","dsaPin","quorumPin","controllerPublic"}{
  if identity[n]==""||cfg.Expected[n]!=identity[n]{return nil,portableRefusal}
 }
 names:=map[string]bool{}
 for _,k:=range []string{"ca","cert","key"}{n:=cfg.TLSFiles[k];if !mailKitPEM.MatchString(n)||names[n]||len(files[n])==0{return nil,portableRefusal};names[n]=true}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(files[cfg.TLSFiles["ca"]]){return nil,portableRefusal}
 pair,e:=tls.X509KeyPair(files[cfg.TLSFiles["cert"]],files[cfg.TLSFiles["key"]])
 if e!=nil||len(pair.Certificate)==0||hexHash(pair.Certificate[0])!=cfg.ClientPin{return nil,portableRefusal}
 // The approval marker is derived from exact imported bytes, never taken
 // from the kit. The Node client revalidates signatures before any network.
 ok=true;return files,nil
}
func writeSessionKit(dir string,files map[string][]byte)error{
 hashes:=map[string]string{}
 for n,b:=range files{hashes[n]=hexHash(b)}
 marker,e:=json.Marshal(hashes);if e!=nil{return e}
 target:=filepath.Join(dir,sessionApprovalName)
 existing:=false
 if _,e=os.Lstat(target);e==nil{
  existing=true
  got,e:=winReadPrivate(target,4096);if e!=nil{return e};defer clear(got)
  if !bytes.Equal(got,marker){return portableRefusal}
 }else if !os.IsNotExist(e){return e}
 if e=writeMailKit(dir,files);e!=nil{return e}
 if !existing{if e=winWritePrivate(target,marker);e!=nil{return e}}
 got,e:=winReadPrivate(target,4096);if e!=nil{return e};defer clear(got)
 if !bytes.Equal(got,marker){return portableRefusal}
 return nil
}
func winImportSessionKitGUI(args []string)error{
 if len(args)!=5||!hashRE.MatchString(args[4])||filepath.Base(args[3])!="session-kit.json"||filepath.Dir(args[3])==args[2]{return portableRefusal}
 dir:=args[2]
 raw,e:=winReadPrivate(args[3],131072);if e!=nil{return e};defer clear(raw)
 if hexHash(raw)!=args[4]{return portableRefusal}
 r,e:=winGUIReadIdentity(dir);if e!=nil{return e}
 files,e:=decodeSessionKit(raw,r);if e!=nil{return e};defer clearMailKit(files)
 if !winGUIApproveText("Importer la configuration de session de TEST pour "+r["address"]+" ? Aucun remplacement ni activation de compte reel."){return portableRefusal}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 if e=writeSessionKit(dir,files);e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(map[string]string{"status":"local-session-kit-imported-lab","address":r["address"]})
}
