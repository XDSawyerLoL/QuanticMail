//go:build windows && cgo && pqopenssl

package main
import(
 "bytes"
 "crypto/ed25519"
 "crypto/x509"
 "encoding/json"
 "encoding/pem"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
)
// New synthetic lab vault only. No root/device key, journal, token import
// command, receipt-key replacement, legacy migration, or overwrite.
var winImportName=regexp.MustCompile("^(desktop[.]json|quorum[.]json|contacts[.]json|controller[.]pem|peer-[a-z0-9-]{1,48}[.]pem|draft-[a-z0-9-]{1,48}[.]json|wire-[a-z0-9-]{1,48}[.]json)$")
func winImportLabFile(dir,name,pin string,b []byte)error{
 if !winImportName.MatchString(name)||!hashRE.MatchString(pin)||len(b)<1||len(b)>131072||hexHash(b)!=pin{return portableRefusal}
 marker,e:=winReadPrivate(filepath.Join(dir,"lab-provisioned"),64);if e!=nil{return e};defer clear(marker)
 if !hashRE.Match(marker){return portableRefusal}
 if name=="controller.pem"{
  p,rest:=pem.Decode(b);if p==nil||p.Type!="PRIVATE KEY"||len(bytes.TrimSpace(rest))!=0{return portableRefusal};defer clear(p.Bytes)
  key,e:=x509.ParsePKCS8PrivateKey(p.Bytes);if e!=nil{return portableRefusal}
  k,ok:=key.(ed25519.PrivateKey);if !ok{return portableRefusal};defer clear(k)
  if hexHash(k.Public().(ed25519.PublicKey))!=string(marker){return portableRefusal}
 }else if strings.HasSuffix(name,".json"){
  if !json.Valid(b){return portableRefusal}
 }else{
  // TLS certificate/private key/CA files will also be validated by the broker.
  p,_:=pem.Decode(b);if p==nil{return portableRefusal};clear(p.Bytes)
 }
 if name=="controller.pem"{return winWriteLocalSecret(filepath.Join(dir,name),b)}
 if clientDraftName.MatchString(name){return winWriteProtectedDraft(filepath.Join(dir,name),b)}
 return winWritePrivate(filepath.Join(dir,name),b)
}
func winImportCLI(args []string)error{
 if len(args)!=5||!winImportName.MatchString(args[3])||!hashRE.MatchString(args[4]){return portableRefusal}
 b,e:=io.ReadAll(io.LimitReader(os.Stdin,131073));if e!=nil{return e};defer clear(b)
 if len(b)<1||len(b)>131072||hexHash(b)!=args[4]{return portableRefusal}
 if !winApprove("Import NEW laboratory file "+args[3]+" / SHA256 "+args[4]+" (no overwrite, no real account)"){return portableRefusal}
 return winImportLabFile(args[2],args[3],args[4],b)
}
