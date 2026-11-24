//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
)

// Only synthetic encrypted 16MiB/80KiB migration lab chunks.
// Never import Web credentials, classical/PQ private keys or bearer tokens.
// The Node verifier authenticates each ciphertext and full snapshot; this
// native layer only validates the strict envelope and protects NTFS files.
var migrationChunkName=regexp.MustCompile("^m-([a-f0-9]{32})-([sc])-(manifest|[0-9]{3})[.]enc$")
const migrationChunkFormat="quantic-native-migration-chunk-lab/v2"

type migrationChunkEnvelope struct {
 Format string `json:"format"`
 Version int `json:"version"`
 TransactionID string `json:"transactionId"`
 Role string `json:"role"`
 Kind string `json:"kind"`
 Index json.RawMessage `json:"index"`
 Total int `json:"total"`
 IV string `json:"iv"`
 Ciphertext string `json:"ciphertext"`
 Tag string `json:"tag"`
}
func migrationChunkValid(name string,raw []byte)bool{
 m:=migrationChunkName.FindStringSubmatch(name)
 if m==nil||len(raw)<128||len(raw)>migrationMaxSealed{return false}
 var p migrationChunkEnvelope
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if d.Decode(&p)!=nil{return false}
 var extra any
 if d.Decode(&extra)!=io.EOF{return false}
 encoded,e:=json.Marshal(p)
 if e!=nil||!bytes.Equal(encoded,raw)||p.Format!=migrationChunkFormat||p.Version!=2||p.TransactionID!=m[1]||p.Role!=m[2]||p.Total<1||p.Total>205{return false}
 if m[3]=="manifest"{
  var str string
  if p.Kind!="manifest"||json.Unmarshal(p.Index,&str)!=nil||str!="manifest"{return false}
 }else{
  var i int
  if p.Kind!="chunk"||json.Unmarshal(p.Index,&i)!=nil||i<0||i>=p.Total||fmt.Sprintf("%03d",i)!=m[3]{return false}
 }
 iv,e:=decode(p.IV,12,12);if e!=nil{return false};defer clear(iv)
 tag,e:=decode(p.Tag,16,16);if e!=nil{return false};defer clear(tag)
 ct,e:=decode(p.Ciphertext,1,81936);if e!=nil{return false};defer clear(ct)
 // The manifest contains an encrypted 1-block metadata record; no untrusted
 // plaintext, public key, path or arbitrary file type can be staged here.
 return true
}
func winMigrationChunkIO(op,dir,name string)(bool,error){
 if strings.HasPrefix(name,"a-"){return winMigrationAuditIO(op,dir,name)}
 if !migrationChunkName.MatchString(name){return true,portableRefusal}
 if e:=migrationLabCheck(dir);e!=nil{return true,e}
 path:=filepath.Join(dir,name)
 if op=="--windows-migration-probe-lab"{
  _,e:=os.Lstat(path)
  if os.IsNotExist(e){_,e=os.Stdout.Write([]byte("absent"));return true,e}
  if e!=nil{return true,e}
  raw,e:=winReadPrivate(path,migrationMaxSealed);if e!=nil{return true,e};defer clear(raw)
  if !migrationChunkValid(name,raw){return true,portableRefusal}
  _,e=os.Stdout.Write([]byte("present"));return true,e
 }
 if op=="--windows-migration-read-lab"{
  raw,e:=winReadPrivate(path,migrationMaxSealed);if e!=nil{return true,e};defer clear(raw)
  if !migrationChunkValid(name,raw){return true,portableRefusal}
  n,e:=os.Stdout.Write(raw);if e==nil&&n!=len(raw){e=io.ErrShortWrite}
  return true,e
 }
 if op!="--windows-migration-write-lab"{return true,portableRefusal}
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,migrationMaxSealed+1))
 if e!=nil{return true,e};defer clear(raw)
 if !migrationChunkValid(name,raw){return true,portableRefusal}
 return true,winWritePrivate(path,raw)
}
