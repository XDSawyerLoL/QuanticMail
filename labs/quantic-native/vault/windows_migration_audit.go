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

// Synthetic encrypted read-only audit receipts. No transaction commit,
// live identity registration, prekey activation or Web-secret import.
// Each record is exclusively created and flushed by winWritePrivate.
var migrationAuditFileName=regexp.MustCompile("^a-([a-f0-9]{32})-([0-9]{3})[.]enc$")
const migrationAuditFormat="quantic-native-migration-audit-lab/v1"
const migrationAuditMaxBytes=8192

type migrationAuditEnvelope struct{
 Format string `json:"format"`
 Version int `json:"version"`
 TransactionID string `json:"transactionId"`
 Sequence int `json:"sequence"`
 Phase string `json:"phase"`
 PreviousHash string `json:"previousHash"`
 IV string `json:"iv"`
 Ciphertext string `json:"ciphertext"`
 Tag string `json:"tag"`
}
func migrationAuditValidate(name string,raw []byte)bool{
 m:=migrationAuditFileName.FindStringSubmatch(name)
 if m==nil||len(raw)<120||len(raw)>migrationAuditMaxBytes{return false}
 var p migrationAuditEnvelope
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if d.Decode(&p)!=nil{return false}
 var extra any
 if d.Decode(&extra)!=io.EOF{return false}
 encoded,e:=json.Marshal(p)
 if e!=nil||!bytes.Equal(encoded,raw)||p.Format!=migrationAuditFormat||p.Version!=1||p.TransactionID!=m[1]
  ||p.Sequence<0||p.Sequence>31||fmt.Sprintf("%03d",p.Sequence)!=m[2]||!hashRE.MatchString(p.PreviousHash){return false}
 want:="blocked"
 if p.Sequence==0{want="prepared"}else if p.Sequence==1{want="snapshot-verified"}else if p.Sequence==2{want="relay-observed"}
 if p.Phase!=want{return false}
 if p.Sequence==0&&p.PreviousHash!=strings.Repeat("0",64){return false}
 iv,e:=decode(p.IV,12,12);if e!=nil{return false};defer clear(iv)
 tag,e:=decode(p.Tag,16,16);if e!=nil{return false};defer clear(tag)
 ct,e:=decode(p.Ciphertext,1,4096);if e!=nil{return false};defer clear(ct)
 // AEAD authenticity and predecessor chain verified by independent Node code.
 return true
}
func winMigrationAuditIO(op,dir,name string)(bool,error){
 if !migrationAuditFileName.MatchString(name){return true,portableRefusal}
 if e:=migrationLabCheck(dir);e!=nil{return true,e}
 file:=filepath.Join(dir,name)
 if op=="--windows-migration-probe-lab"{
  _,e:=os.Lstat(file)
  if os.IsNotExist(e){_,e=os.Stdout.Write([]byte("absent"));return true,e}
  if e!=nil{return true,e}
  raw,e:=winReadPrivate(file,migrationAuditMaxBytes);if e!=nil{return true,e};defer clear(raw)
  if !migrationAuditValidate(name,raw){return true,portableRefusal}
  _,e=os.Stdout.Write([]byte("present"));return true,e
 }
 if op=="--windows-migration-read-lab"{
  raw,e:=winReadPrivate(file,migrationAuditMaxBytes);if e!=nil{return true,e};defer clear(raw)
  if !migrationAuditValidate(name,raw){return true,portableRefusal}
  n,e:=os.Stdout.Write(raw);if e==nil&&n!=len(raw){e=io.ErrShortWrite}
  return true,e
 }
 if op!="--windows-migration-write-lab"{return true,portableRefusal}
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,migrationAuditMaxBytes+1))
 if e!=nil{return true,e};defer clear(raw)
 if !migrationAuditValidate(name,raw){return true,portableRefusal}
 return true,winWritePrivate(file,raw)
}
