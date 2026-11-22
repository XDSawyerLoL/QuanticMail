//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
)

// Experimental Windows-only storage for SYNTHETIC, already-encrypted
// collection snapshots. Inherits the NTFS ACL, no-reparse, no-hardlink,
// CREATE_NEW and FlushFileBuffers checks from windows_storage.go.
// No identity keys are imported, no real account or relay is touched.
const migrationLabMarker = "quantic-native-migration-storage-lab/v1"
const migrationLabMarkerFile = "migration-lab.marker"
const migrationMaxSealed = 131072

func migrationLabCheck(dir string) error {
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 marker,e:=winReadPrivate(filepath.Join(dir,migrationLabMarkerFile),128)
 if e!=nil{return e};defer clear(marker)
 if !bytes.Equal(marker,[]byte(migrationLabMarker)){return portableRefusal}
 return nil
}
func winMigrationIO(args []string)(bool,error){
 if len(args)<2{return false,nil}
 op:=args[1]
 if op!="--windows-migration-init-lab"&&op!="--windows-migration-write-lab"&&op!="--windows-migration-read-lab"{return false,nil}
 if op=="--windows-migration-init-lab"{
  if len(args)!=3{return true,portableRefusal}
  if e:=winCreatePrivateDirectory(args[2]);e!=nil{return true,e}
  return true,winWritePrivate(filepath.Join(args[2],migrationLabMarkerFile),[]byte(migrationLabMarker))
 }
 if len(args)!=4||(args[3]!="source.sealed"&&args[3]!="candidate.sealed"){return true,portableRefusal}
 dir:=args[2]
 if e:=migrationLabCheck(dir);e!=nil{return true,e}
 path:=filepath.Join(dir,args[3])
 if op=="--windows-migration-read-lab"{
  b,e:=winReadPrivate(path,migrationMaxSealed)
  if e!=nil{return true,e};defer clear(b)
  n,e:=os.Stdout.Write(b);if e==nil&&n!=len(b){e=io.ErrShortWrite};return true,e
 }
 b,e:=io.ReadAll(io.LimitReader(os.Stdin,migrationMaxSealed+1))
 if e!=nil{return true,e};defer clear(b)
 if len(b)<64||len(b)>migrationMaxSealed{return true,portableRefusal}
 // Refuse malformed, non-canonical or plaintext input even in the lab. This
 // validates the envelope structure only; AES-GCM auth is checked on readback.
 var p struct{
  Format string `json:"format"`
  Version int `json:"version"`
  IV string `json:"iv"`
  Ciphertext string `json:"ciphertext"`
  Tag string `json:"tag"`
 }
 d:=json.NewDecoder(bytes.NewReader(b));d.DisallowUnknownFields()
 if d.Decode(&p)!=nil{return true,portableRefusal}
 var trailing any
 if d.Decode(&trailing)!=io.EOF{return true,portableRefusal}
 canonical,e:=json.Marshal(p);if e!=nil||!bytes.Equal(canonical,b)||p.Format!="quantic-native-migration-collections-lab/v1"||p.Version!=1{return true,portableRefusal}
 iv,e:=decode(p.IV,12,12);if e!=nil{return true,portableRefusal};defer clear(iv)
 tag,e:=decode(p.Tag,16,16);if e!=nil{return true,portableRefusal};defer clear(tag)
 ciphertext,e:=decode(p.Ciphertext,1,96016);if e!=nil{return true,portableRefusal};defer clear(ciphertext)
 return true,winWritePrivate(path,b)
}
