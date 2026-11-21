//go:build windows && cgo && pqopenssl

package main
import(
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/x509"
 "encoding/pem"
 "path/filepath"
 "strings"
 "testing"
)
func TestWindowsLabImport(t *testing.T){
 pub,k,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)};defer clear(k)
 dir:=filepath.Join(t.TempDir(),"lab")
 _,e=winProvisionVault(dir,b64.EncodeToString(pub),strings.Repeat("a",64),"alice~"+strings.Repeat("b",32)+"@quantic",[]byte("synthetic classical fixture password"),[]byte("different synthetic PQ fixture password"));if e!=nil{t.Fatal(e)}
 key,e:=winReadPrivate(filepath.Join(dir,"receipt.key"),32);if e!=nil||len(key)!=32||bytes.Equal(key,make([]byte,32)){t.Fatal("receipt key")};clear(key)
 der,e:=x509.MarshalPKCS8PrivateKey(k);if e!=nil{t.Fatal(e)};defer clear(der)
 b:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der});defer clear(b)
 _,wrong,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)};defer clear(wrong)
 d,e:=x509.MarshalPKCS8PrivateKey(wrong);if e!=nil{t.Fatal(e)};defer clear(d)
 bad:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:d});defer clear(bad)
 if winImportLabFile(dir,"controller.pem",hexHash(bad),bad)==nil{t.Fatal("different controller accepted")}
 if winImportLabFile(dir,"controller.pem",strings.Repeat("0",64),b)==nil{t.Fatal("wrong digest accepted")}
 if e=winImportLabFile(dir,"controller.pem",hexHash(b),b);e!=nil{t.Fatal(e)}
 if winImportLabFile(dir,"controller.pem",hexHash(b),b)==nil{t.Fatal("overwrite accepted")}
 if winImportLabFile(dir,"receipt.key",hexHash(b),b)==nil{t.Fatal("receipt key replacement")}
 if winImportLabFile(dir,"journal.log",hexHash(b),b)==nil{t.Fatal("journal import")}
 fixture:=[]byte("{}")
 if e=winImportLabFile(dir,"desktop.json",hexHash(fixture),fixture);e!=nil{t.Fatal(e)}
 old:=filepath.Join(t.TempDir(),"old");if e=winCreatePrivateDirectory(old);e!=nil{t.Fatal(e)}
 if winImportLabFile(old,"desktop.json",hexHash(fixture),fixture)==nil{t.Fatal("old vault accepted")}
}
