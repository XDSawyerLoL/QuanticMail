//go:build windows

package vaultsession

import(
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "encoding/pem"
 "path/filepath"
 "strings"
 "testing"
)
func TestTrustedEnrollmentFingerprintAndController(t *testing.T){
 pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 defer clear(key)
 dir:=filepath.Clean(t.TempDir())
 der:=make([]byte,1974);der[0]=1
 pin:=strings.Repeat("a",64)
 digest:=sha256.Sum256(der)
 c:=GraphicalBrokerConfig{Binary:filepath.Join(dir,"vault.exe"),BinarySHA256:pin,VaultDirectory:dir,SigningPin:pin,EncryptionPin:pin,RootPin:pin,MachineID:"test-machine",Controller:pub,Identity:Identity{Address:"test~"+strings.Repeat("a",32)+"@quantic",Device:"d-"+strings.Repeat("b",32),KEMPin:pin,DSAPin:hex.EncodeToString(digest[:]),DSAPublicDER:der}}
 raw,err:=json.Marshal(c);if err!=nil{t.Fatal(err)}
 hash:=sha256.Sum256(raw)
 expected:=hex.EncodeToString(hash[:])
 if _,err:=ParseTrustedEnrollment(raw,expected);err!=nil{t.Fatal(err)}
 if _,err:=ParseTrustedEnrollment(raw,pin);err==nil{t.Fatal("wrong fingerprint accepted")}
 if _,err:=ParseTrustedEnrollment(append(raw,' '),expected);err==nil{t.Fatal("modified enrollment accepted")}
 pk,err:=x509.MarshalPKCS8PrivateKey(key);if err!=nil{t.Fatal(err)};defer clear(pk)
 secret:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:pk});defer clear(secret)
 k,err:=decodeController(secret,pub);if err!=nil{t.Fatal(err)};clear(k)
 other,otherKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)};defer clear(otherKey)
 if k,e:=decodeController(secret,other);e==nil{clear(k);t.Fatal("unrelated controller accepted")}
}
