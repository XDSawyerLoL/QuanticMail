//go:build (linux || windows) && cgo && pqopenssl

package vaultsession

import(
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func run(t *testing.T,args ...string){
 t.Helper()
 if out,err:=exec.Command("openssl",args...).CombinedOutput();err!=nil{t.Fatalf("OpenSSL: %v %s",err,out)}
}
func TestNativeVaultProofInteroperability(t *testing.T){
 dir:=t.TempDir()
 key,pub,msg,sig:=filepath.Join(dir,"key.pem"),filepath.Join(dir,"public.der"),filepath.Join(dir,"message"),filepath.Join(dir,"signature")
 run(t,"genpkey","-algorithm","ML-DSA-65","-out",key)
 run(t,"pkey","-in",key,"-pubout","-outform","DER","-out",pub)
 der,err:=os.ReadFile(pub);if err!=nil{t.Fatal(err)}
 pin:=sha256.Sum256(der)
 id:=Identity{Address:"sentinel~"+strings.Repeat("a",32)+"@quantic",Device:"d-"+strings.Repeat("b",32),KEMPin:strings.Repeat("c",64),DSAPin:hex.EncodeToString(pin[:]),DSAPublicDER:der}
 now:=time.Now()
 s,err:=New(id,"test-machine",now);if err!=nil{t.Fatal(err)}
 req:=s.Request()
 if req.Op!="pq-proof-lab"{t.Fatal("wrong native Vault operation")}
 challenge,err:=base64.RawURLEncoding.DecodeString(req.PQChallenge);if err!=nil||len(challenge)!=32{t.Fatal("invalid challenge")}
 // Independent construction of exact pqKeys.proof payload, matching Vault
 // protocol. OpenSSL generates real ML-DSA-65 signatures, not a mock.
 payload:=append([]byte("quantic-pq-device-proof-lab/v1\x00"+id.Address+"\x00"+id.Device+"\x00"+id.KEMPin+id.DSAPin),challenge...)
 if err:=os.WriteFile(msg,payload,0600);err!=nil{t.Fatal(err)}
 run(t,"pkeyutl","-sign","-rawin","-inkey",key,"-in",msg,"-out",sig)
 signature,err:=os.ReadFile(sig);if err!=nil{t.Fatal(err)}
 encode:=func(b []byte)[]byte{r,e:=json.Marshal(Reply{OK:true,PQProof:base64.RawURLEncoding.EncodeToString(b)});if e!=nil{t.Fatal(e)};return r}
 bad:=append([]byte(nil),signature...);bad[0]^=1
 if s.Verify(encode(bad),now)==nil{t.Fatal("forged signature accepted")}
 if s.Verify(encode(signature),now.Add(30*time.Second))==nil{t.Fatal("expired proof accepted")}
 other,err:=New(id,"other-machine",now);if err!=nil{t.Fatal(err)}
 if other.Verify(encode(signature),now)==nil{t.Fatal("proof replayed in other session")}
 wrong:=id;wrong.DSAPin=strings.Repeat("0",64)
 if _,err:=New(wrong,"test-machine",now);err==nil{t.Fatal("wrong public key pin accepted")}
 if err:=s.Verify(encode(signature),now);err!=nil{t.Fatal(err)}
 if s.Verify(encode(signature),now)==nil{t.Fatal("proof replay accepted")}
}
